// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! A minimal HTTP/1.1 request reader over borrowed bytes: just enough to read the request line
//! and header fields of the message `encode` renders and `emit` is handed, and to undo a chunked
//! body across however many reads it arrives in. Not a general-purpose parser — no header folding,
//! and the only transfer coding it reads is `chunked`. Nothing is copied out of the head: every
//! word and field is a slice of the bytes it was read from.

/// A request head, read in place.
pub(crate) struct Head<'a> {
    /// The request method.
    pub(crate) method: &'a str,
    /// The request target the message STATED; `None` = it named none (an empty target word,
    /// `METHOD  HTTP/version`). A stated `/` is `Some("/")`: it is a target like any other.
    pub(crate) path: Option<&'a str>,
    /// The header block, its request line included.
    block: &'a [u8],
}

/// How a request's body is framed, as its head declares it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum BodyFraming {
    /// `Content-Length` (0 when the head declares neither coding).
    Length(usize),
    /// `Transfer-Encoding: chunked`.
    Chunked,
}

/// The non-empty lines of `block`, each without its CR.
fn lines(block: &[u8]) -> impl Iterator<Item = &[u8]> {
    block
        .split(|b| *b == b'\n')
        .map(|l| l.strip_suffix(b"\r").unwrap_or(l))
        .filter(|l| !l.is_empty())
}

/// A field line's name and its value without the optional whitespace (SP, HTAB) around it (RFC
/// 9112 5.1); every other byte of the value stays (obs-text included).
fn split_field(line: &[u8]) -> Option<(&[u8], &[u8])> {
    let colon = memchr::memchr(b':', line)?;
    let value = &line[colon + 1..];
    let ows = |b: &u8| *b == b' ' || *b == b'\t';
    let start = value.iter().position(|b| !ows(b)).unwrap_or(value.len());
    let end = value
        .iter()
        .rposition(|b| !ows(b))
        .map_or(start, |at| at + 1);
    Some((&line[..colon], &value[start..end]))
}

impl<'a> Head<'a> {
    /// Read the head at the front of `bytes`, which may end exactly at the header terminator or
    /// carry the body after it.
    ///
    /// # Errors
    ///
    /// Anything that is not an HTTP/1.x request head: no request line naming its version, a status
    /// line, a header line with no colon, or whitespace between a field name and its colon — which
    /// the wire forbids outright.
    pub(crate) fn parse(bytes: &'a [u8]) -> Result<Self, &'static str> {
        const UNPARSABLE: &str = "unparsable request head";
        let block = memchr::memmem::find(bytes, b"\r\n\r\n").map_or(bytes, |p| &bytes[..p + 2]);
        let mut all = lines(block);
        let first = std::str::from_utf8(all.next().ok_or(UNPARSABLE)?).map_err(|_| UNPARSABLE)?;
        // The start line and every field name are text; a field VALUE is bytes (RFC 9110 5.5:
        // obs-text is a value's, and 1.5.5's client carried such a value as given).
        for line in all {
            let (name, _) = split_field(line).ok_or(UNPARSABLE)?;
            let name = std::str::from_utf8(name).map_err(|_| UNPARSABLE)?;
            // No whitespace is allowed between a field name and its colon. Trimming it here would
            // normalise a header no compliant peer would honour into one this transport does, and
            // the disagreement that opens between an intermediary and its upstream is exactly the
            // request-smuggling surface the rule exists to close. So: refuse the message.
            if name != name.trim() {
                return Err(UNPARSABLE);
            }
        }

        let mut words = first.splitn(3, ' ');
        let (a, b) = (
            words.next().ok_or(UNPARSABLE)?,
            words.next().ok_or(UNPARSABLE)?,
        );
        let c = words.next().unwrap_or("");
        if a.starts_with("HTTP/") {
            return Err("a status line is not a request");
        }
        // `METHOD path HTTP/version`. The version token is REQUIRED. Without the check a two-word
        // first line — anything at all, followed by a space — parses as a request, so a blob that
        // is not HTTP is read as one and its first two words become a method and a path this
        // transport then acts on. And it is 1.x: the framing rules here — `Content-Length`, chunked
        // transfer coding, a CRLF-terminated header block — are 1.x's, and a `2` or a `3` names a
        // wire made of frames this reader has never seen.
        if !matches!(c, "HTTP/1.0" | "HTTP/1.1") {
            return Err(UNPARSABLE);
        }
        Ok(Self {
            method: a,
            path: (!b.is_empty()).then_some(b),
            block,
        })
    }

    /// The header fields, name and value, in the order they appeared.
    pub(crate) fn fields(&self) -> impl Iterator<Item = (&'a [u8], &'a [u8])> {
        lines(self.block).skip(1).filter_map(split_field)
    }

    /// Every member of the list field `name`, across every line carrying it, each trimmed (`None`
    /// for a member that is not text, which no coding or length matches).
    ///
    /// RFC 9110 5.3 makes this the definition of a repeated field: a sender may split a
    /// comma-separated list across several lines, and the meaning is the one line those values
    /// would have made. Reading only the first line reads a different field than the one that was
    /// sent — and for the framing fields that is a body length: `Transfer-Encoding: chunked`
    /// followed by `Transfer-Encoding: gzip` is the list `chunked, gzip`.
    fn members(&self, name: &'static str) -> impl Iterator<Item = Option<&'a str>> {
        self.fields()
            .filter(move |(k, _)| k.eq_ignore_ascii_case(name.as_bytes()))
            .flat_map(|(_, v)| v.split(|b| *b == b','))
            .map(|m| std::str::from_utf8(m).ok().map(str::trim))
    }

    /// How the body is framed.
    ///
    /// `chunked` must be the FINAL transfer coding (RFC 9112 6.1: a list where it is not last
    /// leaves the body length undeterminable) and applied only ONCE (`chunked, chunked` is a body
    /// wrapped twice); any other declared coding is one this transport cannot frame, and falling
    /// through to `Content-Length` would answer a question the sender did not ask. A chunked
    /// message naming a `Content-Length` beside it — two framings of the same bytes, the smuggling
    /// shape itself — is refused rather than silently disambiguated. A `Content-Length` is exactly
    /// `1*DIGIT` fitting a `usize`, every member and line naming the same value (RFC 9110 8.6);
    /// anything else is unrecoverable framing (RFC 9112 6.3), never a body-less message.
    ///
    /// # Errors
    ///
    /// The refusals above.
    pub(crate) fn framing(&self) -> Result<BodyFraming, &'static str> {
        let (mut coded, mut applied, mut last) = (false, 0_usize, false);
        for coding in self.members("transfer-encoding") {
            coded = true;
            last = coding.is_some_and(|c| c.eq_ignore_ascii_case("chunked"));
            applied += usize::from(last);
        }
        if coded {
            if applied != 1 || !last {
                return Err("unsupported transfer coding");
            }
            if self.members("content-length").next().is_some() {
                return Err("transfer-encoding with content-length");
            }
            return Ok(BodyFraming::Chunked);
        }
        const INVALID: &str = "invalid content-length";
        let mut lengths = self.members("content-length");
        let Some(first) = lengths.next() else {
            return Ok(BodyFraming::Length(0));
        };
        if lengths.any(|other| other != first) {
            return Err(INVALID);
        }
        let first = first
            .filter(|f| !f.is_empty() && f.bytes().all(|b| b.is_ascii_digit()))
            .ok_or(INVALID)?;
        first.parse().map(BodyFraming::Length).map_err(|_| INVALID)
    }
}

/// A chunked-transfer-encoding reader, fed whatever bytes have arrived so far.
///
/// Incremental on purpose. A body arrives across as many reads as the network chooses, and a chunk
/// boundary is free to fall in the middle of a size line, in the middle of the CRLF after one, or
/// between the terminal chunk and its trailers. A decoder that re-scanned the whole buffer on every
/// read would be quadratic in the body size. A chunk's data is taken a slice at a time and a line
/// is found with `memchr`. The trailer section is read for its grammar and discarded: RFC 9110
/// §6.5.1 lets a recipient that removes the chunked coding discard its trailers, and THE DESIGN §5
/// carries no trailer on the transport ABI.
#[derive(Default)]
pub(crate) struct ChunkedDecoder {
    state: ChunkState,
    line: Vec<u8>,
    want: usize,
    body: Vec<u8>,
}

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
enum ChunkState {
    /// Reading the hexadecimal size line that opens a chunk.
    #[default]
    Size,
    /// Reading `want` more bytes of the current chunk's data.
    Data,
    /// Reading the CRLF that closes a chunk's data.
    AfterData,
    /// Reading trailer lines, terminated by an empty one.
    Trailers,
    /// The terminal chunk and its trailers have both arrived.
    Done,
}

/// The bytes did not follow the chunked grammar.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct ChunkedMalformed;

/// A size line's `1*HEXDIG` (RFC 9112 7.1: no sign, no whitespace, not empty). Chunk extensions
/// after a semicolon are not read, and whitespace may stand between a size and them (BWS, RFC 9112
/// 7.1.1).
fn chunk_size(line: &str) -> Result<usize, ChunkedMalformed> {
    let size = match line.split_once(';') {
        Some((size, _)) => size.trim_end_matches([' ', '\t']),
        None => line,
    };
    if size.is_empty() || !size.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(ChunkedMalformed);
    }
    usize::from_str_radix(size, 16).map_err(|_| ChunkedMalformed)
}

impl ChunkedDecoder {
    /// Feed everything that has arrived since the last call, answering how many of `bytes` the
    /// message took: all of them, unless the terminal chunk and its trailer section ended it
    /// first. What is left after that end is not this message's, and the caller judges it.
    ///
    /// # Errors
    ///
    /// The bytes are not chunked-transfer-encoding: a size line that is not hexadecimal, a chunk
    /// not closed by CRLF, or a trailer line with no colon.
    pub(crate) fn feed(&mut self, bytes: &[u8]) -> Result<usize, ChunkedMalformed> {
        let mut at = 0;
        while at < bytes.len() {
            let rest = &bytes[at..];
            at += match self.state {
                ChunkState::Done => return Ok(at),
                ChunkState::Data => {
                    let n = self.want.min(rest.len());
                    self.body.extend_from_slice(&rest[..n]);
                    self.want -= n;
                    if self.want == 0 {
                        self.state = ChunkState::AfterData;
                    }
                    n
                }
                ChunkState::AfterData => {
                    match rest[0] {
                        b'\n' => self.state = ChunkState::Size,
                        b'\r' => {}
                        _ => return Err(ChunkedMalformed),
                    }
                    1
                }
                ChunkState::Size | ChunkState::Trailers => {
                    let end = memchr::memchr(b'\n', rest);
                    let part = &rest[..end.unwrap_or(rest.len())];
                    self.line.extend(part.iter().filter(|b| **b != b'\r'));
                    let Some(end) = end else {
                        return Ok(bytes.len());
                    };
                    self.end_line()?;
                    end + 1
                }
            };
        }
        Ok(bytes.len())
    }

    /// A size or trailer line has ended.
    fn end_line(&mut self) -> Result<(), ChunkedMalformed> {
        let line = std::str::from_utf8(&self.line).map_err(|_| ChunkedMalformed)?;
        self.state = match self.state {
            ChunkState::Size => match chunk_size(line)? {
                0 => ChunkState::Trailers,
                size => {
                    self.want = size;
                    ChunkState::Data
                }
            },
            _ if line.is_empty() => ChunkState::Done,
            _ if line.contains(':') => ChunkState::Trailers,
            _ => return Err(ChunkedMalformed),
        };
        self.line.clear();
        Ok(())
    }

    /// The decoded body bytes so far.
    #[must_use]
    pub(crate) fn body_len(&self) -> usize {
        self.body.len()
    }

    /// Whether the terminal chunk and its trailer section have both arrived.
    #[must_use]
    pub(crate) fn is_done(&self) -> bool {
        self.state == ChunkState::Done
    }

    /// The decoded body.
    #[must_use]
    pub(crate) fn take(self) -> Vec<u8> {
        self.body
    }
}

#[cfg(test)]
#[path = "tests/raw.rs"]
mod tests;
