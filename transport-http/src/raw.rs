// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! A minimal HTTP/1.1 request reader over borrowed bytes: just enough to read the request line
//! and header fields of the message `encode` renders and `emit` is handed, and to undo a chunked
//! body across however many reads it arrives in.

/// A request head, read in place.
pub(crate) struct Head<'a> {
    /// The request method.
    pub(crate) method: &'a str,
    /// The request target the message STATED; `None` = it named none (an empty target word,
    /// `METHOD  HTTP/version`).
    pub(crate) path: Option<&'a str>,
    /// The header block, its request line included.
    block: &'a [u8],
    /// Whether the request line named `HTTP/1.0`.
    http10: bool,
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
    pub(crate) fn parse(bytes: &'a [u8]) -> Result<Self, &'static str> {
        const UNPARSABLE: &str = "unparsable request head";
        let block = memchr::memmem::find(bytes, b"\r\n\r\n").map_or(bytes, |p| &bytes[..p + 2]);
        // `lines` drops empty elements, so a blank line partway through the block would otherwise
        // be skipped and the fields after it read as head fields. The block ends in its last
        // field's CRLF, so any empty line inside it is a malformed head (RFC 9112 2.2).
        if memchr::memmem::find(block, b"\n\n").is_some()
            || memchr::memmem::find(block, b"\n\r\n").is_some()
        {
            return Err(UNPARSABLE);
        }
        let mut all = lines(block);
        let first = std::str::from_utf8(all.next().ok_or(UNPARSABLE)?).map_err(|_| UNPARSABLE)?;

        for line in all {
            let (name, _) = split_field(line).ok_or(UNPARSABLE)?;
            let name = std::str::from_utf8(name).map_err(|_| UNPARSABLE)?;

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

        if !matches!(c, "HTTP/1.0" | "HTTP/1.1") {
            return Err(UNPARSABLE);
        }
        Ok(Self {
            method: a,
            path: (!b.is_empty()).then_some(b),
            block,
            http10: c == "HTTP/1.0",
        })
    }

    /// The header fields, name and value, in the order they appeared.
    pub(crate) fn fields(&self) -> impl Iterator<Item = (&'a [u8], &'a [u8])> {
        lines(self.block).skip(1).filter_map(split_field)
    }

    /// Every member of the list field `name`, across every line carrying it, each trimmed of SP and HTAB only, as `split_field` does (`None`
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
            .map(|m| {
                std::str::from_utf8(m)
                    .ok()
                    .map(|m| m.trim_matches([' ', '\t']))
            })
    }

    /// How the body is framed.  `chunked` ALONE is the coding this transport reads: it must be
    /// the final transfer coding (RFC 9112 6.1: a list where it is not last leaves the body
    /// length undeterminable), applied only ONCE (`chunked, chunked` is a body wrapped twice),
    /// and any other coding in the list (`gzip, chunked`) is one this transport does not
    /// implement, so it is refused (RFC 9112 6.1), never dropped while its bytes go on unnamed;
    /// falling through to `Content-Length` would answer a question the sender did not ask.
    pub(crate) fn framing(&self) -> Result<BodyFraming, &'static str> {
        let (mut codings, mut chunked) = (0_usize, 0_usize);
        for coding in self.members("transfer-encoding") {
            codings += 1;
            chunked += usize::from(coding.is_some_and(|c| c.eq_ignore_ascii_case("chunked")));
        }
        if codings != 0 {
            // RFC 9112 6.1: a Transfer-Encoding on an HTTP/1.0 request is faulty framing.
            if self.http10 {
                return Err("transfer-encoding on HTTP/1.0");
            }
            if codings != 1 || chunked != 1 {
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
/// §6.5.1 lets a recipient that removes the chunked coding discard its trailers, and the transport
/// ABI carries no trailer.
#[derive(Default)]
pub(crate) struct ChunkedDecoder {
    state: ChunkState,
    line: zeroize::Zeroizing<Vec<u8>>,
    want: usize,
    body: zeroize::Zeroizing<Vec<u8>>,
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
    /// Read the CR that closes a chunk's data: its LF is next.
    AfterDataCr,
    /// Reading trailer lines, terminated by an empty one.
    Trailers,
    /// The terminal chunk and its trailers have both arrived.
    Done,
}

/// The bytes did not follow the chunked grammar.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct ChunkedMalformed;

/// A size line's `1*HEXDIG` (RFC 9112 7.1: no sign, no whitespace, not empty). Chunk extensions
/// after a semicolon are not read, and whitespace may stand between a size and them (BWS, RFC
/// 9112 7.1.1).
fn chunk_size(line: &[u8]) -> Result<usize, ChunkedMalformed> {
    let size = match line.iter().position(|byte| *byte == b';') {
        Some(end) => {
            let size = &line[..end];
            let end = size
                .iter()
                .rposition(|byte| !matches!(byte, b' ' | b'\t'))
                .map_or(0, |at| at + 1);
            &size[..end]
        }
        None => line,
    };
    if size.is_empty() || !size.iter().all(u8::is_ascii_hexdigit) {
        return Err(ChunkedMalformed);
    }
    let size = std::str::from_utf8(size).map_err(|_| ChunkedMalformed)?;
    usize::from_str_radix(size, 16).map_err(|_| ChunkedMalformed)
}

impl ChunkedDecoder {
    /// Feed everything that has arrived since the last call, answering how many of `bytes` the
    /// message took: all of them, unless the terminal chunk and its trailer section ended it
    /// first.
    pub(crate) fn feed(&mut self, bytes: &[u8]) -> Result<usize, ChunkedMalformed> {
        let mut at = 0;
        while at < bytes.len() {
            let rest = &bytes[at..];
            at += match self.state {
                ChunkState::Done => return Ok(at),
                ChunkState::Data => {
                    let n = self.want.min(rest.len());
                    crate::door::engine::extend_wiped(&mut self.body, &rest[..n]);
                    #[cfg(test)]
                    crate::wipe_probe::watch("chunk decoded", &self.body);
                    self.want -= n;
                    if self.want == 0 {
                        self.state = ChunkState::AfterData;
                    }
                    n
                }

                ChunkState::AfterData => {
                    match rest[0] {
                        b'\n' => self.state = ChunkState::Size,
                        b'\r' => self.state = ChunkState::AfterDataCr,
                        _ => return Err(ChunkedMalformed),
                    }
                    1
                }
                ChunkState::AfterDataCr => {
                    if rest[0] != b'\n' {
                        return Err(ChunkedMalformed);
                    }
                    self.state = ChunkState::Size;
                    1
                }
                ChunkState::Size | ChunkState::Trailers => {
                    let end = memchr::memchr(b'\n', rest);
                    let part = &rest[..end.unwrap_or(rest.len())];
                    crate::door::engine::extend_wiped(&mut self.line, part);
                    #[cfg(test)]
                    crate::wipe_probe::watch("chunk line", &self.line);
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

    /// A size or trailer line has ended: its one CR before the LF is the line end's; a CR
    /// anywhere else makes it malformed (RFC 9112 7.1), never a byte spliced out.
    fn end_line(&mut self) -> Result<(), ChunkedMalformed> {
        if self.line.last() == Some(&b'\r') {
            self.line.pop();
        }
        if self.line.contains(&b'\r') {
            return Err(ChunkedMalformed);
        }
        let line = self.line.as_slice();
        self.state = match self.state {
            ChunkState::Size => match chunk_size(line)? {
                0 => ChunkState::Trailers,
                size => {
                    self.want = size;
                    ChunkState::Data
                }
            },
            _ if line.is_empty() => ChunkState::Done,
            _ if line.contains(&b':') => ChunkState::Trailers,
            _ => return Err(ChunkedMalformed),
        };
        zeroize::Zeroize::zeroize(&mut *self.line);
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
    pub(crate) fn take(self) -> zeroize::Zeroizing<Vec<u8>> {
        self.body
    }
}

#[cfg(test)]
#[path = "tests/raw.rs"]
mod tests;
