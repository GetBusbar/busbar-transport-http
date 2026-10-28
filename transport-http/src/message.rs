// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The HTTP/1.1 message the framer reads a request through: whether the bytes an `emit` has
//! carried so far are one whole message yet (the egress cross-check's framing), the request target
//! a dialled exchange goes to, and the upstream's `Retry-After` read off a response head.

use crate::raw;

/// Read the upstream's `Retry-After` off a response head and resolve it to whole seconds.
///
/// The header is optional, appears at most once in any answer that means it, and a value this
/// parser cannot read is treated as absent — a wait nobody can compute is not a wait, and guessing
/// one would park a lane on a header nobody wrote.
pub(crate) fn retry_after_secs(headers: &http::HeaderMap, now_secs: u64) -> Option<u64> {
    let raw = headers.get(http::header::RETRY_AFTER)?.to_str().ok()?;
    parse_retry_after(raw, now_secs)
}

/// Parse an RFC 9110 `Retry-After` header VALUE against `now` (a Unix timestamp in seconds). Both
/// normative forms are accepted: `delay-seconds` (an integer, which ignores `now`) and an
/// HTTP-date in any of the three forms RFC 9110 5.6.7 requires a recipient to accept (IMF-fixdate,
/// obsolete RFC 850, asctime), converted to the seconds remaining until that instant and floored
/// at 0 when it is already in the past. A date with an out-of-range field is absent.
///
/// The date is read by `httpdate`, the parser 1.5.5's breaker used. The arithmetic after it is the
/// breaker's own classifier's, and it is duplicated here rather than shared: this crate sits on the
/// transport axis and may not name a unit crate, and the unit crate's own dependency policy names
/// the capability crate as the only workspace crate it may see. Neither can reach the other, so
/// there is no shared home for it. The forms accepted and the flooring rule are pinned by the tests
/// below against the same values.
///
/// (The capability crate is deliberately not spelled here. `tests/no_plane_names.rs` refuses that
/// name anywhere in this crate's source, and a rule with an exception for prose is a rule with an
/// exception — the sentence says the same thing without one.)
pub(crate) fn parse_retry_after(value: &str, now: u64) -> Option<u64> {
    let s = value.trim();
    if let Ok(n) = s.parse::<u64>() {
        return Some(n);
    }
    let at = httpdate::parse_http_date(s).ok()?;
    let epoch_secs = at.duration_since(std::time::UNIX_EPOCH).ok()?.as_secs();
    Some(epoch_secs.saturating_sub(now))
}

/// Where an egress request actually goes: the dialled scheme and authority, carrying the target
/// the message STATED.
///
/// A dial pins a destination — scheme, host, port. It does not pin a request: one connection to an
/// upstream carries many requests (a pooled line is lent to whichever exchange next opens to the
/// same place), and on an API whose surface is its path they are different requests only because
/// their paths differ. So a stated target always wins, `/` included. Only a request that names NO
/// target (`path` = `None`) inherits the dial URI's own path — the shape a caller writes when the
/// dial URI already spells the whole target — and only as the connection's FIRST request
/// (`first`); a later request naming none goes to `/`, never to whatever path the exchange that
/// dialled the line happened to name.
///
/// A stated target is ORIGIN form (`/` and a path, RFC 9112 §3.2.1), the one form this door sends
/// (THE DESIGN §5: the http transport owns "on h1 the host header and origin-form target"). Any
/// other is refused, never rewritten: `v1/chat` would have gone to `/`, and an absolute-form
/// `http://other/x` to whatever host it names on the dialled address (RFC 9112 §3.2.2), each
/// without an error.
pub(crate) fn request_target(
    dial: &http::Uri,
    path: Option<&str>,
    first: bool,
) -> Result<http::Uri, &'static str> {
    let path = match path {
        Some(stated) if stated.starts_with('/') => stated,
        Some(_) => return Err("target not in origin form"),
        None if first => return Ok(dial.clone()),
        None => "/",
    };
    let mut parts = dial.clone().into_parts();
    parts.path_and_query = Some(
        path.parse::<http::uri::PathAndQuery>()
            .map_err(|_| "target not a valid path")?,
    );
    http::Uri::from_parts(parts).map_err(|_| "target not a valid path")
}

/// A message this transport has been handed enough of to send, or `None` for a prefix of one.
///
/// The three endings are the wire's own: a declared `Content-Length` reached, the terminal chunk of
/// a chunked body seen, or a message that declares neither coding and therefore carries no body at
/// all. A chunked message is decoded here, so what comes back always carries the body itself rather
/// than a framing of it. The head is held to `max_head_bytes` and the body to `max_body_bytes`; a
/// byte past either ending is refused (`Framing`).
pub(crate) fn complete_message(
    buffered: &[u8],
    cache: &mut EgressHead,
    max_body_bytes: usize,
    max_head_bytes: usize,
) -> Result<Option<raw::RawMessage>, &'static str> {
    if cache.head.is_none() {
        // Resumed where the last call stopped: the bytes before it hold no terminator, and the
        // search looks back from each line feed it finds, so nothing is missed.
        let (found, scanned) = find_header_end_from(buffered, cache.searched);
        cache.scanned += scanned;
        cache.searched = buffered.len();
        let Some(header_end) = found else {
            // No terminator yet, so every buffered byte is head: past the allowance it is one the
            // sender will not end in bounds.
            if buffered.len() > max_head_bytes {
                return Err("request head over its allowance");
            }
            return Ok(None);
        };
        if header_end > max_head_bytes {
            return Err("request head over its allowance");
        }
        let mut message =
            raw::parse_message(&buffered[..header_end]).ok_or("unparsable request head")?;
        cache.parses += 1;
        if raw::has_transfer_encoding(&message.headers) {
            if !raw::is_chunked(&message.headers) {
                // A declared coding this transport cannot frame. Falling through to
                // `Content-Length` would be answering a question the sender did not ask.
                return Err("unsupported transfer coding");
            }
            if raw::header(&message.headers, "content-length").is_some() {
                // Two headers describing two framings of the same bytes. The coding wins the
                // reading, but forwarding the pair on — as this used to do — hands the next hop a
                // length the bytes do not have, the smuggling shape itself. Refused rather than
                // silently disambiguated.
                return Err("transfer-encoding with content-length");
            }
        }
        cache.head = Some(CachedHead {
            end: header_end,
            start: std::mem::replace(
                &mut message.start,
                crate::raw::RawStartLine::Status {
                    code: 0,
                    reason: String::new(),
                },
            ),
            headers: std::mem::take(&mut message.headers),
        });
    }
    // Read what the head says before touching the cache again: the decoder lives beside it, and
    // feeding it is a mutation of the same cell this borrow reads.
    let (head_end, chunked, declared) = {
        let head = cache.head.as_ref().expect("set just above");
        (
            head.end,
            raw::is_chunked(&head.headers),
            raw::content_length(&head.headers),
        )
    };
    let rest = &buffered[head_end..];

    let body = if chunked {
        // ONE decoder across the calls, fed only what arrived with this one. A fresh decoder per
        // call re-decodes every byte received so far and re-allocates the decoded chunks each
        // time — quadratic in the body, which for the megabyte bodies this path exists to carry is
        // the difference between a transport and a stall.
        let decoder = cache
            .decoder
            .get_or_insert_with(|| Box::new(raw::ChunkedDecoder::default()));
        let fresh = &rest[cache.fed.min(rest.len())..];
        cache.feeds += fresh.len();
        let used = decoder.feed(fresh).map_err(|_| "malformed chunked body")?;
        cache.fed = rest.len();
        // The body cap is the decoded body's, as it is a declared length's, and it is held as the
        // chunks arrive rather than once the message is whole.
        if decoder.body_len() > max_body_bytes {
            return Err("decoded chunked body over the body cap");
        }
        if !decoder.is_done() {
            return Ok(None);
        }
        // Bytes after the terminal chunk's trailer section belong to no message this stream
        // carries: a mis-framed writer, refused rather than dropped.
        if used < fresh.len() {
            return Err("bytes past the end of the message");
        }
        // The trailer section is discarded: RFC 9110 §6.5.1 lets a recipient that removes the
        // chunked coding discard its trailers, and forbids merging them into the header section
        // (a trailer `host` or `connection` would become a second header of that name). THE
        // DESIGN §5 carries no trailer on the transport ABI, so there is nowhere else to send
        // them.
        let (chunks, _trailers) = cache.decoder.take().expect("set just above").take();
        chunks.concat()
    } else {
        let declared = declared
            .map_err(|()| "invalid content-length")?
            .unwrap_or(0);
        if declared > max_body_bytes {
            return Err("declared body over the body cap");
        }
        if rest.len() < declared {
            return Ok(None);
        }
        // Bytes past the declared length (or past a head that declares no body) are a mis-framed
        // writer's, refused rather than dropped.
        if rest.len() > declared {
            return Err("bytes past the end of the message");
        }
        rest.to_vec()
    };

    // Whole: the head is spent with the message it belonged to, so the next one parses its own,
    // and the decoder that read this body is spent with it too.
    let head = cache.head.take().expect("set just above");
    cache.decoder = None;
    cache.fed = 0;
    cache.searched = 0;
    Ok(Some(raw::RawMessage {
        start: head.start,
        headers: head.headers,
        body,
    }))
}

/// The parsed header block of the message the door's `emit` is still accumulating.
///
/// `emit` asks whether the message is whole on EVERY chunk, and the header prefix does not change
/// between those asks. Parsing it each time allocates a fresh vector and two strings per header and
/// throws them away — the same waste the chunked decoder was written incrementally to avoid. Held
/// beside the pending bytes, and taken when the message completes so it can never outlive it.
pub(crate) struct CachedHead {
    pub(crate) end: usize,
    pub(crate) start: raw::RawStartLine,
    pub(crate) headers: Vec<(String, Vec<u8>)>,
}

/// [`CachedHead`], plus this connection's own count of how many times it has parsed one — the cell
/// that pins the egress side to one parse per message rather than one per `emit` call. Per
/// instance rather than a crate-global counter, so a test reading it back sees only its own
/// connection's work, never a sibling test's sharing the same binary.
#[derive(Default)]
pub(crate) struct EgressHead {
    pub(crate) head: Option<CachedHead>,
    pub(crate) parses: usize,
    /// The chunked decoder this message is being decoded by, kept across `emit` calls so each
    /// call feeds only the bytes that arrived with it. Behind a box because it is a per-message working set that most
    /// connections never allocate, and inline it would be carried by every connection ever dialled.
    pub(crate) decoder: Option<Box<raw::ChunkedDecoder>>,
    /// How many bytes past the header block have already been fed to `decoder`.
    pub(crate) fed: usize,
    /// This connection's own tally of bytes fed to a decoder, per instance for the same reason
    /// `parses` is: a test reading it back sees only its own connection's work.
    pub(crate) feeds: usize,
    /// This connection's own tally of bytes the header-end search examined, per instance for the
    /// same reason.
    pub(crate) scanned: usize,
    /// How far into the pending bytes the header-end search has already looked without finding the
    /// end: the next call resumes there.
    pub(crate) searched: usize,
}

/// The offset just past the blank line that ends a header block, searching from `start`, alongside
/// how many bytes of `buf` this call examined — the pair a caller uses to pin the scan's own
/// complexity class without a process-global counter racing every other test in the binary.
///
/// The search JUMPS between line feeds rather than stepping a four-byte window over every position;
/// the terminator's last byte is one, so no candidate is skipped. `start` may sit anywhere in the
/// buffer: the match looks BACKWARD from the line feed it found, so a caller resuming a scan never
/// has to have kept the three bytes before it in view.
pub(crate) fn find_header_end_from(buf: &[u8], start: usize) -> (Option<usize>, usize) {
    let mut i = start.min(buf.len());
    let scanned = buf.len() - i;
    let found = loop {
        let Some(rel) = memchr::memchr(b'\n', &buf[i..]) else {
            break None;
        };
        let at = i + rel;
        if at >= 3 && &buf[at - 3..=at] == b"\r\n\r\n" {
            break Some(at + 1);
        }
        i = at + 1;
    };
    (found, scanned)
}
