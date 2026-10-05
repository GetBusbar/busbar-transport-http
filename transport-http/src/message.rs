// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The HTTP/1.1 message the framer reads a request through: whether the bytes an `emit` has
//! carried so far are one whole message yet (the egress cross-check's framing), the request target
//! a dialled exchange goes to, and the upstream's `Retry-After` read off a response head.

use busbar_contract::transport::wire::TransportError;

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
/// HTTP-date, converted to the seconds remaining until that instant and floored at 0 when it is
/// already in the past.
///
/// The arithmetic is the one the breaker's own classifier does, and it is duplicated here rather
/// than shared: this crate sits on the transport axis and may not name a unit crate, and the unit
/// crate's own dependency policy names the capability crate as the only workspace crate it may see.
/// Neither can reach the other, so there is no shared home for four lines of date parsing. The forms
/// accepted and the flooring rule are pinned by the tests below against the same values.
///
/// (The capability crate is deliberately not spelled here. `tests/no_plane_names.rs` refuses that
/// name anywhere in this crate's source, and a rule with an exception for prose is a rule with an
/// exception — the sentence says the same thing without one.)
pub(crate) fn parse_retry_after(value: &str, now: u64) -> Option<u64> {
    let s = value.trim();
    if let Ok(n) = s.parse::<u64>() {
        return Some(n);
    }
    parse_imf_fixdate_retry_after(s, now)
}

/// Parse the value as an IMF-fixdate (`Sun, 06 Nov 1994 08:49:37 GMT`, the sole HTTP-date form RFC
/// 9110 recommends generating) and return the whole seconds remaining until it, floored at 0 for a
/// date already in the past.
fn parse_imf_fixdate_retry_after(s: &str, now: u64) -> Option<u64> {
    // "Www, dd Mon yyyy HH:MM:SS GMT" — fixed-width, so a byte-length check plus field slicing is
    // enough; no general calendar library is warranted for one wire format.
    if s.len() != 29 || !s.ends_with(" GMT") {
        return None;
    }
    if s.as_bytes().get(3) != Some(&b',') || s.as_bytes().get(4) != Some(&b' ') {
        return None;
    }
    let day: u64 = s.get(5..7)?.parse().ok()?;
    let month = month_from_abbrev(s.get(8..11)?)?;
    let year: u64 = s.get(12..16)?.parse().ok()?;
    let hour: u64 = s.get(17..19)?.parse().ok()?;
    let minute: u64 = s.get(20..22)?.parse().ok()?;
    let second: u64 = s.get(23..25)?.parse().ok()?;
    let epoch_secs = civil_to_epoch_secs(year, month, day, hour, minute, second)?;
    Some(epoch_secs.saturating_sub(now))
}

fn month_from_abbrev(m: &str) -> Option<u64> {
    Some(match m {
        "Jan" => 1,
        "Feb" => 2,
        "Mar" => 3,
        "Apr" => 4,
        "May" => 5,
        "Jun" => 6,
        "Jul" => 7,
        "Aug" => 8,
        "Sep" => 9,
        "Oct" => 10,
        "Nov" => 11,
        "Dec" => 12,
        _ => return None,
    })
}

/// Days-from-civil (Howard Hinnant's public-domain algorithm), giving a UTC Unix timestamp for a
/// UTC calendar date and time with no external date/time dependency.
fn civil_to_epoch_secs(
    year: u64,
    month: u64,
    day: u64,
    hour: u64,
    minute: u64,
    second: u64,
) -> Option<u64> {
    let y = year as i64 - i64::from(month <= 2);
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = y - era * 400; // [0, 399]
    let mp = (month as i64 + 9) % 12; // [0, 11]
    let doy = (153 * mp + 2) / 5 + day as i64 - 1; // [0, 365]
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy; // [0, 146096]
    let days_since_epoch = era * 146_097 + doe - 719_468;
    let days_since_epoch = u64::try_from(days_since_epoch).ok()?;
    Some(days_since_epoch * 86_400 + hour * 3600 + minute * 60 + second)
}

/// Where an egress request actually goes: the dialled scheme and authority, carrying the path the
/// ENVELOPE named.
///
/// A dial pins a destination — scheme, host, port. It does not pin a request: one connection to an
/// upstream carries many requests, and on an API whose surface is its path they are different
/// requests only because their paths differ. So the path travels with the message, and the dial
/// URI's own path stands in only when the message names none (`/` or empty), which is the shape a
/// caller writes when the dial URI already spells the whole target.
pub(crate) fn request_target(dial: &http::Uri, path: &str) -> Result<http::Uri, TransportError> {
    if path.is_empty() || path == "/" {
        return Ok(dial.clone());
    }
    let mut parts = dial.clone().into_parts();
    parts.path_and_query = Some(
        path.parse::<http::uri::PathAndQuery>()
            .map_err(|_| TransportError::Framing)?,
    );
    http::Uri::from_parts(parts).map_err(|_| TransportError::Framing)
}

/// A message this transport has been handed enough of to send, or `None` for a prefix of one.
///
/// The three endings are the wire's own: a declared `Content-Length` reached, the terminal chunk of
/// a chunked body seen, or a message that declares neither coding and therefore carries no body at
/// all. A chunked message is decoded here, so what comes back always carries the body itself rather
/// than a framing of it.
pub(crate) fn complete_message(
    buffered: &[u8],
    cache: &mut EgressHead,
    max_body_bytes: usize,
) -> Result<Option<raw::RawMessage>, TransportError> {
    if cache.head.is_none() {
        let Some(header_end) = find_header_end(buffered) else {
            return Ok(None);
        };
        let message = raw::parse_message(&buffered[..header_end]).ok_or(TransportError::Framing)?;
        cache.parses += 1;
        if raw::has_transfer_encoding(&message.headers) {
            if !raw::is_chunked(&message.headers) {
                // A declared coding this transport cannot frame. Falling through to
                // `Content-Length` would be answering a question the sender did not ask.
                return Err(TransportError::Framing);
            }
            if raw::header(&message.headers, "content-length").is_some() {
                // Two headers describing two framings of the same bytes. The coding wins the
                // reading, but forwarding the pair on — as this used to do — hands the next hop a
                // length the bytes do not have, the smuggling shape itself. Refused rather than
                // silently disambiguated, mirroring the ingress reader's identical refusal.
                return Err(TransportError::Framing);
            }
        }
        cache.head = Some(CachedHead {
            end: header_end,
            start: message.start,
            headers: message.headers,
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

    let (body, trailers) = if chunked {
        // ONE decoder across the calls, fed only what arrived with this one. A fresh decoder per
        // call re-decodes every byte received so far and re-allocates the decoded chunks each
        // time — quadratic in the body, which for the megabyte bodies this path exists to carry is
        // the difference between a transport and a stall. The ingress reader already reads this
        // way; this is the same reading on the side that accumulates.
        let decoder = cache
            .decoder
            .get_or_insert_with(|| Box::new(raw::ChunkedDecoder::default()));
        let fresh = &rest[cache.fed.min(rest.len())..];
        cache.feeds += fresh.len();
        decoder.feed(fresh).map_err(|_| TransportError::Framing)?;
        cache.fed = rest.len();
        if !decoder.is_done() {
            return Ok(None);
        }
        let (chunks, trailers) = cache.decoder.take().expect("set just above").take();
        (chunks.concat(), trailers)
    } else {
        let declared = declared.map_err(|()| TransportError::Framing)?.unwrap_or(0);
        if declared > max_body_bytes {
            return Err(TransportError::Framing);
        }
        if rest.len() < declared {
            return Ok(None);
        }
        (rest[..declared].to_vec(), Vec::new())
    };

    // Whole: the head is spent with the message it belonged to, so the next one parses its own,
    // and the decoder that read this body is spent with it too.
    let mut head = cache.head.take().expect("set just above");
    cache.decoder = None;
    cache.fed = 0;
    // A trailer is a header that arrived late; it goes where every other header went, so
    // nothing downstream has to know which side of the body it was written on.
    head.headers.extend(trailers);
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
    pub(crate) headers: Vec<(String, String)>,
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
    /// call feeds only the bytes that arrived with it — the same discipline the ingress reader
    /// keeps across reads. Behind a box because it is a per-message working set that most
    /// connections never allocate, and inline it would be carried by every connection ever dialled.
    pub(crate) decoder: Option<Box<raw::ChunkedDecoder>>,
    /// How many bytes past the header block have already been fed to `decoder`.
    pub(crate) fed: usize,
    /// This connection's own tally of bytes fed to a decoder, per instance for the same reason
    /// `parses` is: a test reading it back sees only its own connection's work.
    pub(crate) feeds: usize,
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

pub(crate) fn find_header_end(buf: &[u8]) -> Option<usize> {
    find_header_end_from(buf, 0).0
}
