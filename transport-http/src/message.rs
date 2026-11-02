// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The HTTP/1.1 message the framer reads a request through: whether the bytes an `emit` has

use crate::raw;

/// Read the upstream's `Retry-After` off a response head and resolve it to whole seconds.

pub(crate) fn retry_after_secs(headers: &http::HeaderMap, now_secs: u64) -> Option<u64> {
    let raw = headers.get(http::header::RETRY_AFTER)?.to_str().ok()?;
    parse_retry_after(raw, now_secs)
}

/// Parse an RFC 9110 `Retry-After` header VALUE against `now` (a Unix timestamp in seconds). Both

pub(crate) fn parse_retry_after(value: &str, now: u64) -> Option<u64> {
    let s = value.trim();

    if !s.is_empty() && s.bytes().all(|b| b.is_ascii_digit()) {
        return s.parse::<u64>().ok();
    }
    let at = httpdate::parse_http_date(s).ok()?;
    let epoch_secs = at.duration_since(std::time::UNIX_EPOCH).ok()?.as_secs();
    Some(epoch_secs.saturating_sub(now))
}

/// Where an egress request actually goes: the dialled scheme and authority, carrying the target

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

/// A whole request message: where its head ends in the buffered bytes (the head is read in place
/// from them, `raw::Head::parse`), and a chunked body decoded. `decoded` is `None` for a
/// `Content-Length` body: it is the rest of the buffered bytes, where it already lies.
#[derive(Debug)]
pub(crate) struct Whole {
    pub(crate) head_end: usize,
    pub(crate) decoded: Option<zeroize::Zeroizing<Vec<u8>>>,
}

/// A message this transport has been handed enough of to send, or `None` for a prefix of one.

pub(crate) fn complete_message(
    buffered: &[u8],
    cache: &mut EgressHead,
    max_body_bytes: usize,
    max_head_bytes: usize,
) -> Result<Option<Whole>, &'static str> {
    let (head_end, framing) = match cache.head {
        Some(head) => head,
        None => {
            let found = find_header_end_from(buffered, cache.searched);
            #[cfg(test)]
            {
                cache.scanned += buffered.len() - cache.searched.min(buffered.len());
            }
            cache.searched = buffered.len();
            let Some(header_end) = found else {
                if buffered.len() > max_head_bytes {
                    return Err("request head over its allowance");
                }
                return Ok(None);
            };
            if header_end > max_head_bytes {
                return Err("request head over its allowance");
            }

            let framing = raw::Head::parse(&buffered[..header_end])?.framing()?;
            #[cfg(test)]
            {
                cache.parses += 1;
            }
            cache.head = Some((header_end, framing));
            (header_end, framing)
        }
    };
    let rest = &buffered[head_end..];

    let decoded = match framing {
        raw::BodyFraming::Chunked => {
            let decoder = cache.decoder.get_or_insert_with(Box::default);
            let fresh = &rest[cache.fed.min(rest.len())..];
            #[cfg(test)]
            {
                cache.feeds += fresh.len();
            }
            let used = decoder.feed(fresh).map_err(|_| "malformed chunked body")?;
            cache.fed = rest.len();

            if decoder.body_len() > max_body_bytes {
                return Err("decoded chunked body over the body cap");
            }
            if !decoder.is_done() {
                return Ok(None);
            }

            if used < fresh.len() {
                return Err("bytes past the end of the message");
            }
            Some(cache.decoder.take().expect("set just above").take())
        }
        raw::BodyFraming::Length(declared) => {
            if declared > max_body_bytes {
                return Err("declared body over the body cap");
            }
            if rest.len() < declared {
                return Ok(None);
            }

            if rest.len() > declared {
                return Err("bytes past the end of the message");
            }
            None
        }
    };

    cache.head = None;
    cache.decoder = None;
    cache.fed = 0;
    cache.searched = 0;
    Ok(Some(Whole { head_end, decoded }))
}

/// Where the message the door's `emit` is still accumulating stands.
///
/// `emit` asks whether the message is whole on EVERY chunk, and the header prefix does not change
/// between those asks: its end and framing are held here, and taken when the message completes so
/// they can never outlive it. A test build also tallies the work done here (heads parsed, bytes
/// fed to a decoder, bytes searched for a head's end), per instance rather than crate-global so a
/// test reading it back sees only its own connection's work.
#[derive(Default)]
pub(crate) struct EgressHead {
    /// Where the parsed head ends, and how its body is framed.
    pub(crate) head: Option<(usize, raw::BodyFraming)>,
    #[cfg(test)]
    pub(crate) parses: usize,
    /// The chunked decoder this message is being decoded by, kept across `emit` calls so each
    /// call feeds only the bytes that arrived with it. Behind a box because it is a per-message working set that most
    /// connections never allocate, and inline it would be carried by every connection ever dialled.
    pub(crate) decoder: Option<Box<raw::ChunkedDecoder>>,
    /// How many bytes past the header block have already been fed to `decoder`.
    pub(crate) fed: usize,
    #[cfg(test)]
    pub(crate) feeds: usize,
    #[cfg(test)]
    pub(crate) scanned: usize,
    /// How far into the pending bytes the header-end search has already looked without finding the
    /// end: the next call resumes there.
    pub(crate) searched: usize,
}

/// The offset just past the blank line that ends a header block, searching from `start`.

fn find_header_end_from(buf: &[u8], start: usize) -> Option<usize> {
    let mut i = start.min(buf.len());
    loop {
        let at = i + memchr::memchr(b'\n', &buf[i..])?;
        if at >= 3 && &buf[at - 3..=at] == b"\r\n\r\n" {
            return Some(at + 1);
        }
        i = at + 1;
    }
}
