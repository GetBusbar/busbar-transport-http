// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE 1.5.5 BYTE COMPARISON, SECOND OPINION: an HTTP/2 bearer request, as 1.5.5's egress client
//! put it on the wire and as this door puts it on the wire, byte for byte.
//!
//! The exit test is `tests/wire_golden.rs`, which reads what the PUBLISHED 1.5.5 binary sent (the
//! recorded capture cells). This file rebuilds 1.5.5's client from its source instead, so a drift
//! between the recording and a fresh reqwest 0.12 build shows up as a disagreement between the two.
//!
//! 1.5.5's client is reqwest 0.12 with its `http2` feature, built with exactly the calls 1.5.5 made
//! (`crates/busbar/src/main.rs` at v1.5.5, the shared upstream client: keep-alive 30s/10s, adaptive
//! window, no redirects, and the cleartext prior-knowledge key so the bytes can be read). It sends to
//! a listener that only records. The door is driven through its table with the same request, and
//! the two captures are compared frame by frame: the connection preface, SETTINGS, WINDOW_UPDATE,
//! then the request's HEADERS (the HPACK block, byte for byte) and DATA.

mod common;

use std::mem::{size_of, zeroed};
use std::time::Duration;

use busbar_contract::abi::mechanism::call::{AbiStr, Blob, Field, InHead, Op, OutHead, BLOB_JSON};
use busbar_contract::abi::mechanism::lifecycle::{slot as life, OpenIn, OpenOut};
use busbar_contract::abi::transport::{
    slot, BeginIn, ConnFacts, EmitIn, EncodeIn, FramePiece, FramerOut, FramerSink, LocateIn,
    LocateOut, Ops, SIDE_DIAL,
};
use tokio::io::AsyncReadExt;

use common::{frame_name, h2_frames};

const BODY: &str =
    r#"{"model":"claude-x","max_tokens":8,"messages":[{"role":"user","content":"hi"}]}"#;
const BEARER: &str = "Bearer sk-ant-test-0123456789";

fn z<T>() -> T {
    // SAFETY: plain C data; all-zero is valid.
    unsafe { zeroed() }
}

fn s(text: &str) -> AbiStr {
    AbiStr {
        ptr: text.as_ptr(),
        len: text.len(),
    }
}

fn call<I, O>(op: Option<Op>, inst: *mut std::ffi::c_void, i: &mut I, o: &mut O, index: u32) {
    // SAFETY: `I`/`O` lead with their heads.
    unsafe {
        let ih = std::ptr::from_mut(i).cast::<InHead>();
        (*ih).size = size_of::<I>() as u32;
        (*ih).op = index;
        (*std::ptr::from_mut(o).cast::<OutHead>()).size = size_of::<O>() as u32;
    }
    let r = (op.expect("slot"))(
        inst,
        std::ptr::from_ref(i).cast(),
        std::ptr::from_mut(o).cast(),
    );
    assert_eq!(
        r.outcome(),
        busbar_contract::abi::mechanism::call::Outcome::Ready
    );
}

/// What 1.5.5's client wrote for a POST of `body`, read off a listener that answers nothing.
fn capture_155(rt: &tokio::runtime::Runtime, h2: bool, body: &'static str) -> (Vec<u8>, u16) {
    rt.block_on(async {
        let l = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind");
        let port = l.local_addr().expect("addr").port();
        let rec = tokio::spawn(async move {
            let (mut sock, _) = l.accept().await.expect("accept");
            let mut got = Vec::new();
            let mut buf = [0_u8; 4096];
            while let Ok(Ok(n)) =
                tokio::time::timeout(Duration::from_millis(400), sock.read(&mut buf)).await
            {
                if n == 0 {
                    break;
                }
                got.extend_from_slice(&buf[..n]);
            }
            got
        });
        // 1.5.5's shared upstream client, call for call (v1.5.5 crates/busbar/src/main.rs).
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(300))
            .connect_timeout(Duration::from_secs(10))
            .tcp_keepalive(Duration::from_secs(60))
            .tcp_nodelay(true)
            .http2_keep_alive_interval(Duration::from_secs(30))
            .http2_keep_alive_timeout(Duration::from_secs(10))
            .http2_adaptive_window(true)
            .pool_max_idle_per_host(32)
            .pool_idle_timeout(Duration::from_secs(4))
            .redirect(reqwest::redirect::Policy::none());
        // The two keys, as 1.5.5 applied them: prior knowledge, or HTTP/1.1 only.
        let client = if h2 {
            client.http2_prior_knowledge()
        } else {
            client.http1_only()
        }
        .build()
        .expect("client");
        let req = client
            .post(format!("http://127.0.0.1:{port}/v1/messages"))
            .header("authorization", BEARER)
            .header("content-type", "application/json")
            .body(body);
        let _ = tokio::time::timeout(Duration::from_millis(600), req.send()).await;
        (rec.await.expect("record"), port)
    })
}

/// What the door wrote for the same request. `state_len` is whether the host states the length line
/// before the auth; the host states one for a non-empty body and none for an empty one
/// (busbar-kernel `plane_driver/far_end.rs`, the length the head defaults ask for).
fn capture_door(port: u16, h2: bool, body: &str, state_len: bool) -> Vec<u8> {
    let d = busbar_transport_http::door::door();
    // SAFETY: the door's `'static` table.
    let ops: &Ops = unsafe { &*(*d).ops.cast::<Ops>() };
    let settings = if h2 {
        r#"{"advanced.upstream_h2_prior_knowledge":true}"#
    } else {
        r#"{"advanced.upstream_http1_only":true}"#
    };
    let mut i: OpenIn = z();
    i.settings = Blob {
        ptr: settings.as_ptr(),
        len: settings.len(),
        fmt: BLOB_JSON,
        flags: 0,
    };
    let mut o: OpenOut = z();
    call(
        ops.head.open,
        std::ptr::null_mut(),
        &mut i,
        &mut o,
        life::OPEN,
    );
    let inst = o.instance;
    let mut wire = vec![0_u8; 64 * 1024];
    let mut frame = vec![0_u8; 1024];
    let mut pieces: Vec<FramePiece> = vec![z(); 8];
    let (wp, fp, pp) = (wire.as_mut_ptr(), frame.as_mut_ptr(), pieces.as_mut_ptr());
    let sink = || FramerSink {
        wire: wp,
        wire_cap: 64 * 1024,
        frame: fp,
        frame_cap: 1024,
        pieces: pp,
        pieces_cap: 8,
        now_monotonic_ns: 5_000_000_000,
        now_unix_ns: 1_790_000_000_000_000_000,
        heads: std::ptr::null_mut(),
        heads_cap: 0,
    };
    let mut out = Vec::new();
    let mut facts: ConnFacts = z();
    facts.size = size_of::<ConnFacts>() as u32;
    let target = format!("http://127.0.0.1:{port}");
    let mut b: BeginIn = z();
    b.side = SIDE_DIAL;
    b.target = s(&target);
    b.facts = &facts;
    b.sink = sink();
    let mut fo: FramerOut = z();
    call(ops.begin, inst, &mut b, &mut fo, slot::BEGIN);
    let framing = fo.framing;
    out.extend_from_slice(&wire[..fo.yielded.wire_len as usize]);
    // THE HOST'S MERGE (THE DESIGN §6 step 5): the lines the framer's `locate` states for the
    // target, added after the caller's fields, before the auth.
    let mut defaults = vec![0_u8; 512];
    let (mut a, mut n, mut l) = (vec![0_u8; 256], vec![0_u8; 256], vec![0_u8; 64]);
    let mut li: LocateIn = z();
    li.target = s(&target);
    (li.authority_buf, li.authority_cap) = (a.as_mut_ptr(), a.len());
    (li.name_buf, li.name_cap) = (n.as_mut_ptr(), n.len());
    (li.alpn_buf, li.alpn_cap) = (l.as_mut_ptr(), l.len());
    (li.defaults_buf, li.defaults_cap) = (defaults.as_mut_ptr(), defaults.len());
    let mut lo: LocateOut = z();
    call(ops.locate, inst, &mut li, &mut lo, slot::LOCATE);
    let stated = String::from_utf8_lossy(&defaults[..lo.defaults_written as usize]).into_owned();
    let lines: Vec<(&str, &str)> = stated
        .split("\r\n")
        .filter_map(|l| l.split_once(": "))
        .collect();
    let mut fields = vec![
        Field {
            name: s("method"),
            value: s("POST"),
        },
        Field {
            name: s("path"),
            value: s("/v1/messages"),
        },
        Field {
            name: s("authorization"),
            value: s(BEARER),
        },
        Field {
            name: s("content-type"),
            value: s("application/json"),
        },
    ];
    fields.extend(lines.iter().map(|(n, v)| Field {
        name: s(n),
        value: s(v),
    }));
    // Then the length line the host states, last.
    let len = body.len().to_string();
    if state_len {
        fields.push(Field {
            name: s("content-length"),
            value: s(&len),
        });
    }
    let mut e: EncodeIn = z();
    e.fields = fields.as_ptr();
    e.fields_len = fields.len();
    e.body = body.as_ptr();
    e.body_len = body.len();
    e.sink = sink();
    let mut eo: FramerOut = z();
    call(ops.encode, inst, &mut e, &mut eo, slot::ENCODE);
    let message = wire[..eo.yielded.wire_len as usize].to_vec();
    let mut m: EmitIn = z();
    m.framing = framing;
    m.stream = 1;
    m.bytes = message.as_ptr();
    m.len = message.len();
    m.end_of_frame = 1;
    m.sink = sink();
    let mut mo: FramerOut = z();
    call(ops.emit, inst, &mut m, &mut mo, slot::EMIT);
    out.extend_from_slice(&wire[..mo.yielded.wire_len as usize]);
    let mut c: InHead = z();
    let mut co: OutHead = z();
    call(ops.head.close, inst, &mut c, &mut co, life::CLOSE);
    out
}

#[test]
fn an_h2_bearer_request_is_the_bytes_1_5_5_sent() {
    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .expect("runtime");
    let (old, port) = capture_155(&rt, true, BODY);
    // The port is part of `:authority`; the door dials the one the capture listened on.
    let (old_preface, old_frames) = h2_frames(&old);
    let (new_preface, new_frames) = h2_frames(&capture_door(port, true, BODY, true));
    for (label, f) in [("1.5.5", &old_frames), ("door", &new_frames)] {
        let line: Vec<String> = f
            .iter()
            .map(|(t, fl, st, p)| {
                format!(
                    "{}(flags={fl:#x},stream={st},len={})",
                    frame_name(*t),
                    p.len()
                )
            })
            .collect();
        println!("PROOF {label}: {}", line.join(" "));
    }
    assert_eq!(old_preface, new_preface, "the connection preface");
    assert_eq!(old_frames, new_frames, "every frame, byte for byte");
    println!(
        "PROOF the door's h2 bearer request is byte-identical to 1.5.5's ({} bytes)",
        old.len()
    );
}

/// The same request under the http1-only key: 1.5.5's HTTP/1.1 bytes (origin-form target, `host`,
/// reqwest's `accept`) and the door's, byte for byte.
#[test]
fn an_http1_only_bearer_request_is_the_bytes_1_5_5_sent() {
    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .expect("runtime");
    let (old, port) = capture_155(&rt, false, BODY);
    let new = capture_door(port, false, BODY, true);
    println!("PROOF 1.5.5 http/1.1:\n{}", String::from_utf8_lossy(&old));
    assert_eq!(String::from_utf8_lossy(&old), String::from_utf8_lossy(&new));
    println!(
        "PROOF the door's http/1.1 bearer request is byte-identical to 1.5.5's ({} bytes)",
        old.len()
    );
}

/// THE ONE LINE ADDED AFTER THE AUTH, PINNED (Q128 transport-http, ruling (D); `meta::TAIL` names
/// it): HTTP/2, a payload method, an EMPTY body. The host states no length for an empty body, and
/// the h2 framing adds `content-length: 0` at send, exactly as 1.5.5's client did. The door's
/// frames are 1.5.5's client's byte for byte; and they are the very bytes the door sends when the
/// head STATES `content-length: 0` before the auth, so the line on the wire is that one and no
/// other. (1.5.5's recorded goldens carry no empty-body payload request, so the comparison is
/// against 1.5.5's client rebuilt from its source, as this file's other cells are.)
#[test]
fn an_h2_empty_post_carries_content_length_0_as_1_5_5_sent() {
    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .expect("runtime");
    let (old, port) = capture_155(&rt, true, "");
    let (old_preface, old_frames) = h2_frames(&old);
    let (new_preface, new_frames) = h2_frames(&capture_door(port, true, "", false));
    assert_eq!(old_preface, new_preface, "the connection preface");
    assert_eq!(
        old_frames, new_frames,
        "an empty h2 POST: every frame, byte for byte, 1.5.5's"
    );
    let (_, stated) = h2_frames(&capture_door(port, true, "", true));
    assert_eq!(
        new_frames, stated,
        "the line the h2 framing adds is `content-length: 0`: the same bytes as a head stating it"
    );
    assert!(
        new_frames.iter().all(|(t, _, _, _)| *t != 0),
        "an empty body sends no DATA frame"
    );
    println!("PROOF an empty h2 POST carries content-length: 0, byte-identical to 1.5.5's");
}

/// The same empty POST on HTTP/1.1 (ruling (D)): no length line, as 1.5.5's client sent none, byte
/// for byte.
#[test]
fn an_http1_empty_post_carries_no_length_line_as_1_5_5_sent() {
    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .expect("runtime");
    let (old, port) = capture_155(&rt, false, "");
    let new = capture_door(port, false, "", false);
    assert_eq!(String::from_utf8_lossy(&old), String::from_utf8_lossy(&new));
    assert!(
        !String::from_utf8_lossy(&new)
            .to_ascii_lowercase()
            .contains("content-length"),
        "{:?}",
        String::from_utf8_lossy(&new)
    );
    println!("PROOF an empty http/1.1 POST carries no length line, byte-identical to 1.5.5's");
}
