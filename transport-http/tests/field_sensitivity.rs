// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use std::collections::BTreeMap;
use std::ffi::c_void;
use std::mem::{size_of, zeroed};

use busbar_contract::abi::host::service::SCHEME_PLAIN;
use busbar_contract::abi::mechanism::call::{
    AbiStr, Blob, Field, InHead, Op, OutHead, Outcome, BLOB_OCTETS,
};
use busbar_contract::abi::mechanism::extensions;
use busbar_contract::abi::mechanism::lifecycle::{slot as life, OpenIn, OpenOut};
use busbar_contract::abi::mechanism::ticket::Ticket;
use busbar_contract::abi::transport::{
    slot, BeginIn, ConnFacts, EmitIn, EncodeIn, FramePiece, FramerOut, FramerSink, HeadSlots,
    IngestIn, Ops, SIDE_DIAL, YIELD_MORE,
};

fn z<T>() -> T {
    // SAFETY: this test constructs only plain ABI frames whose zero values are valid.
    unsafe { zeroed() }
}
fn text(value: &str) -> AbiStr {
    AbiStr {
        ptr: value.as_ptr(),
        len: value.len(),
    }
}
fn blob(value: &[u8]) -> Blob {
    Blob {
        ptr: value.as_ptr(),
        len: value.len(),
        fmt: BLOB_OCTETS,
        flags: 0,
    }
}
fn ops() -> &'static Ops {
    #[allow(unused_unsafe)]
    // SAFETY: this crate's linked door takes no argument and returns its static table.
    let door = unsafe { busbar_transport_http::door::door() };
    // SAFETY: the linked door owns its static transport table.
    unsafe { &*(*door).ops().cast::<Ops>() }
}
fn call<I, O>(
    op: Option<Op>,
    instance: *mut c_void,
    input: &mut I,
    output: &mut O,
    index: u32,
) -> Outcome {
    // SAFETY: these inputs and outputs all start with their ABI heads.
    unsafe {
        let head = &mut *std::ptr::from_mut(input).cast::<InHead>();
        head.size = size_of::<I>() as u32;
        head.op = index;
        head.ticket = Ticket {
            slot: index,
            generation: 1,
        };
        (*std::ptr::from_mut(output).cast::<OutHead>()).size = size_of::<O>() as u32;
    }
    #[allow(unused_unsafe)]
    // SAFETY: all lent frames and their buffers remain live for the ABI crossing.
    unsafe {
        op.unwrap()(
            instance,
            std::ptr::from_ref(input).cast(),
            std::ptr::from_mut(output).cast(),
        )
        .outcome()
    }
}

struct Client {
    instance: *mut c_void,
    framing: u64,
    wire: Vec<u8>,
    frame: Vec<u8>,
    pieces: Vec<FramePiece>,
    heads: Vec<HeadSlots>,
    sent: Vec<u8>,
}

impl Client {
    fn new() -> Self {
        let mut input: OpenIn = z();
        let mut output: OpenOut = z();
        assert_eq!(
            call(
                ops().head.open,
                std::ptr::null_mut(),
                &mut input,
                &mut output,
                life::OPEN
            ),
            Outcome::Ready
        );
        let mut client = Self {
            instance: output.instance,
            framing: 0,
            wire: vec![0; 65536],
            frame: vec![0; 65536],
            pieces: vec![z(); 64],
            heads: vec![z(); 64],
            sent: Vec::new(),
        };
        let mut facts: ConnFacts = z();
        facts.size = size_of::<ConnFacts>() as u32;
        facts.agreed_protocol = text("h2");
        let mut input: BeginIn = z();
        input.side = SIDE_DIAL;
        input.scheme = SCHEME_PLAIN;
        input.target = text("http://wire.test:80");
        input.facts = &facts;
        input.sink = client.sink();
        let mut output: FramerOut = z();
        assert_eq!(
            call(
                ops().begin,
                client.instance,
                &mut input,
                &mut output,
                slot::BEGIN
            ),
            Outcome::Ready
        );
        client.framing = output.framing;
        client.take(&output);
        // A real HTTP/2 server's empty SETTINGS, using the existing hand-written peer pattern.
        client.ingest(&[0, 0, 0, 4, 0, 0, 0, 0, 0]);
        client
    }
    fn sink(&mut self) -> FramerSink {
        FramerSink {
            wire: self.wire.as_mut_ptr(),
            wire_cap: self.wire.len(),
            frame: self.frame.as_mut_ptr(),
            frame_cap: self.frame.len(),
            pieces: self.pieces.as_mut_ptr(),
            pieces_cap: self.pieces.len(),
            heads: self.heads.as_mut_ptr(),
            heads_cap: self.heads.len(),
            now_monotonic_ns: 1,
            now_unix_ns: 1,
        }
    }
    fn take(&mut self, output: &FramerOut) {
        self.sent
            .extend_from_slice(&self.wire[..output.yielded.wire_len as usize]);
        assert_eq!(
            output.yielded.flags & YIELD_MORE,
            0,
            "the roomy output holds this small request whole"
        );
    }
    fn ingest(&mut self, bytes: &[u8]) {
        let mut input: IngestIn = z();
        input.framing = self.framing;
        input.bytes = bytes.as_ptr();
        input.len = bytes.len();
        input.sink = self.sink();
        let mut output: FramerOut = z();
        assert_eq!(
            call(
                ops().ingest,
                self.instance,
                &mut input,
                &mut output,
                slot::INGEST
            ),
            Outcome::Ready
        );
        self.take(&output);
    }
    fn encode(&mut self, private: bool) -> Vec<u8> {
        let mut pairs = vec![
            ("x-public", "visible"),
            ("content-type", "application/grpc"),
        ];
        if private {
            pairs.extend([("X-Api-Key", "dummy-one"), ("x-api-key", "dummy-two")]);
        }
        self.encode_fields(&pairs)
    }
    fn encode_fields(&mut self, pairs: &[(&str, &str)]) -> Vec<u8> {
        let fields: Vec<_> = pairs
            .iter()
            .map(|(name, value)| Field {
                name: text(name),
                value: text(value),
            })
            .collect();
        let mut input: EncodeIn = z();
        input.fields = fields.as_ptr();
        input.fields_len = fields.len();
        input.method = text("POST");
        input.target = text("/call");
        input.sink = self.sink();
        let mut output: FramerOut = z();
        assert_eq!(
            call(
                ops().encode,
                self.instance,
                &mut input,
                &mut output,
                slot::ENCODE
            ),
            Outcome::Ready
        );
        self.wire[..output.yielded.wire_len as usize].to_vec()
    }
    fn emit(&mut self, stream: u64, bytes: &[u8], end: bool, extension: &[u8]) -> Outcome {
        let mut input: EmitIn = z();
        input.framing = self.framing;
        input.stream = stream;
        input.bytes = bytes.as_ptr();
        input.len = bytes.len();
        input.end_of_frame = u32::from(end);
        input.head.extensions = blob(extension);
        input.sink = self.sink();
        let mut output: FramerOut = z();
        let outcome = call(
            ops().emit,
            self.instance,
            &mut input,
            &mut output,
            slot::EMIT,
        );
        if outcome == Outcome::Ready {
            self.take(&output);
        }
        outcome
    }
}
impl Drop for Client {
    fn drop(&mut self) {
        let mut input: InHead = z();
        let mut output: OutHead = z();
        let _ = call(
            ops().head.close,
            self.instance,
            &mut input,
            &mut output,
            life::CLOSE,
        );
    }
}

fn classification() -> Vec<u8> {
    classification_for(&["X-Api-Key"])
}

fn classification_for(names: &[&str]) -> Vec<u8> {
    let mut value = 1_u32.to_le_bytes().to_vec();
    value.extend_from_slice(&(names.len() as u32).to_le_bytes());
    for name in names {
        value.extend_from_slice(&(name.len() as u32).to_le_bytes());
        value.extend_from_slice(name.as_bytes());
    }
    extensions::encode(&[("fields.sensitive", &value)])
}

fn integer(bytes: &[u8], at: &mut usize, prefix: u8) -> usize {
    let mask = (1 << prefix) - 1;
    let mut value = usize::from(bytes[*at] & mask);
    *at += 1;
    if value != usize::from(mask) {
        return value;
    }
    let mut shift = 0;
    loop {
        let byte = bytes[*at];
        *at += 1;
        value += usize::from(byte & 0x7f) << shift;
        if byte & 0x80 == 0 {
            return value;
        }
        shift += 7;
    }
}
fn string(bytes: &[u8], at: &mut usize) {
    let len = integer(bytes, at, 7);
    *at += len;
    assert!(*at <= bytes.len());
}
fn never_indexed(block: &[u8]) -> usize {
    let (mut at, mut count) = (0, 0);
    while at < block.len() {
        let first = block[at];
        if first & 0x80 != 0 {
            integer(block, &mut at, 7);
            continue;
        }
        if first & 0xe0 == 0x20 {
            integer(block, &mut at, 5);
            continue;
        }
        let prefix = if first & 0x40 != 0 { 6 } else { 4 };
        count += usize::from(first & 0xf0 == 0x10);
        if integer(block, &mut at, prefix) == 0 {
            string(block, &mut at);
        }
        string(block, &mut at);
    }
    count
}
fn header_blocks(wire: &[u8]) -> BTreeMap<u32, Vec<u8>> {
    assert!(wire.starts_with(b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"));
    let mut at = 24;
    let mut blocks = BTreeMap::<u32, Vec<u8>>::new();
    while at < wire.len() {
        let len = usize::from(wire[at]) << 16
            | usize::from(wire[at + 1]) << 8
            | usize::from(wire[at + 2]);
        let kind = wire[at + 3];
        let flags = wire[at + 4];
        let stream = u32::from_be_bytes(wire[at + 5..at + 9].try_into().unwrap()) & 0x7fffffff;
        let mut body = &wire[at + 9..at + 9 + len];
        if matches!(kind, 1 | 9) {
            if flags & 8 != 0 {
                let pad = usize::from(body[0]);
                body = &body[1..body.len() - pad];
            }
            if kind == 1 && flags & 32 != 0 {
                body = &body[5..];
            }
            blocks.entry(stream).or_default().extend_from_slice(body);
        }
        at += 9 + len;
    }
    blocks
}

#[test]
fn credentials_are_never_indexed_after_reparse_while_public_sibling_requests_stay_unmarked() {
    let mut client = Client::new();
    let private = client.encode(true);
    let public = client.encode(false);
    let mut metadata = classification();
    assert_eq!(
        client.emit(1, &private[..7], false, &metadata),
        Outcome::Ready
    );
    metadata.fill(0); // The input extension loan ended; the partial request retains its own copy.
    assert_eq!(client.emit(2, &public, true, &[]), Outcome::Ready);
    assert_eq!(client.emit(1, &private[7..], true, &[]), Outcome::Ready);
    assert_eq!(
        client.emit(3, &private, true, &classification()),
        Outcome::Ready
    );
    assert_eq!(client.emit(4, &private, true, &[]), Outcome::Ready);
    for _ in 0..4 {
        client.ingest(&[]);
    }
    let blocks = header_blocks(&client.sent);
    assert_eq!(blocks.len(), 4);
    let flags: Vec<_> = blocks.values().map(|block| never_indexed(block)).collect();
    assert_eq!(
        flags,
        [0, 2, 2, 0],
        "only the two credential values carry HPACK never-indexed, on every marked request"
    );
}

#[test]
fn malformed_present_classification_fails_before_any_request_headers_reach_the_encoder() {
    let mut client = Client::new();
    let private = client.encode(true);
    let invalid = extensions::encode(&[("fields.sensitive", b"bad")]);
    assert_eq!(client.emit(1, &private, true, &invalid), Outcome::Failed);
    assert!(header_blocks(&client.sent).is_empty());
}

#[test]
fn a_previously_public_exact_value_becomes_never_indexed_when_classified_sensitive() {
    let mut client = Client::new();
    let request = client.encode(true);
    assert_eq!(client.emit(1, &request, true, &[]), Outcome::Ready);
    for _ in 0..4 {
        client.ingest(&[]);
    }
    assert_eq!(
        client.emit(2, &request, true, &classification()),
        Outcome::Ready
    );
    assert_eq!(client.emit(3, &request, true, &[]), Outcome::Ready);
    for _ in 0..4 {
        client.ingest(&[]);
    }
    let blocks = header_blocks(&client.sent);
    assert_eq!(blocks.len(), 3);
    let flags: Vec<_> = blocks.values().map(|block| never_indexed(block)).collect();
    assert_eq!(flags, [0, 2, 0], "a dynamic-table exact match must honor each request's classification without marking its public siblings");
}

#[test]
fn a_sensitive_exact_static_table_value_is_a_never_indexed_literal() {
    let mut client = Client::new();
    // RFC 7541 Appendix A entry16 is this exact name and value.
    let request = client.encode_fields(&[
        ("accept-encoding", "gzip, deflate"),
        ("x-public", "visible"),
        ("content-type", "application/grpc"),
    ]);
    assert_eq!(client.emit(1, &request, true, &[]), Outcome::Ready);
    assert_eq!(
        client.emit(2, &request, true, &classification_for(&["accept-encoding"])),
        Outcome::Ready
    );
    assert_eq!(client.emit(3, &request, true, &[]), Outcome::Ready);
    for _ in 0..4 {
        client.ingest(&[]);
    }
    let blocks = header_blocks(&client.sent);
    assert_eq!(blocks.len(), 3);
    let flags: Vec<_> = blocks.values().map(|block| never_indexed(block)).collect();
    assert_eq!(
        flags,
        [0, 1, 0],
        "an exact static-table match must preserve the sensitive flag on the wire"
    );
}
