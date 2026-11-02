// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors
//! Ordinary tests of this product's actual linked door and independently built cdylib.
use busbar_contract::abi::mechanism::call::{AbiStr, Blob, InHead};
use busbar_contract::abi::mechanism::lifecycle::{
    slot as life, OpenIn, RefreshIn, TickIn, TickOut, ValidateIn,
};
use busbar_plugin_loader::dispatch::{in_head, load_dropped, load_linked, out_head};
use serde_json::Value;
use std::sync::atomic::Ordering;

fn input<T: InFrame>() -> T {
    // SAFETY: ABI frames contain only zero-valid plain C data and begin with InHead.
    let mut v: T = unsafe { std::mem::zeroed() };
    unsafe { std::ptr::addr_of_mut!(v).cast::<InHead>().write(in_head()) };
    v
}
fn output<T: OutFrame>() -> T {
    // SAFETY: ABI frames contain only zero-valid plain C data and begin with OutHead.
    let mut v: T = unsafe { std::mem::zeroed() };
    unsafe {
        std::ptr::addr_of_mut!(v)
            .cast::<OutHead>()
            .write(out_head())
    };
    v
}
fn abi_bytes(b: &(impl AsRef<[u8]> + ?Sized)) -> AbiStr {
    AbiStr {
        ptr: b.as_ref().as_ptr(),
        len: b.as_ref().len(),
    }
}
fn count(p: &Plugin<Transport>) -> u64 {
    p.inner.crossings.load(Ordering::SeqCst) - p.inner.resumes.load(Ordering::SeqCst)
}
enum Expected {
    Exact(String),
    Prefix(&'static str),
}
use busbar_contract::abi::mechanism::call::{Field, OutHead, Outcome};
use busbar_contract::abi::transport::{
    slot, AcceptIn, AcceptOut, AdoptIn, ArrivalIn, ArrivalOut, BeginIn, ConnIn, ConnOut, DialIn,
    EmitIn, EncodeIn, FinishIn, FramePiece, FramerOut, FramerSink, FramingIn, IngestIn, IoOut,
    ListenIn, ListenOut, LocateIn, LocateOut, ReadIn, RefuseIn, ShutIn, WriteIn,
    PIECE_END_OF_FRAME, SIDE_ACCEPT, SIDE_DIAL, YIELD_ENDED, YIELD_HAS_DEADLINE, YIELD_MORE,
};

use busbar_plugin_loader::dispatch::kinds::transport::Transport;
use busbar_plugin_loader::dispatch::{Called, Frame, InFrame, OutFrame, Plugin};

const TIGHT_WIRE: usize = 4;

const TIGHT_FRAME: usize = 3;

const AMPLE: usize = 4096;

const MAX_REDRIVE: usize = 4096;

fn text(v: &serde_json::Value, what: &str) -> Vec<u8> {
    match v {
        serde_json::Value::String(s) => s.as_bytes().to_vec(),
        serde_json::Value::Null => panic!("conformance.json: transport.{what} is missing"),
        serde_json::Value::Object(o) if o.len() == 1 && o.contains_key("hex") => o["hex"]
            .as_str()
            .and_then(unhex)
            .unwrap_or_else(|| panic!("conformance.json: transport.{what}.hex is not hex")),
        other => other.to_string().into_bytes(),
    }
}

fn unhex(hex: &str) -> Option<Vec<u8>> {
    let digits = hex.as_bytes();
    if !digits.len().is_multiple_of(2) {
        return None;
    }
    digits
        .chunks(2)
        .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).ok()?, 16).ok())
        .collect()
}

fn opt_text(v: &serde_json::Value, what: &str) -> Vec<u8> {
    if v.is_null() {
        Vec::new()
    } else {
        text(v, what)
    }
}

fn texts(v: &serde_json::Value, what: &str) -> Vec<Vec<u8>> {
    v.as_array()
        .unwrap_or_else(|| panic!("conformance.json: transport.{what} must be an array"))
        .iter()
        .map(|x| text(x, what))
        .collect()
}

fn lossy(b: &[u8]) -> String {
    match std::str::from_utf8(b) {
        Ok(text) if !text.starts_with('\u{e000}') => text.to_owned(),
        _ => format!("\u{e000}{}", hex::encode(b)),
    }
}

fn sinkfuls(len: usize, cap: usize) -> u64 {
    len.div_ceil(cap).max(1) as u64
}

fn frame_sinkfuls(frames: &[Vec<u8>]) -> u64 {
    frames
        .iter()
        .map(|f| f.len().div_ceil(TIGHT_FRAME).max(1) as u64)
        .sum::<u64>()
        .max(1)
}

struct Sink {
    wire: Vec<u8>,
    frame: Vec<u8>,
    pieces: Vec<FramePiece>,
}

impl Sink {
    fn new(wire: usize, frame: usize, pieces: usize) -> Self {
        let piece = FramePiece {
            stream: 0,
            offset: 0,
            len: 0,
            code: 0,
            status_class: 0,
            fault: 0,
            flags: 0,
            retry_after_secs: 0,
            declared_len: 0,
        };
        Self {
            wire: vec![0; wire],
            frame: vec![0; frame],
            pieces: vec![piece; pieces],
        }
    }

    fn tight() -> Self {
        Self::new(TIGHT_WIRE, TIGHT_FRAME, 1)
    }

    fn ample() -> Self {
        Self::new(AMPLE, AMPLE, 16)
    }

    fn raw(&mut self) -> FramerSink {
        FramerSink {
            wire: self.wire.as_mut_ptr(),
            wire_cap: self.wire.len(),
            frame: self.frame.as_mut_ptr(),
            frame_cap: self.frame.len(),
            pieces: self.pieces.as_mut_ptr(),
            pieces_cap: self.pieces.len(),
            now_monotonic_ns: 1,
            now_unix_ns: 1,
            heads: std::ptr::null_mut(),
            heads_cap: 0,
        }
    }
}

/// What a (re-driven) framer op answered, gathered across its calls.
#[derive(Default)]
struct Yielded {
    /// The last call's outcome and error text.
    last: String,
    outcome: Option<Outcome>,
    wire: Vec<u8>,
    /// Whole frames (their last piece carried `PIECE_END_OF_FRAME`), and the piece flags seen.
    frames: Vec<Vec<u8>>,
    /// A frame begun and not ended.
    partial: Vec<u8>,
    /// Frame bytes answered with no piece (what `detach` hands back).
    raw: Vec<u8>,
    flags: u32,
    framing: u64,
}

impl Yielded {
    fn take(&mut self, c: &Called, o: &FramerOut, sink: &Sink) {
        let text = c.error.as_deref().map(lossy).unwrap_or_default();
        self.last = format!("{:?} lease={} err={text:?}", c.outcome, c.lease != 0);
        self.outcome = Some(c.outcome);
        self.flags = o.yielded.flags;
        if o.framing != 0 {
            self.framing = o.framing;
        }
        if c.outcome != Outcome::Ready {
            return;
        }

        let wire_len = (o.yielded.wire_len as usize).min(sink.wire.len());
        self.wire.extend_from_slice(&sink.wire[..wire_len]);
        let frame_len = (o.yielded.frame_len as usize).min(sink.frame.len());
        let pieces = (o.yielded.pieces_len as usize).min(sink.pieces.len());
        if pieces == 0 {
            self.raw.extend_from_slice(&sink.frame[..frame_len]);
        }
        for p in &sink.pieces[..pieces] {
            let at = p.offset as usize;
            let bytes = sink
                .frame
                .get(at..at + p.len as usize)
                .unwrap_or_else(|| panic!("a piece past the frame bytes: {p:?}"));
            self.partial.extend_from_slice(bytes);
            if p.flags & PIECE_END_OF_FRAME != 0 {
                self.frames.push(std::mem::take(&mut self.partial));
            }
        }
    }

    fn ready(&self) -> bool {
        self.outcome == Some(Outcome::Ready)
    }

    fn line(&self) -> String {
        let frames: Vec<String> = self.frames.iter().map(|f| lossy(f)).collect();
        format!(
            "{} wire={:?} frames={frames:?} partial={:?} raw={:?} flags={} framing={}",
            self.last,
            lossy(&self.wire),
            lossy(&self.partial),
            lossy(&self.raw),
            self.flags,
            self.framing != 0
        )
    }
}

/// One framer op, by what it carries.
#[derive(Clone, Copy)]
enum Op<'a> {
    Begin(u32, &'a [u8]),
    Ingest(&'a [u8], bool),
    Emit(&'a [u8], bool),
    Refuse(&'a [u8]),
    Encode(&'a [u8], &'a [Field]),
    Adopt(&'a [u8]),
    Finish,
    Detach,
    Timer,
}

impl Op<'_> {
    fn again(self) -> Self {
        match self {
            Op::Ingest(_, end) => Op::Ingest(&[], end),

            Op::Emit(..) => Op::Emit(&[], false),
            Op::Refuse(_) => Op::Refuse(&[]),
            Op::Adopt(_) | Op::Begin(..) => Op::Timer,
            other => other,
        }
    }
}

fn go<I: InFrame, O: OutFrame>(p: &Plugin<Transport>, s: u32, i: I) -> (Called, O) {
    let mut f = Frame::new(i, output::<O>());
    let c = p.call(s, &mut f);
    (c, f.out)
}

fn cross(p: &Plugin<Transport>, framing: u64, op: Op<'_>, sink: &mut Sink) -> (Called, FramerOut) {
    let raw = sink.raw();
    match op {
        Op::Begin(side, target) => {
            let mut i: BeginIn = input();
            (i.side, i.sink, i.target) = (side, raw, abi_bytes(target));

            i.scheme = busbar_contract::abi::host::service::SCHEME_PLAIN;
            go(p, slot::BEGIN, i)
        }
        Op::Ingest(bytes, end) => {
            let mut i: IngestIn = input();
            (i.framing, i.bytes, i.len, i.end, i.sink) =
                (framing, bytes.as_ptr(), bytes.len(), u32::from(end), raw);
            go(p, slot::INGEST, i)
        }
        Op::Emit(bytes, end) => {
            let mut i: EmitIn = input();
            (i.framing, i.bytes, i.len, i.end_of_frame, i.sink) =
                (framing, bytes.as_ptr(), bytes.len(), u32::from(end), raw);
            go(p, slot::EMIT, i)
        }
        Op::Refuse(bytes) => {
            let mut i: RefuseIn = input();
            (i.framing, i.bytes, i.len, i.sink) = (framing, bytes.as_ptr(), bytes.len(), raw);
            go(p, slot::REFUSE, i)
        }
        Op::Encode(body, fields) => {
            let mut i: EncodeIn = input();
            (i.body, i.body_len, i.sink) = (body.as_ptr(), body.len(), raw);
            (i.fields, i.fields_len) = (fields.as_ptr(), fields.len());
            go(p, slot::ENCODE, i)
        }
        Op::Adopt(leftover) => {
            let mut i: AdoptIn = input();
            (i.side, i.leftover, i.leftover_len, i.sink) =
                (SIDE_ACCEPT, leftover.as_ptr(), leftover.len(), raw);
            go(p, slot::ADOPT, i)
        }
        Op::Finish => {
            let mut i: FinishIn = input();
            (i.framing, i.sink) = (framing, raw);
            go(p, slot::FINISH, i)
        }
        Op::Detach | Op::Timer => {
            let mut i: FramingIn = input();
            (i.framing, i.sink) = (framing, raw);
            let s = if matches!(op, Op::Detach) {
                slot::DETACH
            } else {
                slot::TIMER
            };
            go(p, s, i)
        }
    }
}

fn once(p: &Plugin<Transport>, framing: u64, op: Op<'_>, sink: &mut Sink) -> Yielded {
    let mut y = Yielded::default();
    let (c, o) = cross(p, framing, op, sink);
    y.take(&c, &o, sink);
    y
}

fn pump(p: &Plugin<Transport>, framing: u64, op: Op<'_>, sink: &mut Sink) -> Yielded {
    let mut y = Yielded::default();
    let (c, o) = cross(p, framing, op, sink);
    y.take(&c, &o, sink);
    let framing = if framing == 0 { y.framing } else { framing };
    let mut n = 0;
    while y.ready() && y.flags & YIELD_MORE != 0 {
        n += 1;
        assert!(n < MAX_REDRIVE, "a framer answered YIELD_MORE {n} times");
        let (c, o) = cross(p, framing, op.again(), sink);
        y.take(&c, &o, sink);
    }
    y
}

fn carrier_ops(p: &Plugin<Transport>) -> [Outcome; 8] {
    [
        go::<_, ListenOut>(p, slot::LISTEN, input::<ListenIn>())
            .0
            .outcome,
        go::<_, AcceptOut>(p, slot::ACCEPT, input::<AcceptIn>())
            .0
            .outcome,
        go::<_, ConnOut>(p, slot::DIAL, input::<DialIn>()).0.outcome,
        go::<_, IoOut>(p, slot::READ, input::<ReadIn>()).0.outcome,
        go::<_, IoOut>(p, slot::WRITE, input::<WriteIn>()).0.outcome,
        go::<_, OutHead>(p, slot::FLUSH, input::<ConnIn>())
            .0
            .outcome,
        go::<_, OutHead>(p, slot::SHUT, input::<ShutIn>()).0.outcome,
        go::<_, ArrivalOut>(p, slot::ARRIVAL, input::<ArrivalIn>())
            .0
            .outcome,
    ]
}

type HeadLine = (Vec<u8>, Vec<u8>);

fn located_defaults(p: &Plugin<Transport>, target: &[u8]) -> (String, (Vec<HeadLine>, bool)) {
    let (mut authority, mut name, mut alpn, mut defaults) = (
        vec![0_u8; AMPLE],
        vec![0_u8; AMPLE],
        vec![0_u8; AMPLE],
        vec![0_u8; AMPLE],
    );
    let mut i: LocateIn = input();
    i.target = abi_bytes(target);
    (i.authority_buf, i.authority_cap) = (authority.as_mut_ptr(), authority.len());
    (i.name_buf, i.name_cap) = (name.as_mut_ptr(), name.len());
    (i.alpn_buf, i.alpn_cap) = (alpn.as_mut_ptr(), alpn.len());
    (i.defaults_buf, i.defaults_cap) = (defaults.as_mut_ptr(), defaults.len());
    let mut f: Frame<LocateIn, LocateOut> = Frame::new(i, output());
    let c = p.call(slot::LOCATE, &mut f);
    let written = (f.out.defaults_written as usize).min(defaults.len());
    let lines: Vec<HeadLine> = if c.outcome == Outcome::Ready {
        defaults[..written]
            .split(|b| *b == b'\n')
            .map(|l| l.strip_suffix(b"\r").unwrap_or(l))
            .filter(|l| !l.is_empty())
            .filter_map(|l| {
                let at = l.iter().position(|b| *b == b':')?;
                let value = &l[at + 1..];
                let start = value.iter().position(|b| *b != b' ').unwrap_or(value.len());
                Some((l[..at].to_vec(), value[start..].to_vec()))
            })
            .collect()
    } else {
        Vec::new()
    };
    let states_length = c.outcome == Outcome::Ready && f.out.states_length != 0;
    let line = format!(
        "{:?} defaults={} states_length={states_length}",
        c.outcome,
        lines.len()
    );
    (line, (lines, states_length))
}

fn locate(
    p: &Plugin<Transport>,
    target: &[u8],
    cap: usize,
) -> (
    String,
    Option<(busbar_plugin_loader::dispatch::Recall, u64)>,
) {
    locate_on(p, target, cap, None)
}

fn locate_on(
    p: &Plugin<Transport>,
    target: &[u8],
    cap: usize,
    recall: Option<busbar_plugin_loader::dispatch::Recall>,
) -> (
    String,
    Option<(busbar_plugin_loader::dispatch::Recall, u64)>,
) {
    let (mut authority, mut name, mut alpn) =
        (vec![0_u8; cap], vec![0_u8; AMPLE], vec![0_u8; AMPLE]);
    let mut i: LocateIn = input();
    i.target = abi_bytes(target);
    (i.authority_buf, i.authority_cap) = (authority.as_mut_ptr(), authority.len());
    (i.name_buf, i.name_cap) = (name.as_mut_ptr(), name.len());
    (i.alpn_buf, i.alpn_cap) = (alpn.as_mut_ptr(), alpn.len());

    let mut defaults = vec![0_u8; AMPLE];
    (i.defaults_buf, i.defaults_cap) = (defaults.as_mut_ptr(), defaults.len());
    let mut f: Frame<LocateIn, LocateOut> = Frame::new(i, output());
    let c = match recall {
        Some(token) => p.recall(token, slot::LOCATE, &mut f),
        None => p.call(slot::LOCATE, &mut f),
    };
    let (o, text) = (&f.out, c.error.as_deref().map(lossy));
    let written = (o.authority_written as usize).min(authority.len());
    let authority = if c.outcome == Outcome::Ready {
        lossy(&authority[..written])
    } else {
        String::new()
    };
    let line = format!(
        "{:?} err={:?} authority={authority:?} secure={} has_name={} short={}",
        c.outcome,
        text.unwrap_or_default(),
        o.secure != 0,
        o.has_name != 0,
        c.recall.is_some()
    );
    let needed = o.authority_needed;
    (line, c.recall.map(|r| (r, needed)))
}

fn ready_locate(authority: &[u8], secure: bool, has_name: bool) -> String {
    format!(
        "Ready err=\"\" authority={:?} secure={secure} has_name={has_name} short=false",
        lossy(authority)
    )
}
fn yielded_line(wire: &[u8], frames: &[Vec<u8>], raw: &[u8], flags: u32, framing: bool) -> String {
    let frames: Vec<String> = frames.iter().map(|f| lossy(f)).collect();
    format!(
        "Ready lease=false err=\"\" wire={:?} frames={frames:?} partial=\"\" raw={:?} flags={flags} framing={framing}",
        lossy(wire),
        lossy(raw)
    )
}

fn exercise(p: &Plugin<Transport>, d: &busbar_plugin_loader::dispatch::Dispatcher) -> Vec<String> {
    let mut transcript = Vec::new();
    let inputs: Value = serde_json::from_str(include_str!("conformance.json")).unwrap();
    let k = &inputs["transport"];
    let facts = p
        .context::<busbar_plugin_loader::dispatch::kinds::transport::TransportFacts>()
        .expect("transport tail");
    assert_eq!(facts.role, busbar_contract::abi::transport::ROLE_FRAMER);
    assert!(!facts.datagram);
    transcript.push(format!("facts {facts:?}"));
    let begin = || once(p, 0, Op::Begin(SIDE_DIAL, b""), &mut Sink::ample()).line();
    let before = count(p);
    let answer = begin();
    assert!(answer.starts_with("Refused "));
    transcript.push(format!("begin unopened: {answer}"));
    assert_eq!(count(p) - before, 0);
    let before = count(p);
    let mut i: ValidateIn = input();
    i.settings = Blob::json(b"{}");
    let (c, _): (_, OutHead) = go(p, life::VALIDATE, i);
    assert_eq!(c.outcome, Outcome::Ready);
    transcript.push(format!(
        "lifecycle Ready lease={} err={:?}",
        c.lease != 0,
        c.error
    ));
    assert_eq!(count(p) - before, 1);
    let before = count(p);
    let mut i: OpenIn = input();
    i.settings = Blob::json(b"{}");
    i.generation = 1;
    let (c, _): (_, busbar_contract::abi::mechanism::lifecycle::OpenOut) = go(p, life::OPEN, i);
    assert_eq!(c.outcome, Outcome::Ready);
    transcript.push(format!(
        "lifecycle Ready lease={} err={:?}",
        c.lease != 0,
        c.error
    ));
    assert_eq!(count(p) - before, 1);
    let before = count(p);
    let answer = p.ready(d, std::time::Duration::from_secs(30));
    assert!(answer.is_ok());
    transcript.push(format!("ready has_ready={} {answer:?}", p.has_ready()));
    assert_eq!(count(p) - before, u64::from(p.has_ready()));
    let before = count(p);
    assert_eq!(carrier_ops(p), [Outcome::Refused; 8]);
    assert_eq!(count(p) - before, 8);
    match &k["locate"] {
        Value::String(v) if v == "refused" => {
            {
                let label = "locate";
                let before = count(&p);
                let value = (|| locate(&p, b"conformance", AMPLE).0)();
                assert_eq!(count(&p) - before, 1, "{label} crossings");
                let answer = value;
                assert!(answer.starts_with("Refused "), "{label}: {answer}");
                transcript.push(format!("{label}: {answer}"));
                ()
            };
        }
        l => {
            let reads = l["reads"]
                .as_array()
                .expect("conformance.json: transport.locate.reads must be an array");
            assert!(!reads.is_empty(), "transport.locate.reads is empty");
            for (n, read) in reads.iter().enumerate() {
                let target = text(&read["target"], "locate.reads.target");
                let authority = text(&read["authority"], "locate.reads.authority");
                let secure = read["secure"].as_bool().unwrap_or(false);
                let has_name = read["has_name"].as_bool().unwrap_or(false);
                let want = Expected::Exact(ready_locate(&authority, secure, has_name));
                {
                    let label = &format!("locate #{n}");
                    let want = want;
                    let before = count(&p);
                    let value = (|| locate(&p, &target, AMPLE).0)();
                    assert_eq!(count(&p) - before, 1, "{label} crossings");
                    let answer = value;
                    match want {
                        Expected::Exact(v) => assert_eq!(answer, v, "{label}"),
                        Expected::Prefix(v) => assert!(answer.starts_with(v), "{label}: {answer}"),
                    };
                    transcript.push(format!("{label}: {answer}"));
                    ()
                };
            }
            let target = text(&reads[0]["target"], "locate.reads.target");
            let authority = text(&reads[0]["authority"], "locate.reads.authority");
            let secure = reads[0]["secure"].as_bool().unwrap_or(false);
            let has_name = reads[0]["has_name"].as_bool().unwrap_or(false);
            assert!(
                authority.len() > 1,
                "transport.locate.reads[0].authority must be longer than one byte"
            );
            let want = Expected::Exact(format!(
                "needed={} then {}",
                authority.len(),
                ready_locate(&authority, secure, has_name)
            ));

            {
                let label = "locate short";
                let want = want;
                let before = count(&p);
                let value = (|| {
                    let (first, token) = locate(&p, &target, 1);
                    let Some((token, needed)) = token else {
                        return format!("{first} (no re-call)");
                    };
                    let again = locate_on(&p, &target, needed as usize, Some(token)).0;
                    format!("needed={needed} then {again}")
                })();
                assert_eq!(count(&p) - before, 2, "{label} crossings");
                let answer = value;
                match want {
                    Expected::Exact(v) => assert_eq!(answer, v, "{label}"),
                    Expected::Prefix(v) => assert!(answer.starts_with(v), "{label}: {answer}"),
                };
                transcript.push(format!("{label}: {answer}"));
                ()
            };
            for (n, t) in texts(&l["refuses"], "locate.refuses").iter().enumerate() {
                {
                    let label = &format!("locate refused #{n}");
                    let before = count(&p);
                    let value = (|| locate(&p, t, AMPLE).0)();
                    assert_eq!(count(&p) - before, 1, "{label} crossings");
                    let answer = value;
                    assert!(answer.starts_with("Failed "), "{label}: {answer}");
                    transcript.push(format!("{label}: {answer}"));
                    ()
                };
            }
        }
    }

    let dial = &k["dial"];
    let wire = text(&dial["wire"], "dial.wire");
    let (ingest, frames) = (
        text(&dial["ingest"], "dial.ingest"),
        texts(&dial["frames"], "dial.frames"),
    );
    let target = opt_text(&dial["target"], "dial.target");
    let opening = opt_text(&dial["opening"], "dial.opening");
    let mut tight = Sink::tight();

    let armed = |step: &str| -> u32 {
        let on = match &dial["deadline"] {
            Value::Bool(b) => *b && step == "emit",
            Value::Array(a) => a.iter().any(|v| v.as_str() == Some(step)),
            _ => false,
        };
        if on {
            YIELD_HAS_DEADLINE
        } else {
            0
        }
    };

    let want = begin_dial_want(dial, armed("begin"));
    let pinned = sinkfuls(opening.len(), TIGHT_WIRE);
    let token = {
        let label = "begin dial";
        let want = want;
        let before = count(&p);
        let value = (|| {
            let y = pump(&p, 0, Op::Begin(SIDE_DIAL, &target), &mut tight);
            (y.line(), y.framing)
        })();
        assert_eq!(count(&p) - before, pinned, "{label} crossings");
        let (answer, result) = value;
        match want {
            Expected::Exact(v) => assert_eq!(answer, v, "{label}"),
            Expected::Prefix(v) => assert!(answer.starts_with(v), "{label}: {answer}"),
        };
        transcript.push(format!("{label}: {answer}"));
        result
    };

    if !dial["answer"].is_null() {
        let answer = text(&dial["answer"], "dial.answer");
        let heard = if dial["answer_frames"].is_null() {
            Vec::new()
        } else {
            texts(&dial["answer_frames"], "dial.answer_frames")
        };
        let want = Expected::Exact(yielded_line(&[], &heard, &[], 0, false));
        {
            let label = "dial answer";
            let want = want;
            let before = count(&p);
            let value = (|| pump(&p, token, Op::Ingest(&answer, false), &mut tight).line())();
            assert_eq!(
                count(&p) - before,
                frame_sinkfuls(&heard),
                "{label} crossings"
            );
            let answer = value;
            match want {
                Expected::Exact(v) => assert_eq!(answer, v, "{label}"),
                Expected::Prefix(v) => assert!(answer.starts_with(v), "{label}: {answer}"),
            };
            transcript.push(format!("{label}: {answer}"));
            ()
        };
    }

    let emit = if dial["request"].is_null() {
        text(&dial["emit"], "dial.emit")
    } else {
        let request = &dial["request"];
        let body = opt_text(&request["body"], "dial.request.body");
        let mut named: Vec<HeadLine> = request["fields"]
            .as_array()
            .map(|fs| {
                fs.iter()
                    .map(|f| {
                        (
                            text(&f[0], "dial.request.fields name"),
                            text(&f[1], "dial.request.fields value"),
                        )
                    })
                    .collect()
            })
            .unwrap_or_default();
        let (defaults, states_length) = {
            let label = "dial defaults";
            let before = count(&p);
            let value = (|| located_defaults(&p, &target))();
            assert_eq!(count(&p) - before, 1, "{label} crossings");
            let (answer, result) = value;
            transcript.push(format!("{label}: {answer}"));
            result
        };
        for (name, value) in defaults {
            if !named.iter().any(|(n, _)| n.eq_ignore_ascii_case(&name)) {
                named.push((name, value));
            }
        }

        if states_length
            && !body.is_empty()
            && !named
                .iter()
                .any(|(n, _)| n.eq_ignore_ascii_case(b"content-length"))
        {
            named.push((
                b"content-length".to_vec(),
                body.len().to_string().into_bytes(),
            ));
        }
        let fields: Vec<Field> = named
            .iter()
            .map(|(n, v)| Field {
                name: abi_bytes(n),
                value: abi_bytes(v),
            })
            .collect();
        {
            let label = "dial encode";
            let before = count(&p);
            let value = (|| {
                let y = once(&p, 0, Op::Encode(&body, &fields), &mut Sink::ample());
                (y.line(), y.wire)
            })();
            assert_eq!(count(&p) - before, 1, "{label} crossings");
            let (answer, result) = value;
            transcript.push(format!("{label}: {answer}"));
            result
        }
    };
    let want = Expected::Exact(yielded_line(&wire, &[], &[], armed("emit"), false));
    {
        let label = "emit";
        let want = want;
        let before = count(&p);
        let value = (|| pump(&p, token, Op::Emit(&emit, true), &mut tight).line())();
        assert_eq!(
            count(&p) - before,
            sinkfuls(wire.len(), TIGHT_WIRE),
            "{label} crossings"
        );
        let answer = value;
        match want {
            Expected::Exact(v) => assert_eq!(answer, v, "{label}"),
            Expected::Prefix(v) => assert!(answer.starts_with(v), "{label}: {answer}"),
        };
        transcript.push(format!("{label}: {answer}"));
        ()
    };

    let answered = opt_text(&dial["ingest_wire"], "dial.ingest_wire");
    let ingest_calls = sinkfuls(answered.len(), TIGHT_WIRE).max(frame_sinkfuls(&frames));

    let ends = !dial["ingest_wire"].is_null() && dial["ingest_ends"].as_bool().unwrap_or(true);
    let ingest_flags = armed("ingest") | if ends { YIELD_ENDED } else { 0 };
    let want = Expected::Exact(yielded_line(&answered, &frames, &[], ingest_flags, false));
    {
        let label = "ingest";
        let want = want;
        let before = count(&p);
        let value = (|| pump(&p, token, Op::Ingest(&ingest, false), &mut tight).line())();
        assert_eq!(count(&p) - before, ingest_calls, "{label} crossings");
        let answer = value;
        match want {
            Expected::Exact(v) => assert_eq!(answer, v, "{label}"),
            Expected::Prefix(v) => assert!(answer.starts_with(v), "{label}: {answer}"),
        };
        transcript.push(format!("{label}: {answer}"));
        ()
    };
    let want = Expected::Exact(yielded_line(&[], &[], &[], YIELD_ENDED, false));
    {
        let label = "ingest end";
        let want = want;
        let before = count(&p);
        let value = (|| pump(&p, token, Op::Ingest(&[], true), &mut tight).line())();
        assert_eq!(count(&p) - before, 1, "{label} crossings");
        let answer = value;
        match want {
            Expected::Exact(v) => assert_eq!(answer, v, "{label}"),
            Expected::Prefix(v) => assert!(answer.starts_with(v), "{label}: {answer}"),
        };
        transcript.push(format!("{label}: {answer}"));
        ()
    };
    let finish = opt_text(&dial["finish"], "dial.finish");
    let want = Expected::Exact(yielded_line(&finish, &[], &[], YIELD_ENDED, false));
    {
        let label = "finish";
        let want = want;
        let before = count(&p);
        let value = (|| pump(&p, token, Op::Finish, &mut tight).line())();
        assert_eq!(
            count(&p) - before,
            sinkfuls(finish.len(), TIGHT_WIRE),
            "{label} crossings"
        );
        let answer = value;
        match want {
            Expected::Exact(v) => assert_eq!(answer, v, "{label}"),
            Expected::Prefix(v) => assert!(answer.starts_with(v), "{label}: {answer}"),
        };
        transcript.push(format!("{label}: {answer}"));
        ()
    };
    {
        let label = "finish again";
        let before = count(&p);
        let value = (|| once(&p, token, Op::Finish, &mut tight).line())();
        assert_eq!(count(&p) - before, 1, "{label} crossings");
        let answer = value;
        assert!(answer.starts_with("Failed "), "{label}: {answer}");
        transcript.push(format!("{label}: {answer}"));
        ()
    };

    let cases = k["encode"]
        .as_array()
        .expect("conformance.json: transport.encode must be an array");
    for (n, case) in cases.iter().enumerate() {
        let body = text(&case["body"], "encode.body");
        let named: Vec<(Vec<u8>, Vec<u8>)> = case["fields"]
            .as_array()
            .map(|fs| {
                fs.iter()
                    .map(|f| {
                        (
                            text(&f[0], "encode.fields name"),
                            text(&f[1], "encode.fields value"),
                        )
                    })
                    .collect()
            })
            .unwrap_or_default();
        let fields: Vec<Field> = named
            .iter()
            .map(|(n, v)| Field {
                name: abi_bytes(n),
                value: abi_bytes(v),
            })
            .collect();
        let want = match &case["wire"] {
            Value::Null => Expected::Prefix("Failed "),
            v => Expected::Exact(yielded_line(&text(v, "encode.wire"), &[], &[], 0, false)),
        };
        {
            let label = &format!("encode #{n}");
            let want = want;
            let before = count(&p);
            let value = (|| once(&p, 0, Op::Encode(&body, &fields), &mut Sink::ample()).line())();
            assert_eq!(count(&p) - before, 1, "{label} crossings");
            let answer = value;
            match want {
                Expected::Exact(v) => assert_eq!(answer, v, "{label}"),
                Expected::Prefix(v) => assert!(answer.starts_with(v), "{label}: {answer}"),
            };
            transcript.push(format!("{label}: {answer}"));
            ()
        };
    }

    if refused(&k["refuse"]) {
        unreachable!("both real products accept connections");
    } else {
        let refuse = &k["refuse"];
        let (bytes, wire) = (
            text(&refuse["bytes"], "refuse.bytes"),
            text(&refuse["wire"], "refuse.wire"),
        );

        let accept_opening = opt_text(&refuse["begin"], "refuse.begin");
        let want = Expected::Exact(yielded_line(&accept_opening, &[], &[], 0, true));
        let pinned = sinkfuls(accept_opening.len(), TIGHT_WIRE);
        let token = {
            let label = "begin accept";
            let want = want;
            let before = count(&p);
            let value = (|| {
                let y = pump(&p, 0, Op::Begin(SIDE_ACCEPT, b""), &mut tight);
                (y.line(), y.framing)
            })();
            assert_eq!(count(&p) - before, pinned, "{label} crossings");
            let (answer, result) = value;
            match want {
                Expected::Exact(v) => assert_eq!(answer, v, "{label}"),
                Expected::Prefix(v) => assert!(answer.starts_with(v), "{label}: {answer}"),
            };
            transcript.push(format!("{label}: {answer}"));
            result
        };

        if !refuse["opening"].is_null() {
            let opening = text(&refuse["opening"], "refuse.opening");
            let answer = opt_text(&refuse["answer"], "refuse.answer");
            let want = Expected::Exact(yielded_line(&answer, &[], &[], 0, false));
            {
                let label = "accept opening";
                let want = want;
                let before = count(&p);
                let value = (|| pump(&p, token, Op::Ingest(&opening, false), &mut tight).line())();
                assert_eq!(
                    count(&p) - before,
                    sinkfuls(answer.len(), TIGHT_WIRE),
                    "{label} crossings"
                );
                let answer = value;
                match want {
                    Expected::Exact(v) => assert_eq!(answer, v, "{label}"),
                    Expected::Prefix(v) => assert!(answer.starts_with(v), "{label}: {answer}"),
                };
                transcript.push(format!("{label}: {answer}"));
                ()
            };
        }

        let refuses_none = refuse["refused"].as_bool().unwrap_or(false);
        let ends = refuse["ends"].as_bool().unwrap_or(false);
        let ended = if ends { YIELD_ENDED } else { 0 };
        let want = if refuses_none {
            Expected::Prefix("Refused ")
        } else {
            Expected::Exact(yielded_line(&wire, &[], &[], ended, false))
        };
        {
            let label = "refuse";
            let want = want;
            let before = count(&p);
            let value = (|| pump(&p, token, Op::Refuse(&bytes), &mut tight).line())();
            assert_eq!(
                count(&p) - before,
                sinkfuls(wire.len(), TIGHT_WIRE),
                "{label} crossings"
            );
            let answer = value;
            match want {
                Expected::Exact(v) => assert_eq!(answer, v, "{label}"),
                Expected::Prefix(v) => assert!(answer.starts_with(v), "{label}: {answer}"),
            };
            transcript.push(format!("{label}: {answer}"));
            ()
        };
        let want = if ends {
            Expected::Prefix("Failed ")
        } else {
            Expected::Exact(yielded_line(&[], &[], &[], 0, false))
        };
        {
            let label = "timer";
            let want = want;
            let before = count(&p);
            let value = (|| pump(&p, token, Op::Timer, &mut tight).line())();
            assert_eq!(count(&p) - before, 1, "{label} crossings");
            let answer = value;
            match want {
                Expected::Exact(v) => assert_eq!(answer, v, "{label}"),
                Expected::Prefix(v) => assert!(answer.starts_with(v), "{label}: {answer}"),
            };
            transcript.push(format!("{label}: {answer}"));
            ()
        };
        {
            let label = "finish refused";
            let before = count(&p);
            let value = (|| once(&p, token, Op::Finish, &mut tight).line())();
            assert_eq!(count(&p) - before, 1, "{label} crossings");
            let answer = value;
            assert!(answer.starts_with("Ready "), "{label}: {answer}");
            transcript.push(format!("{label}: {answer}"));
            ()
        };

        let token = {
            let label = "begin upgrade";
            let before = count(&p);
            let value = (|| {
                let y = once(&p, 0, Op::Begin(SIDE_ACCEPT, b""), &mut tight);
                (y.line(), y.framing)
            })();
            assert_eq!(count(&p) - before, 1, "{label} crossings");
            let (answer, result) = value;
            assert!(answer.starts_with("Ready "), "{label}: {answer}");
            transcript.push(format!("{label}: {answer}"));
            result
        };
        upgrade(&mut transcript, &p, k, token);
    }
    {
        let label = "ingest on no framing";
        let before = count(&p);
        let value = (|| once(&p, u64::MAX, Op::Ingest(b"x", false), &mut tight).line())();
        assert_eq!(count(&p) - before, 1, "{label} crossings");
        let answer = value;
        assert!(answer.starts_with("Failed "), "{label}: {answer}");
        transcript.push(format!("{label}: {answer}"));
        ()
    };

    let before = count(p);
    let mut i: TickIn = input();
    i.now_ns = 1;
    let (c, o): (_, TickOut) = go(p, life::TICK, i);
    transcript.push(format!(
        "tick {:?} lease={} err={:?} next={}",
        c.outcome,
        c.lease != 0,
        c.error,
        o.next_tick_ns
    ));
    assert_eq!(count(p) - before, 1);
    let before = count(p);
    let mut i: RefreshIn = input();
    i.settings = Blob::json(b"{}");
    i.generation = 2;
    let (c, _): (_, OutHead) = go(p, life::REFRESH, i);
    assert_eq!(c.outcome, Outcome::Ready);
    transcript.push(format!(
        "lifecycle Ready lease={} err={:?}",
        c.lease != 0,
        c.error
    ));
    assert_eq!(count(p) - before, 1);
    let before = count(p);
    let (c, _): (_, OutHead) = go(p, life::CLOSE, input::<InHead>());
    assert_eq!(c.outcome, Outcome::Ready);
    transcript.push(format!(
        "lifecycle Ready lease={} err={:?}",
        c.lease != 0,
        c.error
    ));
    assert_eq!(count(p) - before, 1);
    let before = count(p);
    let answer = begin();
    assert!(answer.starts_with("Fault "));
    transcript.push(format!("begin after close: {answer}"));
    assert_eq!(count(p) - before, 0);
    transcript
}

#[test]
fn the_linked_and_the_dropped_in_door_are_one_plugin() {
    let d = busbar_plugin_loader::dispatch::Dispatcher::new(Default::default());
    let path = super::cdylib();
    let (dropped_address, dropped_ops) =
        busbar_plugin_loader::dispatch::load::door_addresses_of_library(&path)
            .expect("actual library reads")
            .expect("actual door export");
    assert_eq!(
        busbar_plugin_loader::dispatch::load::rendering_of_library(&path)
            .expect("actual Statement reads")
            .expect("actual door export"),
        super::row().statement,
        "actual images state the same Statement"
    );
    let linked_address = (super::row().door)();
    assert!(!linked_address.is_null());
    // SAFETY: the validated actual product door is immutable and static.
    let linked_ops =
        unsafe { busbar_contract::abi::mechanism::door::Door::read_parts(linked_address) }.ops
            as usize;
    assert_ne!(
        dropped_address, linked_address as usize,
        "independent loaded image"
    );
    assert_ne!(dropped_ops, linked_ops, "independent operation table");
    let linked: Plugin<Transport> =
        load_linked(&super::row(), super::bind(&d)).expect("linked product");
    let dropped: Plugin<Transport> =
        load_dropped(&super::cdylib(), &super::row().statement, super::bind(&d))
            .expect("real dropped product");
    assert_eq!(linked.name(), dropped.name());
    let linked_transcript = exercise(&linked, &d);
    let dropped_transcript = exercise(&dropped, &d);
    assert_eq!(linked_transcript, dropped_transcript);
    let mut changed = dropped_transcript.clone();
    changed[1].push('!');
    assert_ne!(
        linked_transcript, changed,
        "a changed product answer fails parity"
    );
}
#[test]
fn the_suite_runs_in_the_profile_it_was_asked_to() {
    assert!(
        !(cfg!(debug_assertions) && std::env::var_os("BUSBAR_EXPECT_RELEASE").is_some()),
        "run with --release"
    );
}
fn upgrade(transcript: &mut Vec<String>, p: &Plugin<Transport>, k: &Value, token: u64) {
    let mut tight = Sink::tight();
    let whole = &k["handoff"];
    let refused_ = || once(p, 0, Op::Adopt(b"conformance"), &mut Sink::tight()).line();
    if refused(whole) {
        {
            let label = "detach";
            let before = count(&p);
            let value = (|| once(p, token, Op::Detach, &mut tight).line())();
            assert_eq!(count(&p) - before, 1, "{label} crossings");
            let answer = value;
            assert!(answer.starts_with("Refused "), "{label}: {answer}");
            transcript.push(format!("{label}: {answer}"));
            ()
        };
        {
            let label = "adopt";
            let before = count(&p);
            let value = (refused_)();
            assert_eq!(count(&p) - before, 1, "{label} crossings");
            let answer = value;
            assert!(answer.starts_with("Refused "), "{label}: {answer}");
            transcript.push(format!("{label}: {answer}"));
            ()
        };
        {
            let label = "finish upgrade";
            let before = count(&p);
            let value = (|| once(p, token, Op::Finish, &mut tight).line())();
            assert_eq!(count(&p) - before, 1, "{label} crossings");
            let answer = value;
            assert!(answer.starts_with("Ready "), "{label}: {answer}");
            transcript.push(format!("{label}: {answer}"));
            ()
        };
        return;
    }

    let (detach, of, adopt, adopt_of, leftover) = if whole.is_null() {
        (&k["detach"], "detach", &k["adopt"], "adopt", "leftover")
    } else {
        (whole, "handoff", whole, "handoff", "adopt")
    };
    if refused(detach) {
        {
            let label = "detach";
            let before = count(&p);
            let value = (|| once(p, token, Op::Detach, &mut tight).line())();
            assert_eq!(count(&p) - before, 1, "{label} crossings");
            let answer = value;
            assert!(answer.starts_with("Refused "), "{label}: {answer}");
            transcript.push(format!("{label}: {answer}"));
            ()
        };
    } else {
        let ingest = text(&detach["ingest"], &format!("{of}.ingest"));
        let detached = text(&detach["detached"], &format!("{of}.detached"));

        {
            let label = "ingest before upgrade";
            let before = count(&p);
            let value = (|| once(p, token, Op::Ingest(&ingest, false), &mut tight).line())();
            assert_eq!(count(&p) - before, 1, "{label} crossings");
            let answer = value;
            assert!(answer.starts_with("Ready "), "{label}: {answer}");
            transcript.push(format!("{label}: {answer}"));
            ()
        };
        let want = Expected::Exact(yielded_line(&[], &[], &detached, YIELD_ENDED, false));
        {
            let label = "detach";
            let want = want;
            let before = count(&p);
            let value = (|| pump(p, token, Op::Detach, &mut tight).line())();
            assert_eq!(
                count(&p) - before,
                sinkfuls(detached.len(), TIGHT_FRAME),
                "{label} crossings"
            );
            let answer = value;
            match want {
                Expected::Exact(v) => assert_eq!(answer, v, "{label}"),
                Expected::Prefix(v) => assert!(answer.starts_with(v), "{label}: {answer}"),
            };
            transcript.push(format!("{label}: {answer}"));
            ()
        };
    }

    if whole.is_null() {
        {
            let label = "finish upgrade";
            let before = count(&p);
            let value = (|| once(p, token, Op::Finish, &mut tight).line())();
            assert_eq!(count(&p) - before, 1, "{label} crossings");
            let answer = value;
            assert!(answer.starts_with("Ready "), "{label}: {answer}");
            transcript.push(format!("{label}: {answer}"));
            ()
        };
    }
    if refused(adopt) {
        {
            let label = "adopt";
            let before = count(&p);
            let value = (refused_)();
            assert_eq!(count(&p) - before, 1, "{label} crossings");
            let answer = value;
            assert!(answer.starts_with("Refused "), "{label}: {answer}");
            transcript.push(format!("{label}: {answer}"));
            ()
        };
        return;
    }
    let left = text(&adopt[leftover], &format!("{adopt_of}.{leftover}"));
    let frames = texts(&adopt["frames"], &format!("{adopt_of}.frames"));

    let wire = if whole.is_null() {
        opt_text(&adopt["wire"], "adopt.wire")
    } else {
        Vec::new()
    };
    let crossings = sinkfuls(wire.len(), TIGHT_WIRE).max(frame_sinkfuls(&frames));
    let want = Expected::Exact(yielded_line(&wire, &frames, &[], 0, true));
    let adopted = {
        let label = "adopt";
        let want = want;
        let before = count(&p);
        let value = (|| {
            let y = pump(p, 0, Op::Adopt(&left), &mut tight);
            (y.line(), y.framing)
        })();
        assert_eq!(count(&p) - before, crossings, "{label} crossings");
        let (answer, result) = value;
        match want {
            Expected::Exact(v) => assert_eq!(answer, v, "{label}"),
            Expected::Prefix(v) => assert!(answer.starts_with(v), "{label}: {answer}"),
        };
        transcript.push(format!("{label}: {answer}"));
        result
    };
    {
        let label = "finish adopted";
        let before = count(&p);
        let value = (|| once(p, adopted, Op::Finish, &mut tight).line())();
        assert_eq!(count(&p) - before, 1, "{label} crossings");
        let answer = value;
        assert!(answer.starts_with("Ready "), "{label}: {answer}");
        transcript.push(format!("{label}: {answer}"));
        ()
    };
}

fn refused(v: &Value) -> bool {
    v.as_str() == Some("refused")
}
fn begin_dial_want(dial: &Value, flags: u32) -> Expected {
    Expected::Exact(yielded_line(
        &opt_text(&dial["opening"], "dial.opening"),
        &[],
        &[],
        flags,
        true,
    ))
}
