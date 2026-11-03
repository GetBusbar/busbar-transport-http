// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Terminal handoff retires the actual door token, after every caller-owned byte is drained.

use super::*;
use busbar_contract::abi::mechanism::lifecycle::{slot as life_slot, OpenIn, OpenOut};
use busbar_contract::abi::sdk::door::{blank_in, blank_out, Entry};
use busbar_contract::abi::transport::slot;
use std::ffi::c_void;

const REQUEST: &[u8] = b"GET /ws HTTP/1.1\r\nhost: busbar.test\r\nconnection: upgrade\r\nupgrade: websocket\r\nauthorization: Bearer detach-custody-canary\r\n\r\n\x81\x02hi";

// This test-only helper crosses the real SDK entry rather than bypassing the slot adapter.
#[allow(unsafe_code)]
fn call<S: SafeSlot>(p: *mut c_void, index: u32, i: &S::In, o: &mut S::Out) -> Outcome {
    // SAFETY: p is null for Open or is the matching State instance minted by that SDK Open,
    // remains live until the serialized Close call, and is never used after Close. Inputs and
    // outputs are fully initialized with the SDK's AbiIn/AbiOut blank constructors. Nonempty
    // sink pointers name distinct caller-owned mutable slices, disjoint from i and o, alive
    // throughout this synchronous call; all other pointer/length pairs are null/zero. The test
    // serializes every call, lends i immutably and o exclusively, and retains no borrowed input.
    unsafe { <Safe<S> as Entry>::enter(p, index, i, o) }
}

struct Seed;
impl SafeSlot for Seed {
    type In = FramingIn;
    type Out = FramerOut;
    type State = State;
    fn call(
        p: sdk::Instance<'_, State>,
        i: Lent<'_, FramingIn>,
        mut o: Out<'_, FramerOut>,
    ) -> Outcome {
        let instance = p.get().unwrap().life();
        let mut accepted = Accepted::accept(1, vec![guest::Line::any(1)]);
        accepted.ingest(
            if i.framing == 0 {
                REQUEST
            } else {
                b"PRI * HTTP/2.0\r\n"
            },
            false,
        );
        accepted.drive(1);
        let token = instance
            .framings
            .insert_with(|| Held::Accept(Box::new(accepted)))
            .unwrap();
        o.set(|out| &out.framing, token);
        Outcome::Ready
    }
}

struct Probe;
impl SafeSlot for Probe {
    type In = FramingIn;
    type Out = FramerOut;
    type State = State;
    fn call(p: sdk::Instance<'_, State>, i: Lent<'_, FramingIn>, _: Out<'_, FramerOut>) -> Outcome {
        if p.get().unwrap().life().framings.reach(i.framing).is_ok() {
            Outcome::Ready
        } else {
            Outcome::Refused
        }
    }
}

struct Door(*mut c_void);
impl Door {
    fn open() -> Self {
        let i: OpenIn = blank_in();
        let mut o: OpenOut = blank_out();
        assert_eq!(
            call::<life::Open<Instance>>(std::ptr::null_mut(), life_slot::OPEN, &i, &mut o),
            Outcome::Ready
        );
        assert!(!o.instance.is_null());
        Self(o.instance)
    }
    fn seed(&self, partial_h2: bool) -> u64 {
        let mut i: FramingIn = blank_in();
        i.framing = u64::from(partial_h2);
        let mut o: FramerOut = blank_out();
        assert_eq!(
            call::<Seed>(self.0, slot::TIMER, &i, &mut o),
            Outcome::Ready
        );
        o.framing
    }
    fn reachable(&self, token: u64) -> bool {
        let mut i: FramingIn = blank_in();
        i.framing = token;
        let mut o: FramerOut = blank_out();
        call::<Probe>(self.0, slot::TIMER, &i, &mut o) == Outcome::Ready
    }
    fn detach(&self, token: u64, wire: &mut [u8], frame: &mut [u8]) -> (Outcome, FramerOut) {
        let mut i: FramingIn = blank_in();
        i.framing = token;
        i.sink.wire = wire.as_mut_ptr();
        i.sink.wire_cap = wire.len();
        i.sink.frame = frame.as_mut_ptr();
        i.sink.frame_cap = frame.len();
        i.sink.now_monotonic_ns = 1;
        let mut o: FramerOut = blank_out();
        let outcome = call::<Detach>(self.0, slot::DETACH, &i, &mut o);
        (outcome, o)
    }
}
impl Drop for Door {
    fn drop(&mut self) {
        let i: InHead = blank_in();
        let mut o: OutHead = blank_out();
        assert_eq!(
            call::<life::Close<Instance>>(self.0, life_slot::CLOSE, &i, &mut o),
            Outcome::Ready
        );
    }
}

#[test]
fn partial_detach_retains_the_token_until_caller_owned_bytes_are_fully_drained() {
    let door = Door::open();
    let token = door.seed(false);
    let mut received = Vec::new();
    for _ in 0..REQUEST.len() {
        let mut frame = [0; 3];
        let mut wire = [0; 3];
        let (outcome, out) = door.detach(token, &mut wire, &mut frame);
        assert_eq!(outcome, Outcome::Ready);
        assert_eq!(
            out.yielded.wire_len, 0,
            "the unanswered upgrade has no response"
        );
        received.extend_from_slice(&frame[..out.yielded.frame_len as usize]);
        if out.yielded.flags & YIELD_MORE != 0 {
            assert!(
                door.reachable(token),
                "MORE keeps the remaining custody live"
            );
        } else {
            assert_eq!(out.yielded.flags, YIELD_ENDED);
            assert!(
                !door.reachable(token),
                "ENDED retires the old framing without Finish"
            );
            assert_eq!(
                received, REQUEST,
                "retirement cannot wipe the caller's transferred bytes"
            );
            let next = door.seed(false);
            assert_ne!(next, token);
            assert_eq!(next as u32, token as u32, "the retired slot is reusable");
            assert!(
                !door.reachable(token),
                "reuse cannot revive the old generation"
            );
            assert!(door.reachable(next));
            return;
        }
    }
    panic!("bounded three-byte drains must finish");
}

#[test]
fn a_refused_detach_keeps_the_original_framing_available() {
    let door = Door::open();
    let token = door.seed(true);
    let (outcome, _) = door.detach(token, &mut [0; 8], &mut [0; 8]);
    assert_eq!(outcome, Outcome::Refused);
    assert!(
        door.reachable(token),
        "a partial HTTP/2 preface was not handed off"
    );
}
