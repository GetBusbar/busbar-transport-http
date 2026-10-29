// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE FRAMINGS AN INSTANCE HOLDS, by token, with no lock shared between them.
//!
//! THE DESIGN Appendix A.8 sets "zero contended atomics per chunk" and request-path ops that
//! "return READY or PENDING in bounded CPU"; A.4.2 says conn ops "never block". So the per-chunk
//! ops (`ingest`, `emit`, `timer`) reach a framing through its token alone: the token names a
//! slot, the slot's segment is found with one read of a set-once cell, and the slot's own lock is
//! the only one taken. Each slot sits on its own cache lines, so two framings never share one. The
//! host calls one op at a time on a connection's framing, so that lock is never contended; should
//! it ever be held, the op is answered at once ([`Reach::Busy`]), never waited for.
//!
//! Only `begin` and `finish` (once per connection, never per chunk) take the free list's lock, to
//! mint a slot and to give one back. Segments are allocated on first use and grow geometrically, so
//! an instance that frames a handful of connections holds a handful of slots. A token carries its
//! slot's generation: one that outlived its framing never reaches the framing that reused the slot.

use std::sync::{Mutex, MutexGuard, OnceLock, TryLockError};

use super::accept::Accepted;
use super::engine::Framing;

/// The first segment's slots; segment `k` holds `BASE << k`.
const BASE: usize = 64;
/// Segments: `BASE * (2^SEGMENTS - 1)` framings at most (about four million).
const SEGMENTS: usize = 16;

/// One framing the instance holds: a dialled connection's client, or an accepted connection's
/// server.
pub(super) enum Held {
    /// A dialled connection (`SIDE_DIAL`).
    Dial(Framing),
    /// An accepted connection (`SIDE_ACCEPT`).
    Accept(Accepted),
}

/// A slot's state: the generation of the token that last named it, and the framing it holds.
#[derive(Default)]
pub(super) struct SlotState {
    generation: u32,
    held: Option<Box<Held>>,
}

impl SlotState {
    /// The framing held here (a reached slot always holds one).
    pub(super) fn held(&mut self) -> &mut Held {
        self.held
            .as_mut()
            .expect("a reached slot holds its framing")
    }
}

/// One slot, alone on its cache lines.
#[derive(Default)]
#[repr(align(128))]
struct Slot(Mutex<SlotState>);

/// Slots minted and given back.
#[derive(Default)]
struct Free {
    idle: Vec<u32>,
    next: u32,
}

/// Why a token reached no framing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Reach {
    /// No framing holds this token (never minted, finished, or outlived by a newer one).
    Gone,
    /// Another op holds the framing right now: answered at once, never waited for.
    Busy,
}

impl Reach {
    /// The text the op answers with.
    pub(super) fn why(self) -> &'static str {
        match self {
            Self::Gone => "no such framing",
            Self::Busy => "framing busy: another op holds it",
        }
    }
}

/// The framings an instance holds.
pub(super) struct Framings {
    segments: [OnceLock<Box<[Slot]>>; SEGMENTS],
    free: Mutex<Free>,
}

impl Default for Framings {
    fn default() -> Self {
        Self {
            segments: std::array::from_fn(|_| OnceLock::new()),
            free: Mutex::new(Free::default()),
        }
    }
}

/// Which segment holds slot `index`, and where in it.
fn place(index: usize) -> (usize, usize) {
    let k = (usize::BITS - 1 - (index / BASE + 1).leading_zeros()) as usize;
    (k, index - BASE * ((1 << k) - 1))
}

fn token(index: u32, generation: u32) -> u64 {
    (u64::from(generation) << 32) | (u64::from(index) + 1)
}

fn untoken(token: u64) -> Option<(u32, u32)> {
    let index = u32::try_from(token & u64::from(u32::MAX))
        .ok()?
        .checked_sub(1)?;
    Some((index, (token >> 32) as u32))
}

impl Framings {
    /// Hold the dialled `framing`, answering its token, or `None` when every slot is in use.
    #[cfg(test)]
    pub(super) fn insert(&self, framing: Framing) -> Option<u64> {
        self.insert_held(Held::Dial(framing))
    }

    /// Hold `held`, answering its token, or `None` when every slot is in use.
    pub(super) fn insert_held(&self, held: Held) -> Option<u64> {
        let index = {
            let mut free = self
                .free
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            match free.idle.pop() {
                Some(i) => i,
                None => {
                    if free.next as usize >= BASE * ((1 << SEGMENTS) - 1) {
                        return None;
                    }
                    free.next += 1;
                    free.next - 1
                }
            }
        };
        let (k, at) = place(index as usize);
        let segment =
            self.segments[k].get_or_init(|| (0..BASE << k).map(|_| Slot::default()).collect());
        // A free slot is held by nobody, save an op still holding a token it outlived, which
        // finds the generation moved on and lets go.
        let mut slot = segment[at]
            .0
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        slot.generation = slot.generation.wrapping_add(1);
        slot.held = Some(Box::new(held));
        Some(token(index, slot.generation))
    }

    /// The framing `token` names, held for one op.
    ///
    /// # Errors
    ///
    /// [`Reach::Gone`]: no framing holds the token; [`Reach::Busy`]: another op holds it.
    pub(super) fn reach(&self, token: u64) -> Result<MutexGuard<'_, SlotState>, Reach> {
        let (index, generation) = untoken(token).ok_or(Reach::Gone)?;
        let (k, at) = place(index as usize);
        let slot = self
            .segments
            .get(k)
            .and_then(OnceLock::get)
            .and_then(|s| s.get(at))
            .ok_or(Reach::Gone)?;
        let state = match slot.0.try_lock() {
            Ok(s) => s,
            Err(TryLockError::WouldBlock) => return Err(Reach::Busy),
            // An op that panicked left this framing mid-step: it is not reached again.
            Err(TryLockError::Poisoned(_)) => return Err(Reach::Gone),
        };
        if state.generation != generation || state.held.is_none() {
            return Err(Reach::Gone);
        }
        Ok(state)
    }

    /// Visit every framing no op holds right now, `f` on each. Never waits: a framing another op
    /// holds is skipped, as that op is running, not parked. Once per call over every minted slot,
    /// for the rare op that names no framing (`cancel` names only a ticket).
    pub(super) fn each(&self, mut f: impl FnMut(&mut Held)) {
        for segment in self.segments.iter().filter_map(OnceLock::get) {
            for slot in segment.iter() {
                if let Ok(mut state) = slot.0.try_lock() {
                    if let Some(held) = state.held.as_mut() {
                        f(held);
                    }
                }
            }
        }
    }

    /// Drop the framing `token` names and give its slot back.
    ///
    /// # Errors
    ///
    /// As [`Self::reach`].
    pub(super) fn remove(&self, token: u64) -> Result<(), Reach> {
        let mut state = self.reach(token)?;
        state.held = None;
        drop(state);
        if let Some((index, _)) = untoken(token) {
            self.free
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .idle
                .push(index);
        }
        Ok(())
    }
}

#[cfg(test)]
#[path = "tests/framings_tests.rs"]
mod tests;
