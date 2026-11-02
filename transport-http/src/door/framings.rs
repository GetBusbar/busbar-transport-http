// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE FRAMINGS AN INSTANCE HOLDS, by token, with no lock shared between them.

use std::sync::{Mutex, MutexGuard, OnceLock, TryLockError};

use super::accept::Accepted;
use super::engine::Framing;

/// The first segment's slots; segment `k` holds `BASE << k`.
const BASE: usize = 64;
/// Segments: `BASE * (2^SEGMENTS - 1)` framings at most (about four million).
const SEGMENTS: usize = 16;

/// One framing the instance holds: a dialled connection's client, or an accepted connection's
pub(super) enum Held {
    /// A dialled connection (`SIDE_DIAL`).
    Dial(Box<Framing>),
    /// An accepted connection (`SIDE_ACCEPT`).
    Accept(Box<Accepted>),
}

/// A slot's state: the generation of the token that last named it, and the framing it holds.
#[derive(Default)]
pub(super) struct SlotState {
    generation: u32,
    held: Option<Held>,
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
        self.insert_with(|| Held::Dial(Box::new(framing)))
    }

    /// Construct the owned framing only after its slot and generation are reserved.
    pub(super) fn insert_with(&self, make: impl FnOnce() -> Held) -> Option<u64> {
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

        let mut slot = segment[at]
            .0
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        slot.generation = slot.generation.checked_add(1)?;
        slot.held = Some(make());
        Some(token(index, slot.generation))
    }

    /// The framing `token` names, held for one op.
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

            Err(TryLockError::Poisoned(_)) => return Err(Reach::Gone),
        };
        if state.generation != generation || state.held.is_none() {
            return Err(Reach::Gone);
        }
        Ok(state)
    }

    /// Visit every framing no op holds right now, `f` on each. Never waits (the op holding a
    pub(super) fn each(&self, mut f: impl FnMut(&mut Held)) -> bool {
        let mut skipped = false;
        for segment in self.segments.iter().filter_map(OnceLock::get) {
            for slot in segment.iter() {
                match slot.0.try_lock() {
                    Ok(mut state) => {
                        if let Some(held) = state.held.as_mut() {
                            f(held);
                        }
                    }
                    Err(TryLockError::WouldBlock) => skipped = true,

                    Err(TryLockError::Poisoned(_)) => {}
                }
            }
        }
        skipped
    }

    /// Drop the framing `token` names and give its slot back. The one op that WAITS for its slot:
    pub(super) fn remove(&self, token: u64) -> Result<(), Reach> {
        let (index, generation) = untoken(token).ok_or(Reach::Gone)?;
        let (k, at) = place(index as usize);
        let slot = self
            .segments
            .get(k)
            .and_then(OnceLock::get)
            .and_then(|s| s.get(at))
            .ok_or(Reach::Gone)?;
        let mut state = slot
            .0
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if state.generation != generation || state.held.is_none() {
            return Err(Reach::Gone);
        }
        let held = state.held.take();
        drop(state);
        slot.0.clear_poison();

        drop(held);

        if generation != u32::MAX {
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
