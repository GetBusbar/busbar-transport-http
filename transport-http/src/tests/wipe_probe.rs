// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use std::alloc::{GlobalAlloc, Layout, System};
use std::cell::RefCell;
#[cfg(target_os = "linux")]
use std::{cell::Cell, fs::File, os::unix::fs::FileExt, sync::OnceLock};

#[cfg(target_os = "linux")]
static MEMORY: OnceLock<File> = OnceLock::new();

#[cfg(target_os = "linux")]
#[derive(Debug, PartialEq, Eq)]
enum Observation {
    Wiped,
    Unwiped,
    Bounds,
    MissingReader,
    ShortRead,
    ReadError,
}

#[derive(Debug)]
struct Record {
    label: &'static str,
    address: usize,
    len: usize,
    freed: bool,
    #[cfg(target_os = "linux")]
    observation: Option<Observation>,
}

struct State {
    active: bool,
    records: Vec<Record>,
}

thread_local! {
    static STATE: RefCell<State> = const {
        RefCell::new(State { active: false, records: Vec::new() })
    };
    #[cfg(target_os = "linux")]
    static READING: Cell<bool> = const { Cell::new(false) };
    #[cfg(target_os = "linux")]
    static REENTERED: Cell<bool> = const { Cell::new(false) };
}

struct Observing;

#[cfg(target_os = "linux")]
fn read_reentered_allocator() -> bool {
    READING
        .try_with(|reading| {
            if reading.get() {
                let _ = REENTERED.try_with(|flag| flag.set(true));
                true
            } else {
                false
            }
        })
        .unwrap_or(false)
}

// SAFETY: allocations and physical frees use System unchanged. The source allocation is never
// dereferenced through Rust in dealloc: Linux copies its registered byte prefix through a
// preopened /proc/self/mem descriptor into initialized stack storage before System frees it.
// Reading even a previously initialized prefix as a Rust slice at dealloc is not justified.
// No allocation capacity, unrelated allocation, object padding or physically freed memory is read.
// These synchronous resolver tests register and drop payloads on the same test thread.
// The registry itself can reallocate under a RefCell borrow; try_borrow_mut then skips that
// metadata allocation. Registered payloads are never dropped while that borrow is held.
unsafe impl GlobalAlloc for Observing {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        #[cfg(target_os = "linux")]
        read_reentered_allocator();
        unsafe { System.alloc(layout) }
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        #[cfg(target_os = "linux")]
        let reentered = read_reentered_allocator();
        #[cfg(not(target_os = "linux"))]
        let reentered = false;
        let _ = STATE.try_with(|state| {
            if reentered {
                return;
            }
            let Ok(mut state) = state.try_borrow_mut() else {
                return;
            };
            if !state.active {
                return;
            }
            if let Some(record) = state
                .records
                .iter_mut()
                .find(|record| !record.freed && record.address == ptr as usize)
            {
                record.freed = true;
                #[cfg(target_os = "linux")]
                let _ = READING.try_with(|reading| {
                    reading.set(true);
                    record.observation = Some(observe(record.address, record.len, layout.size()));
                    reading.set(false);
                });
            }
        });
        unsafe { System.dealloc(ptr, layout) }
    }
}

#[global_allocator]
static ALLOCATOR: Observing = Observing;

#[cfg(target_os = "linux")]
fn observe(address: usize, len: usize, allocation_size: usize) -> Observation {
    if len > allocation_size || address.checked_add(len).is_none() {
        return Observation::Bounds;
    }
    let Some(memory) = MEMORY.get() else {
        return Observation::MissingReader;
    };
    let Ok(address) = u64::try_from(address) else {
        return Observation::Bounds;
    };
    let mut chunk = [0_u8; 4096];
    let mut offset = 0;
    let mut wiped = true;
    while offset < len {
        let count = chunk.len().min(len - offset);
        let Some(at) = address.checked_add(offset as u64) else {
            return Observation::Bounds;
        };
        match memory.read_at(&mut chunk[..count], at) {
            Ok(read) if read == count => {
                wiped &= chunk[..count].iter().all(|byte| *byte == 0);
                offset += count;
            }
            Ok(_) => return Observation::ShortRead,
            Err(_) => return Observation::ReadError,
        }
    }
    if wiped {
        Observation::Wiped
    } else {
        Observation::Unwiped
    }
}

/// Register only an initialized Vec/String/OsString byte payload, at its allocation's start.
/// The caller retains ordinary ownership and must not retype or make the registered prefix
/// uninitialized. A later registration of the same live allocation extends its known prefix.
pub(super) fn watch(label: &'static str, bytes: &[u8]) {
    if bytes.is_empty() {
        return;
    }
    STATE.with(|state| {
        let mut state = state.borrow_mut();
        if !state.active {
            return;
        }
        let address = bytes.as_ptr() as usize;
        if let Some(record) = state
            .records
            .iter_mut()
            .find(|record| !record.freed && record.address == address)
        {
            record.len = record.len.max(bytes.len());
        } else {
            state.records.push(Record {
                label,
                address,
                len: bytes.len(),
                freed: false,
                #[cfg(target_os = "linux")]
                observation: None,
            });
        }
    });
}

pub(super) struct Probe;

impl Probe {
    pub(super) fn start() -> Self {
        // Open before entering the allocator observer; the hook only uses FileExt::read_at.
        #[cfg(target_os = "linux")]
        MEMORY
            .get_or_init(|| File::open("/proc/self/mem").expect("open the Linux memory observer"));
        STATE.with(|state| {
            let mut state = state.borrow_mut();
            assert!(!state.active, "one probe per test thread");
            state.records.clear();
            state.active = true;
        });
        #[cfg(target_os = "linux")]
        REENTERED.with(|flag| flag.set(false));
        Self
    }

    pub(super) fn finish(self) -> Report {
        let records = STATE.with(|state| {
            let mut state = state.borrow_mut();
            state.active = false;
            std::mem::take(&mut state.records)
        });
        #[cfg(target_os = "linux")]
        assert!(
            !REENTERED.with(|flag| flag.replace(false)),
            "the memory read reentered the allocator"
        );
        Report(records)
    }
}

impl Drop for Probe {
    fn drop(&mut self) {
        // Also disarm on a test panic; no stale record may match a later reused address.
        let _ = STATE.try_with(|state| {
            let mut state = state.borrow_mut();
            state.active = false;
            state.records.clear();
        });
    }
}

pub(super) struct Report(Vec<Record>);

impl Report {
    pub(super) fn assert_wiped_on_linux(&self, labels: &[&str]) {
        for label in labels {
            assert!(
                self.0.iter().any(|record| record.label == *label),
                "no initialized payload was registered for {label}: {:?}",
                self.0
            );
        }
        assert!(!self.0.is_empty(), "the probe must observe a payload");
        for record in &self.0 {
            assert!(
                record.freed,
                "payload destruction was not observed: {record:?}"
            );
            #[cfg(target_os = "linux")]
            assert_eq!(
                record.observation,
                Some(Observation::Wiped),
                "complete OS observation must find a wiped payload: {record:?}"
            );
        }
        #[cfg(not(target_os = "linux"))]
        eprintln!("memory-proof gap: this platform checks behavior and matched frees only; byte wiping requires the Linux /proc/self/mem observer");
    }

    pub(super) fn allocations(&self) -> usize {
        self.0.len()
    }

    pub(super) fn allocations_for(&self, label: &str) -> usize {
        self.0.iter().filter(|record| record.label == label).count()
    }
}

#[test]
#[cfg(target_os = "linux")]
fn an_unwiped_payload_is_detected_without_reading_its_spare_capacity() {
    let probe = Probe::start();
    let mut payload = Vec::with_capacity(16_384);
    payload.resize(8193, 0);
    payload[8192] = b'!';
    watch("control", &payload);
    // Unregistered buffers with spare capacity must be ignored altogether.
    drop(Vec::<u8>::with_capacity(8192));
    drop(payload);
    let report = probe.finish();
    assert_eq!(report.allocations(), 1);
    assert_eq!(report.allocations_for("control"), 1);
    assert!(report.0[0].freed, "the negative control was actually freed");
    assert_eq!(
        report.0[0].observation,
        Some(Observation::Unwiped),
        "a complete read must detect the nonzero byte in the final chunk"
    );
}

#[test]
fn a_held_payload_has_a_matched_free_and_is_wiped_on_linux() {
    let probe = Probe::start();
    let mut payload = Vec::with_capacity(16_384);
    payload.resize(8193, b'!');
    watch("held control", &payload);
    drop(busbar_contract::abi::sdk::cred::Held::new(payload));
    let report = probe.finish();
    assert_eq!(report.allocations(), 1);
    assert_eq!(report.allocations_for("held control"), 1);
    report.assert_wiped_on_linux(&["held control"]);
}

#[test]
fn a_live_payload_has_no_deallocation_receipt() {
    let probe = Probe::start();
    let payload = b"still owned".to_vec();
    watch("live", &payload);
    let report = probe.finish();
    assert_eq!(report.allocations(), 1);
    assert!(
        !report.0[0].freed,
        "registration is not a destruction receipt"
    );
    drop(payload);
}
