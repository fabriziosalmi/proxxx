#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::cast_possible_truncation,
    clippy::cast_precision_loss
)]
//! Bench 1 — serde JSON parsing of a 15 000-VM Proxmox payload.
//!
//! Mission 1, Rule 1 (black_box): both the input bytes and the parsed
//! `Vec<Guest>` go through `std::hint::black_box(...)` so LLVM cannot
//! observe that the parse result is unused and dead-strip the call.
//!
//! Mission 1, Rule 2 (isolated I/O): the JSON is generated in memory
//! BEFORE `c.bench_function(...)` is called, so `criterion` only times
//! `serde_json::from_slice` + the trivial vec construction. Zero
//! network, zero filesystem, zero allocator pollution from the
//! generator.

use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use proxxx::api::types::Guest;
use std::hint::black_box;

#[path = "common/mod.rs"]
mod common;

fn bench_parse_guests(c: &mut Criterion) {
    let mut group = c.benchmark_group("serde_parse_guests");
    // Three sizes so we can graph the parser's complexity directly:
    // 100 (laptop homelab), 1 000 (medium prod), 15 000 (mega-cluster
    // — the audit's stated worst case).
    for n in [100usize, 1_000, 15_000] {
        let payload = common::guests_payload(n);
        // Throughput annotation lets criterion print MB/s — useful when
        // comparing against a future zero-copy parser.
        group.throughput(Throughput::Bytes(payload.len() as u64));
        group.bench_with_input(BenchmarkId::from_parameter(n), &payload, |b, payload| {
            b.iter(|| {
                // Both ends of the call are black_boxed: input prevents
                // constant-folding the whole bench away; output prevents
                // dead-code elimination on the Vec<Guest>.
                let parsed: Vec<Guest> =
                    serde_json::from_slice(black_box(payload)).expect("fixture parses");
                black_box(parsed);
            });
        });
    }
    group.finish();
}

criterion_group!(benches, bench_parse_guests);
criterion_main!(benches);
