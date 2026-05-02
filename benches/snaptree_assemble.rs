#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::cast_possible_truncation
)]
//! Bench 2 — snapshot-tree assembly cost on a long parent chain.
//!
//! Stresses `app::snaptree::assemble` — the iterative DFS that
//! materialises a `Vec<Snapshot>` flat list into the branching tree
//! the TUI renders. The bench's specific contract is that even the
//! 1 000-deep chain (the audit's stack-overflow regression case)
//! completes in microseconds, not milliseconds.
//!
//! Mission 1 rules:
//! - Rule 1 (black_box): both `snaps` going in and the `Tree` coming
//!   out are black-boxed.
//! - Rule 2 (isolated I/O): `snapshot_chain(depth)` runs ONCE per
//!   bench-input, not per iteration. The criterion timer wraps only
//!   the `assemble` call.

use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion};
use proxxx::app::snaptree;
use std::hint::black_box;

#[path = "common/mod.rs"]
mod common;

fn bench_assemble_chain(c: &mut Criterion) {
    let mut group = c.benchmark_group("snaptree_assemble_chain");
    for depth in [10usize, 100, 1_000] {
        let snaps = common::snapshot_chain(depth);
        group.bench_with_input(BenchmarkId::from_parameter(depth), &snaps, |b, snaps| {
            b.iter(|| {
                // Clone inside the timed block because `assemble`
                // takes `Vec<Snapshot>` by value (it sorts in
                // place). The clone cost is part of the realistic
                // call profile — the Reducer hands assemble a
                // freshly-fetched Vec.
                let tree = snaptree::assemble(black_box(snaps.clone()));
                black_box(tree);
            });
        });
    }
    group.finish();
}

criterion_group!(benches, bench_assemble_chain);
criterion_main!(benches);
