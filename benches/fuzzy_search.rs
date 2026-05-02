#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::cast_possible_truncation
)]
//! Bench 3 — fuzzy search latency on a 10 000-string haystack.
//!
//! The 60 fps render budget gives proxxx 16.67 ms per frame for ALL
//! work (input handling + state mutation + render). Fuzzy search is
//! one component of that budget; the audit's hard contract is that
//! resolving a complex query (multi-token: `"ubuntu prod sql"`) over
//! a 10 000-item haystack must complete in < 16 ms.
//!
//! Mission 1 rules:
//! - Rule 1 (black_box): the matcher, pattern, and score are all
//!   black-boxed — without this LLVM would observe the score is
//!   unused and inline-fold the entire scoring loop.
//! - Rule 2 (isolated I/O): the haystack is built once outside the
//!   timer. The Matcher itself is constructed inside the iter
//!   closure because `Matcher::new` does heap allocation we want to
//!   amortise per-iteration (mirrors real call cost in
//!   `get_search_results`, which constructs a fresh Matcher per call).
//! - Rule 3 (latency contract): criterion's default 100-sample,
//!   t-test outlier filter is sufficient to detect regressions; if
//!   any of the 100 samples exceeds 16 ms, the matcher's complexity
//!   has regressed and the bench will FAIL on the human reviewer's
//!   eye even if criterion doesn't auto-fail.

use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion};
use nucleo_matcher::pattern::{CaseMatching, Normalization, Pattern};
use nucleo_matcher::{Config, Matcher, Utf32Str};
use std::hint::black_box;

#[path = "common/mod.rs"]
mod common;

fn bench_fuzzy_search(c: &mut Criterion) {
    let mut group = c.benchmark_group("fuzzy_search");

    // Three queries spanning the realistic difficulty range:
    //   - "vm" — short, matches almost everything (worst-case scoring)
    //   - "ubuntu prod" — multi-token fuzzy
    //   - "ubuntu prod sql" — three tokens, the audit's stated case
    let queries = [
        ("short", "vm"),
        ("two_tokens", "ubuntu prod"),
        ("three_tokens", "ubuntu prod sql"),
    ];

    for haystack_size in [1_000usize, 10_000] {
        let haystack = common::haystack(haystack_size);
        for (label, query) in queries {
            let id = format!("haystack_{haystack_size}_{label}");
            group.bench_with_input(
                BenchmarkId::from_parameter(id),
                &(haystack.clone(), query),
                |b, (haystack, query)| {
                    b.iter(|| {
                        // Mirror `get_search_results`: fresh Matcher
                        // per call.
                        let mut matcher = Matcher::new(Config::DEFAULT);
                        let pattern = Pattern::parse(
                            black_box(query),
                            CaseMatching::Ignore,
                            Normalization::Smart,
                        );
                        let mut buf = Vec::new();
                        let mut hits: u32 = 0;
                        for s in haystack.iter() {
                            let h = Utf32Str::new(s, &mut buf);
                            if let Some(score) = pattern.score(h, &mut matcher) {
                                hits = hits.wrapping_add(score);
                            }
                        }
                        // Sink for the accumulator so LLVM can't
                        // notice the loop is side-effect-free.
                        black_box(hits);
                    });
                },
            );
        }
    }
    group.finish();
}

criterion_group!(benches, bench_fuzzy_search);
criterion_main!(benches);
