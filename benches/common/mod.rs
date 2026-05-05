//! Shared fixture generators for the proxxx benchmark suite.
//!
//! Each bench binary `mod common;` this file. The functions return
//! owned data so the caller can `let payload = common::guests_payload(N);`
//! BEFORE handing the payload to `c.bench_function(...)` — i.e., the
//! generation cost is OUTSIDE the criterion timer.

#![allow(
    dead_code, // each bench uses a subset
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::cast_possible_truncation,
    clippy::cast_precision_loss
)]

/// Build a JSON byte buffer for `n` Proxmox guests, schema-faithful to
/// `api::types::Guest` (vmid, name, status, type, node, cpu/cpus, mem,
/// disk, uptime, tags). Output is a `Vec<u8>` of UTF-8 JSON suitable
/// for `serde_json::from_slice`.
///
/// Generation is deterministic (index-based) — every call with the
/// same `n` produces byte-identical output. Bench result variance
/// reflects parser jitter only, not fixture entropy.
pub fn guests_payload(n: usize) -> Vec<u8> {
    let mut s = String::with_capacity(n * 220);
    s.push('[');
    for i in 0..n {
        if i > 0 {
            s.push(',');
        }
        let vmid = 1000 + i;
        let node = format!("pve{}", (i % 16) + 1);
        let typ = if i % 3 == 0 { "lxc" } else { "qemu" };
        let status = match i % 4 {
            0 => "running",
            1 => "stopped",
            2 => "paused",
            _ => "unknown",
        };
        let tags = if i % 5 == 0 { "prod;web" } else { "dev" };
        // Faithful to PVE shape: cpu = float, mem = u64, type = string.
        let _ = std::fmt::Write::write_fmt(
            &mut s,
            format_args!(
                r#"{{"vmid":{vmid},"name":"vm-{i:05}","status":"{status}","type":"{typ}","node":"{node}","cpu":{cpu:.2},"cpus":{cpus},"mem":{mem},"maxmem":{maxmem},"disk":{disk},"maxdisk":{maxdisk},"uptime":{uptime},"tags":"{tags}"}}"#,
                cpu = (i % 100) as f64 / 100.0,
                cpus = (i % 8) + 1,
                mem = (i as u64) * 1024,
                maxmem = ((i as u64) + 1) * 4096,
                disk = (i as u64) * 1_000_000,
                maxdisk = ((i as u64) + 1) * 5_000_000,
                uptime = i * 60,
            ),
        );
    }
    s.push(']');
    s.into_bytes()
}

/// Synthetic snapshot list with a linear parent chain `depth` long.
/// Used to stress `snaptree::assemble` worst-case recursion (chain
/// resolution) without any branching.
///
/// Returns `Vec<api::types::Snapshot>` ready to pass into
/// `assemble(&snaps)`.
pub fn snapshot_chain(depth: usize) -> Vec<proxxx::api::types::Snapshot> {
    use proxxx::api::types::Snapshot;
    let mut out = Vec::with_capacity(depth + 1);
    for i in 0..depth {
        out.push(Snapshot {
            name: format!("snap-{i}"),
            parent: if i == 0 {
                String::new()
            } else {
                format!("snap-{}", i - 1)
            },
            description: String::new(),
            snaptime: i as u64,
            vmstate: 0,
        });
    }
    // Tail "current" pointer at the end of the chain (matches PVE).
    out.push(Snapshot {
        name: "current".into(),
        parent: format!("snap-{}", depth.saturating_sub(1)),
        description: String::new(),
        snaptime: 0,
        vmstate: 0,
    });
    out
}

/// `n` synthetic strings to drop into a fuzzy-matcher haystack. Mix
/// of guest-name-shaped and tag-shaped tokens so the matcher's
/// fuzzy-vs-prefix paths both get exercised.
pub fn haystack(n: usize) -> Vec<String> {
    (0..n)
        .map(|i| {
            let kind = match i % 4 {
                0 => "ubuntu-jammy",
                1 => "debian-bookworm",
                2 => "alpine-edge",
                _ => "fedora-39",
            };
            let role = match i % 3 {
                0 => "prod-sql",
                1 => "dev-web",
                _ => "stage-cache",
            };
            format!("vm-{i:05}-{kind}-{role}")
        })
        .collect()
}
