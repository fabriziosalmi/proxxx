#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::missing_panics_doc,
    clippy::missing_errors_doc,
    clippy::too_many_lines
)]
//! Audit-chain verifiability — the ADMIN-facing contract.
//!
//! The audit chain is only useful to an auditor if they can *run something* that
//! proves the log wasn't tampered with, and that thing must fail loudly when it
//! was. This drives the real `proxxx audit verify` binary end-to-end:
//!
//!   * a clean chain → exit 0 (`proxxx audit verify && echo trusted`)
//!   * one tampered row → exit 1 (scriptable / monitorable alarm)
//!
//! The logger-level mutation detection is exhaustively proptested in
//! `src/audit/mod.rs`; this pins the CLI exit-code contract an operator's cron
//! job actually depends on.
//!
//! Single test per binary: it sets the process-global `PROXXX_AUDIT_DIR`, so it
//! must not race a sibling. Its own subprocesses inherit the same dir explicitly.

use std::process::Command;

const fn proxxx_bin() -> &'static str {
    env!("CARGO_BIN_EXE_proxxx")
}

#[test]
fn audit_verify_exit_code_reflects_tampering() {
    let dir = tempfile::tempdir().expect("temp dir");
    let audit_dir = dir.path().to_str().unwrap().to_string();

    // Point the in-process logger at the temp dir; co-locate the key (no
    // PROXXX_AUDIT_KEY) so the subprocess resolves the same key file.
    std::env::set_var("PROXXX_AUDIT_DIR", &audit_dir);
    std::env::remove_var("PROXXX_AUDIT_KEY");

    // Write a short chain via the real logger.
    {
        let mut logger = proxxx::audit::AuditLogger::open().expect("open audit logger");
        logger
            .log(
                "delete",
                "alice",
                Some(100),
                Some("pve1"),
                Some("{\"k\":1}"),
                "ok",
            )
            .unwrap();
        logger
            .log("stop", "bob", Some(101), Some("pve1"), None, "ok")
            .unwrap();
        logger
            .log("migrate", "carol", Some(102), Some("pve2"), None, "ok")
            .unwrap();
    }

    // (1) Clean chain → `audit verify` exits 0.
    let clean = Command::new(proxxx_bin())
        .args(["audit", "verify"])
        .env("PROXXX_AUDIT_DIR", &audit_dir)
        .env_remove("PROXXX_AUDIT_KEY")
        .output()
        .expect("run audit verify");
    assert!(
        clean.status.success(),
        "clean chain must verify (exit 0). stdout={} stderr={}",
        String::from_utf8_lossy(&clean.stdout),
        String::from_utf8_lossy(&clean.stderr),
    );

    // Tamper: rewrite the actor of the first row directly in SQLite — exactly
    // the "rewrite who ran the delete" attack the chain exists to catch.
    {
        let db = dir.path().join("audit.db");
        let conn = rusqlite::Connection::open(&db).expect("open audit db");
        let n = conn
            .execute("UPDATE audit_log SET user = 'mallory' WHERE id = 1", [])
            .expect("tamper");
        assert_eq!(n, 1, "expected to rewrite exactly one row");
    }

    // (2) Tampered chain → `audit verify` exits non-zero.
    let tampered = Command::new(proxxx_bin())
        .args(["audit", "verify"])
        .env("PROXXX_AUDIT_DIR", &audit_dir)
        .env_remove("PROXXX_AUDIT_KEY")
        .output()
        .expect("run audit verify");
    assert!(
        !tampered.status.success(),
        "tampered chain MUST fail verification (non-zero exit). stdout={} stderr={}",
        String::from_utf8_lossy(&tampered.stdout),
        String::from_utf8_lossy(&tampered.stderr),
    );

    std::env::remove_var("PROXXX_AUDIT_DIR");
}
