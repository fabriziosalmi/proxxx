#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
//! #363: an empty identifier is a usage error before any request. It used
//! to build `/pools/` or `/access/users//token`, and some of those printed
//! a fabricated empty object with exit 0.

#[test]
fn empty_identifiers_are_rejected_before_any_request() {
    let dir = tempfile::tempdir().unwrap();
    let cfg = dir.path().join("config.toml");
    // Points nowhere: a request would fail with exit 1, not 2.
    std::fs::write(
        &cfg,
        "url = \"https://127.0.0.1:1\"\nuser = \"root@pam\"\ntoken_id = \"x\"\n\
         token_secret = \"00000000-0000-0000-0000-000000000000\"\nverify_tls = false\n",
    )
    .unwrap();
    for args in [
        vec!["pool", "show", ""],
        vec!["backup-jobs", "show", ""],
        vec!["firewall-cluster", "group", "rules", ""],
        vec!["storage-defs", "show", ""],
        vec!["token", "list", ""],
    ] {
        let out = std::process::Command::new(env!("CARGO_BIN_EXE_proxxx"))
            .args(&args)
            .env("PROXXX_CONFIG", &cfg)
            .env("PROXXX_AUDIT_DIR", dir.path().join("audit"))
            .output()
            .unwrap();
        let err = String::from_utf8_lossy(&out.stderr);
        assert_eq!(out.status.code(), Some(2), "{args:?}: {err}");
        assert!(err.contains("a value is required"), "{args:?}: {err}");
        assert!(out.stdout.is_empty(), "{args:?}");
    }
    // A real id still parses (and then fails on the network, exit 1).
    let out = std::process::Command::new(env!("CARGO_BIN_EXE_proxxx"))
        .args(["pool", "show", "tenant-a"])
        .env("PROXXX_CONFIG", &cfg)
        .env("PROXXX_AUDIT_DIR", dir.path().join("audit"))
        .output()
        .unwrap();
    assert_ne!(out.status.code(), Some(2));
}
