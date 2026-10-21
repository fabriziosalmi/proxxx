#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
//! #351: PVE sends `/nodes/{node}/journal` gzip-compressed even though
//! proxxx does not ask for it; the compressed bytes went to the JSON
//! parser and `node-system <node> journal` always failed.

use std::io::Write as _;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

fn gzip(body: &[u8]) -> Vec<u8> {
    let mut e = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
    e.write_all(body).unwrap();
    e.finish().unwrap()
}

#[tokio::test]
async fn a_gzip_body_is_decoded() {
    let s = MockServer::start().await;
    let body =
        br#"{"data": ["Oct 21 19:12:02 pve1 sshd[1]: one", "Oct 21 19:12:03 pve1 sshd[1]: two"]}"#;
    Mock::given(method("GET"))
        .and(path("/api2/json/nodes/pve1/journal"))
        .respond_with(
            ResponseTemplate::new(200)
                .insert_header("content-encoding", "gzip")
                .insert_header("content-type", "application/json")
                .set_body_raw(gzip(body), "application/json"),
        )
        .mount(&s)
        .await;
    let dir = tempfile::tempdir().unwrap();
    let cfg = dir.path().join("config.toml");
    std::fs::write(
        &cfg,
        format!(
            "url = \"{}\"\nuser = \"root@pam\"\ntoken_id = \"x\"\n\
             token_secret = \"00000000-0000-0000-0000-000000000000\"\nverify_tls = false\n",
            s.uri()
        ),
    )
    .unwrap();
    let out = std::process::Command::new(env!("CARGO_BIN_EXE_proxxx"))
        .args([
            "--format",
            "json",
            "node-system",
            "pve1",
            "journal",
            "--lastentries",
            "2",
        ])
        .env("PROXXX_CONFIG", &cfg)
        .env("PROXXX_AUDIT_DIR", dir.path().join("audit"))
        .output()
        .unwrap();
    let text = String::from_utf8_lossy(&out.stdout);
    assert_eq!(
        out.status.code(),
        Some(0),
        "{text}\n{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(
        text.contains("sshd[1]: two") && text.contains("\"count\": 2"),
        "{text}"
    );
}
