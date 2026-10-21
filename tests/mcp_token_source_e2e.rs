#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
//! #384: `mcp serve-http` took its bearer token only on argv, where `ps`
//! shows it. `--token-file` and `PROXXX_MCP_TOKEN` keep it out of the
//! process listing; the file wins over `--token`, which wins over the
//! variable.

use std::io::{BufRead as _, BufReader};
use std::process::{Child, Command, Stdio};
use std::time::Duration;

fn write_config(dir: &std::path::Path) -> std::path::PathBuf {
    let path = dir.join("config.toml");
    std::fs::write(
        &path,
        "url = \"https://127.0.0.1:1\"\nuser = \"root@pam\"\ntoken_id = \"proxxx\"\n\
         token_secret = \"00000000-0000-0000-0000-000000000000\"\nverify_tls = false\n",
    )
    .unwrap();
    path
}

fn free_port() -> u16 {
    let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    l.local_addr().unwrap().port()
}

struct Server(Child);
impl Drop for Server {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

/// Start `mcp serve-http` and wait until it listens.
fn serve(dir: &std::path::Path, port: u16, extra: &[&str], env: Option<&str>) -> Server {
    let cfg = write_config(dir);
    let port_s = port.to_string();
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_proxxx"));
    cmd.args(["mcp", "serve-http", "--port", &port_s])
        .args(extra)
        .env("PROXXX_CONFIG", &cfg)
        .env("PROXXX_AUDIT_DIR", dir.join("audit"))
        .env("RUST_LOG", "proxxx=info")
        .env_remove("PROXXX_MCP_TOKEN")
        .stdout(Stdio::null())
        .stderr(Stdio::piped());
    if let Some(v) = env {
        cmd.env("PROXXX_MCP_TOKEN", v);
    }
    let mut child = cmd.spawn().unwrap();
    let stderr = child.stderr.take().unwrap();
    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        for line in BufReader::new(stderr).lines().map_while(Result::ok) {
            if line.contains("MCP HTTP server listening") {
                let _ = tx.send(());
            }
        }
    });
    rx.recv_timeout(Duration::from_secs(20))
        .expect("serve-http did not start");
    Server(child)
}

async fn ping(port: u16, bearer: Option<&str>) -> u16 {
    let mut req = reqwest::Client::new()
        .post(format!("http://127.0.0.1:{port}/mcp"))
        .header("Host", format!("127.0.0.1:{port}"))
        .header("Content-Type", "application/json")
        .body(r#"{"jsonrpc":"2.0","id":1,"method":"ping"}"#);
    if let Some(b) = bearer {
        req = req.header("Authorization", format!("Bearer {b}"));
    }
    req.send().await.unwrap().status().as_u16()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_token_comes_from_the_file_then_the_flag_then_the_variable() {
    let dir = tempfile::tempdir().unwrap();
    let file = dir.path().join("mcp.token");
    std::fs::write(&file, "from-file\n").unwrap();
    let file_s = file.to_str().unwrap();

    let port = free_port();
    let server = serve(
        dir.path(),
        port,
        &["--token-file", file_s, "--token", "from-flag"],
        Some("from-env"),
    );
    assert_eq!(ping(port, Some("from-file")).await, 200);
    assert_eq!(ping(port, Some("from-flag")).await, 401);
    assert_eq!(ping(port, Some("from-env")).await, 401);
    assert_eq!(ping(port, None).await, 401);
    drop(server);

    let port = free_port();
    let server = serve(
        dir.path(),
        port,
        &["--token", "from-flag"],
        Some("from-env"),
    );
    assert_eq!(ping(port, Some("from-flag")).await, 200);
    assert_eq!(ping(port, Some("from-env")).await, 401);
    drop(server);

    let port = free_port();
    let _server = serve(dir.path(), port, &[], Some("from-env"));
    assert_eq!(ping(port, Some("from-env")).await, 200);
    assert_eq!(ping(port, None).await, 401);
}

#[test]
fn an_empty_token_file_is_refused() {
    let dir = tempfile::tempdir().unwrap();
    let file = dir.path().join("mcp.token");
    std::fs::write(&file, "  \n").unwrap();
    let child = Command::new(env!("CARGO_BIN_EXE_proxxx"))
        .args(["mcp", "serve-http", "--port", &free_port().to_string()])
        .arg("--token-file")
        .arg(&file)
        .env("PROXXX_CONFIG", write_config(dir.path()))
        .env("PROXXX_AUDIT_DIR", dir.path().join("audit"))
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let mut server = Server(child);
    // A server that starts instead of refusing must fail the test, not hang it.
    let deadline = std::time::Instant::now() + Duration::from_secs(20);
    let status = loop {
        if let Some(st) = server.0.try_wait().unwrap() {
            break st;
        }
        assert!(
            std::time::Instant::now() < deadline,
            "serve-http started with an empty --token-file"
        );
        std::thread::sleep(Duration::from_millis(50));
    };
    let mut err = String::new();
    std::io::Read::read_to_string(&mut server.0.stderr.take().unwrap(), &mut err).unwrap();
    assert_ne!(status.code(), Some(0), "{err}");
    assert!(err.contains("is empty"), "{err}");
}
