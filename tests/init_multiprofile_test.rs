#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]
//! Integration tests for `proxxx init --profile` (append, never clobber)
//! and the profile-only `load_config` UX (#142).
//!
//! Hermetic via the `PROXXX_CONFIG` env override (added alongside this
//! feature) — each test points proxxx at a temp config file, so no OS
//! config dir is touched. `serial_test` guards the shared env var.

use std::io::Write as _;

use serial_test::serial;

/// Unique temp config path for one test. Returns a guard that cleans up
/// on drop and sets `PROXXX_CONFIG` for the duration.
struct ConfigEnv {
    path: std::path::PathBuf,
}

impl ConfigEnv {
    fn new(tag: &str) -> Self {
        let mut path = std::env::temp_dir();
        // tag is unique per test; no Instant/random needed.
        path.push(format!("proxxx-init-test-{tag}.toml"));
        let _ = std::fs::remove_file(&path);
        std::env::set_var("PROXXX_CONFIG", &path);
        Self { path }
    }

    fn write(&self, body: &str) {
        let mut f = std::fs::File::create(&self.path).unwrap();
        f.write_all(body.as_bytes()).unwrap();
    }

    fn read(&self) -> String {
        std::fs::read_to_string(&self.path).unwrap()
    }
}

impl Drop for ConfigEnv {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.path);
        std::env::remove_var("PROXXX_CONFIG");
    }
}

// ── init --profile: append, never clobber ──────────────────────

#[tokio::test]
#[serial]
async fn bare_init_refuses_to_clobber_existing_and_suggests_profile() {
    let env = ConfigEnv::new("append");
    // Pre-existing multi-profile config + a comment to preserve.
    env.write(
        "# my homelab config\n\
         [profiles.alpha]\n\
         url = \"https://10.0.0.1:8006\"\n\
         user = \"root@pam\"\n\
         token_id = \"t\"\n",
    );

    // Bare `proxxx init` (no --profile) must NOT clobber an existing config.
    let err = proxxx::cli::execute(
        proxxx::cli::Command::Init {
            force: false,
            interactive: false,
        },
        None,
        None,
        false,
        proxxx::util::format::OutputFormat::Json,
    )
    .await
    .expect_err("bare init must refuse to overwrite an existing config");
    let msg = err.to_string();
    assert!(msg.contains("already exists"), "got: {msg}");
    assert!(
        msg.contains("--profile"),
        "points at the append path: {msg}"
    );
    // Existing content fully intact.
    assert!(env.read().contains("[profiles.alpha]"), "alpha preserved");
}

#[tokio::test]
#[serial]
async fn init_profile_via_profile_arg_appends_second_profile() {
    let env = ConfigEnv::new("second");
    env.write(
        "[profiles.alpha]\n\
         url = \"https://10.0.0.1:8006\"\n\
         user = \"root@pam\"\n\
         token_id = \"t\"\n",
    );

    // `--profile beta init` → append [profiles.beta], keep alpha.
    let (val, code) = proxxx::cli::execute(
        proxxx::cli::Command::Init {
            force: false,
            interactive: false,
        },
        Some("beta"),
        None,
        false,
        proxxx::util::format::OutputFormat::Json,
    )
    .await
    .unwrap();

    assert_eq!(code, 0);
    assert_eq!(val["action"], "added");
    assert_eq!(val["profile"], "beta");

    let content = env.read();
    assert!(
        content.contains("[profiles.alpha]"),
        "alpha preserved: {content}"
    );
    assert!(content.contains("[profiles.beta]"), "beta added: {content}");

    // Both load cleanly.
    assert_eq!(
        proxxx::config::list_profiles().unwrap(),
        vec!["alpha", "beta"]
    );
}

#[tokio::test]
#[serial]
async fn init_profile_refuses_duplicate_without_force() {
    let env = ConfigEnv::new("dup");
    env.write(
        "[profiles.alpha]\nurl = \"https://x:8006\"\nuser = \"root@pam\"\ntoken_id = \"t\"\n",
    );
    let err = proxxx::cli::execute(
        proxxx::cli::Command::Init {
            force: false,
            interactive: false,
        },
        Some("alpha"),
        None,
        false,
        proxxx::util::format::OutputFormat::Json,
    )
    .await
    .unwrap_err();
    assert!(err.to_string().contains("already exists"), "got: {err:#}");
    // --force overwrites just that profile.
    let (val, _) = proxxx::cli::execute(
        proxxx::cli::Command::Init {
            force: true,
            interactive: false,
        },
        Some("alpha"),
        None,
        false,
        proxxx::util::format::OutputFormat::Json,
    )
    .await
    .unwrap();
    assert_eq!(val["action"], "updated");
}

#[tokio::test]
#[serial]
async fn init_profile_creates_file_when_absent() {
    let env = ConfigEnv::new("fresh");
    // no file yet
    assert!(!env.path.exists());
    let (val, code) = proxxx::cli::execute(
        proxxx::cli::Command::Init {
            force: false,
            interactive: false,
        },
        Some("prod"),
        None,
        false,
        proxxx::util::format::OutputFormat::Json,
    )
    .await
    .unwrap();
    assert_eq!(code, 0);
    assert_eq!(val["action"], "added");
    assert!(env.read().contains("[profiles.prod]"));
    assert_eq!(proxxx::config::list_profiles().unwrap(), vec!["prod"]);
}

// ── load_config UX: profile-only configs ───────────────────────

#[test]
#[serial]
fn load_config_auto_defaults_to_sole_profile() {
    let env = ConfigEnv::new("sole");
    env.write(
        "[profiles.only]\nurl = \"https://10.0.0.9:8006\"\nuser = \"root@pam\"\ntoken_id = \"t\"\n",
    );
    // No --profile, no flat config, exactly one profile → use it.
    let cfg = proxxx::config::load_config(None).expect("auto-defaults to the sole profile");
    assert_eq!(cfg.url, "https://10.0.0.9:8006");
    assert_eq!(cfg.profile_name.as_deref(), Some("only"));
}

#[test]
#[serial]
fn load_config_honors_top_level_default_key() {
    let env = ConfigEnv::new("defkey");
    env.write(
        "default = \"prod\"\n\
         [profiles.dev]\nurl = \"https://dev:8006\"\nuser = \"root@pam\"\ntoken_id = \"t\"\n\
         [profiles.prod]\nurl = \"https://prod:8006\"\nuser = \"root@pam\"\ntoken_id = \"t\"\n",
    );
    let cfg = proxxx::config::load_config(None).expect("uses default = prod");
    assert_eq!(cfg.url, "https://prod:8006");
    assert_eq!(cfg.profile_name.as_deref(), Some("prod"));
}

#[test]
#[serial]
fn load_config_multiprofile_no_default_errors_actionably() {
    let env = ConfigEnv::new("ambig");
    env.write(
        "[profiles.dev]\nurl = \"https://dev:8006\"\nuser = \"root@pam\"\ntoken_id = \"t\"\n\
         [profiles.prod]\nurl = \"https://prod:8006\"\nuser = \"root@pam\"\ntoken_id = \"t\"\n",
    );
    let err = proxxx::config::load_config(None).expect_err("ambiguous: 2 profiles, no default");
    let msg = err.to_string();
    assert!(
        msg.contains("dev") && msg.contains("prod"),
        "lists profiles: {msg}"
    );
    assert!(msg.contains("--profile"), "suggests --profile: {msg}");
    // NOT the opaque serde message.
    assert!(!msg.contains("missing field"), "should be friendly: {msg}");
}

#[test]
#[serial]
fn load_config_explicit_profile_still_wins() {
    let env = ConfigEnv::new("explicit");
    env.write(
        "default = \"dev\"\n\
         [profiles.dev]\nurl = \"https://dev:8006\"\nuser = \"root@pam\"\ntoken_id = \"t\"\n\
         [profiles.prod]\nurl = \"https://prod:8006\"\nuser = \"root@pam\"\ntoken_id = \"t\"\n",
    );
    let cfg = proxxx::config::load_config(Some("prod")).expect("explicit wins over default");
    assert_eq!(cfg.url, "https://prod:8006");
}

#[test]
#[serial]
fn load_config_flat_still_works() {
    let env = ConfigEnv::new("flat");
    env.write("url = \"https://flat:8006\"\nuser = \"root@pam\"\ntoken_id = \"t\"\n");
    let cfg = proxxx::config::load_config(None).expect("flat config still loads");
    assert_eq!(cfg.url, "https://flat:8006");
    assert_eq!(cfg.profile_name, None);
}
