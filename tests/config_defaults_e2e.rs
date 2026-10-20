//! End-to-end binary tests for `[defaults]` config inheritance (`#331`, Step 20).

use std::process::Command;

use anyhow::{Context, Result};

const fn proxxx_bin() -> &'static str {
    env!("CARGO_BIN_EXE_proxxx")
}

const REFUSAL_CASES: &[(&str, &str, &str)] = &[
    (
        "url-in-defaults.toml",
        "[defaults]\nurl = \"https://pve1.lan:8006\"\nuser = \"root@pam\"\n\n[profiles.pve1]\nurl = \"https://pve1.lan:8006\"\n",
        "url",
    ),
    (
        "token-secret-in-defaults.toml",
        "[defaults]\nuser = \"root@pam\"\ntoken_secret = \"shared-secret-value\"\n\n[profiles.pve1]\nurl = \"https://pve1.lan:8006\"\n",
        "token_secret",
    ),
    (
        "token-secret-file-in-defaults.toml",
        "[defaults]\nuser = \"root@pam\"\ntoken_secret_file = \"/tmp/shared.token\"\n\n[profiles.pve1]\nurl = \"https://pve1.lan:8006\"\n",
        "token_secret_file",
    ),
    (
        "password-in-defaults.toml",
        "[defaults]\nuser = \"root@pam\"\npassword = \"shared-password\"\n\n[profiles.pve1]\nurl = \"https://pve1.lan:8006\"\n",
        "password",
    ),
    (
        "pbs-secret-in-defaults.toml",
        "[defaults]\nuser = \"root@pam\"\n[defaults.pbs]\ntoken_secret = \"shared-pbs-secret\"\n\n[profiles.pve1]\nurl = \"https://pve1.lan:8006\"\n",
        "pbs.token_secret",
    ),
    (
        "telegram-secret-in-defaults.toml",
        "[defaults]\nuser = \"root@pam\"\n[defaults.telegram]\nbot_token = \"shared-tg-secret\"\n\n[profiles.pve1]\nurl = \"https://pve1.lan:8006\"\n",
        "telegram.bot_token",
    ),
    (
        "unknown-key-in-defaults.toml",
        "[defaults]\nuser = \"root@pam\"\nverfiy_tls = false\n\n[profiles.pve1]\nurl = \"https://pve1.lan:8006\"\n",
        "verfiy_tls",
    ),
    (
        "unknown-ssh-key-in-defaults.toml",
        "[defaults]\nuser = \"root@pam\"\n[defaults.ssh]\nkey = \"~/.ssh/id_ed25519\"\n\n[profiles.pve1]\nurl = \"https://pve1.lan:8006\"\n",
        "unknown field `key`",
    ),
];

/// Test 5 (`#331`): Refusals (`url` in `[defaults]`, secrets in `[defaults]`,
/// unknown key in `[defaults]`) must all exit `3` (`ConfigError::EXIT_CODE`)
/// end-to-end with the binary and name `defaults` on stderr.
#[test]
fn test_5_binary_refuses_url_secrets_and_unknown_keys_in_defaults_with_exit_3() -> Result<()> {
    let tmp = tempfile::tempdir()?;

    for &(filename, body, expected_needle) in REFUSAL_CASES {
        let cfg_path = tmp.path().join(filename);
        std::fs::write(&cfg_path, body)?;

        let out = Command::new(proxxx_bin())
            .env("PROXXX_CONFIG", &cfg_path)
            .args(["--profile", "pve1", "ls", "nodes"])
            .output()?;

        let code = out.status.code().unwrap_or(-1);
        let stderr = String::from_utf8_lossy(&out.stderr);
        assert_eq!(
            code, 3,
            "{filename}: expected exit code 3 (ConfigError), got {code}; stderr:\n{stderr}"
        );
        assert!(
            stderr.contains("defaults"),
            "{filename}: stderr must name `defaults`, got:\n{stderr}"
        );
        assert!(
            stderr.contains(expected_needle),
            "{filename}: stderr must mention `{expected_needle}`, got:\n{stderr}"
        );
    }
    Ok(())
}

/// End-to-end binary verification that `proxxx --profile <name> doctor` merges
/// `[defaults]` and `[defaults.ssh]` into each profile (`pve1` and `pve2`).
#[test]
fn binary_doctor_merges_defaults_into_each_profile() -> Result<()> {
    let tmp = tempfile::tempdir()?;
    let ssh_key = tmp.path().join("id_ed25519");
    std::fs::write(&ssh_key, "dummy-ssh-key-for-doctor-check\n")?;

    let cfg_path = tmp.path().join("config.toml");
    let body = format!(
        r#"
default = "pve1"

[defaults]
user = "root@pam"
token_id = "proxxx"
verify_tls = false

[defaults.ssh]
user = "ops"
key_path = "{}"

[profiles.pve1]
url = "https://127.0.0.1:1"

[profiles.pve2]
url = "https://127.0.0.2:1"
"#,
        ssh_key.display()
    );
    std::fs::write(&cfg_path, body)?;

    for (prof, expected_url) in [
        ("pve1", "https://127.0.0.1:1"),
        ("pve2", "https://127.0.0.2:1"),
    ] {
        let out = Command::new(proxxx_bin())
            .env("PROXXX_CONFIG", &cfg_path)
            .args(["--format", "json", "--profile", prof, "doctor"])
            .output()?;

        let stdout = String::from_utf8_lossy(&out.stdout);
        let parsed: serde_json::Value = serde_json::from_str(&stdout)?;
        let checks = parsed.as_array().context("doctor array")?;

        let config_check = checks
            .iter()
            .find(|c| c["check"] == "config")
            .context("config check")?;
        assert_eq!(config_check["status"], "ok");
        assert!(
            config_check["message"]
                .as_str()
                .unwrap_or("")
                .contains(expected_url),
            "expected {expected_url} in doctor config message, got: {config_check}"
        );

        let tls_check = checks
            .iter()
            .find(|c| c["check"] == "tls")
            .context("tls check")?;
        assert_eq!(
            tls_check["status"], "warn",
            "verify_tls = false from [defaults] must propagate to {prof}"
        );

        let ssh_check = checks
            .iter()
            .find(|c| c["check"] == "ssh_key")
            .context("ssh_key check")?;
        assert_eq!(
            ssh_check["status"], "ok",
            "[defaults.ssh].key_path must propagate to {prof}: {ssh_check}"
        );
    }
    Ok(())
}
