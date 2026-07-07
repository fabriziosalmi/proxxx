//! Executable proof for the `SecretString` invariant: no secret-bearing
//! type can leak its value through `Debug` — `{:?}` and `{:#?}` print
//! `[REDACTED]` for every credential field, as a property of the type.
//!
//! Method: build each secret-bearing struct with a unique sentinel per
//! field, format it both ways, and assert (a) no sentinel appears and
//! (b) the redaction marker does. The v0.13.1 `WsTarget` fix proved the
//! pattern; v0.13.2 makes it total. Non-secret fields (`user`, `url`,
//! `chat_id`) must still print — redaction must not blind diagnostics.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

use proxxx::config::ProfileConfig;
use proxxx::util::secret::SecretString;

const S1: &str = "SENTINEL-pve-token-a7f3";
const S2: &str = "SENTINEL-pve-ticket-b2e9";
const S3: &str = "SENTINEL-pve-csrf-c4d1";
const S4: &str = "SENTINEL-password-d8c2";
const S5: &str = "SENTINEL-mcp-bearer-e5a6";
const S6: &str = "SENTINEL-pbs-token-f9b4";
const S7: &str = "SENTINEL-bot-token-a1c8";

fn assert_redacted(label: &str, rendered: &str, sentinels: &[&str]) {
    for s in sentinels {
        assert!(
            !rendered.contains(s),
            "{label}: sentinel {s} leaked through Debug:\n{rendered}"
        );
    }
    assert!(
        rendered.contains("[REDACTED]"),
        "{label}: expected the [REDACTED] marker in Debug output:\n{rendered}"
    );
}

// NOTE: `AuthMethod` (api::auth is crate-private) has the equivalent
// Debug-redaction proofs as inline unit tests in src/api/auth.rs —
// `debug_redacts_token_variant` / `debug_redacts_password_variant`.

#[test]
fn secret_string_itself_redacts_both_forms() {
    let s = SecretString::from(S2);
    assert_eq!(format!("{s:?}"), "[REDACTED]");
    assert_eq!(format!("{s:#?}"), "[REDACTED]");
    // No length leak: output identical regardless of the secret's size.
    assert_eq!(format!("{:?}", SecretString::from("")), "[REDACTED]");
    // The value is still reachable — explicitly.
    assert_eq!(s.expose(), S2);
}

#[test]
fn full_profile_config_debug_redacts_every_credential_field() {
    // A config.toml exercising EVERY secret-bearing field in one parse:
    // profile token_secret + password + mcp_token, PBS token_secret,
    // Telegram bot_token. Parsed through the real serde path so this
    // also pins that `SecretString: Deserialize` accepts plain TOML
    // strings (config back-compat).
    let toml_src = format!(
        r#"
url = "https://pve.example:8006"
user = "root@pam"
token_id = "proxxx"
token_secret = "{S1}"
password = "{S4}"
verify_tls = true
mcp_token = "{S5}"

[pbs]
url = "https://pbs.example:8007"
user = "proxxx@pbs"
token_id = "reader"
token_secret = "{S6}"

[telegram]
bot_token = "{S7}"
chat_id = "-100200300"
"#
    );
    let profile: ProfileConfig = toml::from_str(&toml_src).expect("config parses");
    let profile = &profile;

    for rendered in [format!("{profile:?}"), format!("{profile:#?}")] {
        assert_redacted(
            "ProfileConfig (incl. PbsConfig + TelegramConfig)",
            &rendered,
            &[S1, S2, S3, S4, S5, S6, S7],
        );
        // Non-secret operational fields must survive redaction.
        assert!(rendered.contains("https://pve.example:8006"));
        assert!(rendered.contains("proxxx@pbs"));
        assert!(rendered.contains("-100200300"));
    }

    // The values themselves are intact behind the redaction.
    assert_eq!(profile.token_secret.as_ref().expect("set").expose(), S1);
    assert_eq!(
        profile
            .telegram
            .as_ref()
            .and_then(|t| t.bot_token.as_ref())
            .expect("set")
            .expose(),
        S7
    );
}

#[test]
fn clone_preserves_value_and_redaction() {
    let original = SecretString::from(S3);
    let clone = original.clone();
    assert_eq!(original, clone);
    assert_eq!(clone.expose(), S3);
    assert_eq!(format!("{clone:?}"), "[REDACTED]");
}

#[test]
fn statically_pinned_zeroize_on_drop() {
    // Invariant #1 (security matrix row 3): the drop-wipe guarantee is a
    // compile-time property — SecretString implements ZeroizeOnDrop
    // (backed by zeroize::Zeroizing). Runtime memory inspection after
    // free is UB, so the honest executable proof is this type pin: if a
    // refactor swaps the inner storage for a plain String, this stops
    // compiling.
    fn assert_zod<T: zeroize::ZeroizeOnDrop>() {}
    assert_zod::<SecretString>();
}
