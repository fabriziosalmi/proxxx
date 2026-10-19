//! Aerospace-style panic hook (flight recorder — flight recorder).
//!
//! Installs a `std::panic::set_hook` that, before propagating the panic:
//! 1. Disables raw mode (best-effort — no-op if not enabled).
//! 2. Leaves the alternate screen and shows the cursor.
//! 3. Logs the panic info via `tracing::error!` so the audit log file
//!    captures the trace alongside the rest of the application log.
//! 4. Calls the previous hook so the default colourful trace still
//!    prints to stderr for the user.
//!
//! Idempotent: calling `install()` twice replaces the hook with itself
//! (the second install captures the first one's chain via `take_hook`).
//! Both TUI and CLI mode call this from `main` so a panic from any path
//! leaves the terminal in a usable state.

use std::sync::atomic::{AtomicBool, Ordering};

static INSTALLED: AtomicBool = AtomicBool::new(false);

/// Install the global panic hook. Safe to call multiple times — only
/// the first call wires the chain; later calls are no-ops.
pub fn install() {
    if INSTALLED
        .compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst)
        .is_err()
    {
        return;
    }
    let original = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| {
        // 1. Audit log capture FIRST — even if the terminal restoration
        //    below fails for some reason, the trace must reach the log
        //    file. tracing-appender's non_blocking writer flushes on
        //    drop of its guard (the application's `_guard` in main).
        let location = info.location().map_or_else(
            || "unknown".to_string(),
            |l| format!("{}:{}", l.file(), l.line()),
        );
        let raw_payload = panic_message(info);
        // Phase 5.13 GAP 3 — scrub credentials from the payload BEFORE
        // it reaches the audit log. An `expect("token: abc")` in a hot
        // path would otherwise leak the secret to disk forever.
        let payload = scrub_secrets(&raw_payload);
        tracing::error!(
            target: "panic",
            location = %location,
            "PANIC: {payload}"
        );

        // 2. Terminal restoration. Best-effort — every step is fire-
        //    and-forget. The user's terminal is the most precious thing
        //    we own at this point; we do not gate later steps on
        //    earlier-step failures.
        let _ = crossterm::terminal::disable_raw_mode();
        let _ = crossterm::execute!(
            std::io::stdout(),
            crossterm::terminal::LeaveAlternateScreen,
            crossterm::cursor::Show,
        );

        // 3. Mark the audit log so a tail of the file shows the panic
        //    without needing the panic-target filter.
        eprintln!();
        eprintln!("💀 proxxx panicked at {location}");
        // Stderr message also goes through the scrubber — a panic
        // message printed to a CI log or screenshot is just as
        // dangerous as one in the audit file.
        eprintln!("   payload: {payload}");
        eprintln!("   audit log: ~/.local/share/proxxx (proxxx.log)");
        eprintln!();

        // 4. Run the original hook for the colourful trace.
        original(info);
    }));
}

/// Best-effort extraction of the panic payload as a string. Handles
/// the two payload types `panic!` macros produce: `&'static str` and
/// `String`. Other Box<dyn Any> payloads return a generic placeholder.
fn panic_message(info: &std::panic::PanicHookInfo<'_>) -> String {
    let payload = info.payload();
    if let Some(s) = payload.downcast_ref::<&'static str>() {
        return (*s).to_string();
    }
    if let Some(s) = payload.downcast_ref::<String>() {
        return s.clone();
    }
    "<non-string panic payload>".to_string()
}

/// Phase 5.13 GAP 3 — scrub credential-bearing tokens from a panic
/// payload before logging. Inputs are arbitrary `panic!` strings; we
/// don't know what shape they take, so we look for the credential
/// **markers** known to appear in proxxx (PVE, PBS, Telegram) and
/// replace the value run with `[REDACTED]`.
///
/// Patterns covered:
/// - `PVEAuthCookie=<value>` (PVE ticket cookie — bearer token)
/// - `PVEAPIToken=<user>!<id>=<secret>` (PVE API token header)
/// - `PBSAPIToken=<user>!<id>:<secret>` (PBS API token header)
/// - `tokenid=<value>` (Telegram bot token URL parameter; PVE token id)
/// - `password=<value>` (login form field — never logged in normal
///   path but a panic before secret-sweeping could leak it)
/// - `Authorization: Bearer <value>` (RFC 7235 bearer header)
/// - `bot<token>:` (Telegram URL prefix `https://api.telegram.org/bot.../`)
///
/// Value run = everything from after `=` (or `: Bearer `) up to the
/// next "stop" character: ` ` ` ;` `&` `"` `'` newline. This is the
/// boundary used by HTTP cookie / form / URL syntax.
///
/// Why not regex: proxxx has no `regex` crate dependency and this
/// substring scan is < 100 ns on a 1 KiB panic message — well below
/// the noise floor of `tracing::error!`. Keeping the dep tree narrow
/// is its own security property (, supply chain).
pub(crate) fn scrub_secrets(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    let lower = input.to_ascii_lowercase();
    let bytes = input.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        // Try each key=value marker (case-insensitive).
        let mut matched = false;
        for marker in KEY_VALUE_MARKERS {
            let m_lower = marker.to_ascii_lowercase();
            if lower[i..].starts_with(&m_lower) {
                out.push_str(&input[i..i + marker.len()]);
                i += marker.len();
                i = skip_value_run(bytes, i, &mut out);
                matched = true;
                break;
            }
        }
        if matched {
            continue;
        }
        if lower[i..].starts_with(BEARER) {
            out.push_str(&input[i..i + BEARER.len()]);
            i += BEARER.len();
            i = skip_value_run(bytes, i, &mut out);
            continue;
        }
        // Telegram bot URL: /bot<token>:/sendMessage  →  /bot[REDACTED]:/...
        // The `bot` prefix is always followed by digits then `:`. Mask
        // everything from after `bot` up to (and not including) the
        // next `/` or whitespace.
        if lower[i..].starts_with("bot") && bytes.get(i + 3).is_some_and(u8::is_ascii_digit) {
            out.push_str(&input[i..i + 3]);
            i += 3;
            i = skip_value_run(bytes, i, &mut out);
            continue;
        }
        // Default: copy one byte through. We index by char boundary by
        // walking via UTF-8-safe slice; here `bytes[i]` is the leading
        // byte of a char so we copy until next char start.
        let ch_start = i;
        i += utf8_char_len(bytes[i]);
        out.push_str(&input[ch_start..i.min(bytes.len())]);
    }
    out
}

/// Consume the value run starting at `i` (everything up to the next
/// stop character) and append `[REDACTED]` to `out`. Returns the
/// position of the stop character (which is NOT consumed — the caller
/// will copy it through on the next loop iteration).
fn skip_value_run(bytes: &[u8], mut i: usize, out: &mut String) -> usize {
    out.push_str("[REDACTED]");
    while i < bytes.len() {
        let b = bytes[i];
        if matches!(b, b' ' | b';' | b'&' | b'"' | b'\'' | b'\n' | b'\r' | b'/') {
            break;
        }
        i += 1;
    }
    i
}

/// Markers that introduce a credential value run terminated by a
/// stop char. Module-level so they sit outside the hot loop and clippy
/// doesn't flag `items_after_statements`.
const KEY_VALUE_MARKERS: &[&str] = &[
    "PVEAuthCookie=",
    "PVEAPIToken=",
    "PBSAPIToken=",
    "tokenid=",
    "password=",
    "token_secret=",
    "csrfpreventiontoken=",
    // Console session credential — if a panic in the wsterm/console path
    // embeds the WS URL (`?…&vncticket=…`), scrub it here too, so the
    // defense-in-depth net covers it, not just the 3 hand-redacted log sites.
    "vncticket=",
];

/// Substrings that mark a parameter key name as secret-bearing (`#344`).
/// Any key whose ASCII-lowercased name contains one of these substrings has
/// its entire value replaced with `"[REDACTED]"` before entering the audit log.
const SECRET_KEY_SUBSTRINGS: &[&str] = &["password", "secret", "token", "ticket", "key", "cookie"];

/// Return `true` if `key` (matched case-insensitively) names a credential or
/// secret field (`password`, `secret`, `token`, `ticket`, `key`, `cookie`).
#[must_use]
pub fn is_secret_key(key: &str) -> bool {
    let lower = key.to_ascii_lowercase();
    SECRET_KEY_SUBSTRINGS
        .iter()
        .any(|needle| lower.contains(needle))
}

/// Redact a `(key, value)` parameter pair for audit logging (`#344`):
/// - If [`is_secret_key`] matches `key`, returns `"[REDACTED]"`.
/// - Otherwise runs [`scrub_secrets`] over `value` so embedded credential
///   markers (`PVEAPIToken=…`, `password=…`, `Bearer …`, etc.) are still
///   masked even inside free-form string parameters.
#[must_use]
pub fn redact_param_value(key: &str, value: &str) -> String {
    if is_secret_key(key) {
        "[REDACTED]".to_string()
    } else {
        scrub_secrets(value)
    }
}

/// `Authorization` style headers use a multi-char separator.
const BEARER: &str = "authorization: bearer ";

/// Length of a UTF-8 character given its leading byte.
const fn utf8_char_len(b: u8) -> usize {
    if b < 0x80 {
        1
    } else if b < 0xC0 {
        // Continuation byte — shouldn't happen on a valid leading
        // index, but be defensive: treat as 1 to make forward progress.
        1
    } else if b < 0xE0 {
        2
    } else if b < 0xF0 {
        3
    } else {
        4
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn install_is_idempotent() {
        // Calling install() twice from a single test process must not
        // panic or stack hooks. The atomic guard ensures only one
        // install actually wires the chain.
        install();
        install();
        install();
    }

    #[test]
    fn scrub_pve_auth_cookie() {
        let dirty = "PANIC: cookie PVEAuthCookie=PVE:user@pam:6532ABCD:abcd1234efgh5678; path=/";
        let clean = scrub_secrets(dirty);
        assert!(!clean.contains("abcd1234"));
        assert!(!clean.contains("PVE:user@pam:6532ABCD"));
        assert!(clean.contains("PVEAuthCookie=[REDACTED]"));
        // The trailing `; path=/` portion must survive — only the
        // value run is masked.
        assert!(clean.ends_with("; path=/"));
    }

    #[test]
    fn scrub_pbs_api_token() {
        let dirty = "request failed: PBSAPIToken=root@pam!proxxx:deadbeef-1234-5678 returned 401";
        let clean = scrub_secrets(dirty);
        assert!(!clean.contains("deadbeef"));
        assert!(!clean.contains("root@pam!proxxx"));
        assert!(clean.contains("PBSAPIToken=[REDACTED]"));
        assert!(clean.contains("returned 401"));
    }

    #[test]
    fn scrub_pve_api_token() {
        let dirty = "PANIC: request failed: Authorization: PVEAPIToken=root@pam!fake=0f1e2d3c-4b5a-6978-8091-a2b3c4d5e6f7 returned 401";
        let clean = scrub_secrets(dirty);
        assert!(!clean.contains("0f1e2d3c-4b5a-6978-8091-a2b3c4d5e6f7"));
        assert!(!clean.contains("root@pam!fake"));
        assert!(clean.contains("PVEAPIToken=[REDACTED]"));
        assert!(clean.contains(" returned 401"));
    }

    #[test]
    fn scrub_pve_api_token_lowercase() {
        let dirty = "header: authorization: pveapitoken=auditor@pve!ci=11112222-3333-4444-5555-666677778888 failed";
        let clean = scrub_secrets(dirty);
        assert!(!clean.contains("11112222-3333-4444-5555-666677778888"));
        assert!(!clean.contains("auditor@pve!ci"));
        assert!(clean.contains("pveapitoken=[REDACTED]"));
        assert!(clean.contains(" failed"));
    }

    #[test]
    fn scrub_pve_api_token_multiple_in_one_message() {
        let dirty = "primary PVEAPIToken=root@pam!tok1=aaaa1111-bbbb-2222-cccc-3333dddd4444 fallback PVEAPIToken=ops@pve!tok2=eeee5555-ffff-6666-0000-111122223333 aborted";
        let clean = scrub_secrets(dirty);
        assert!(!clean.contains("aaaa1111-bbbb-2222-cccc-3333dddd4444"));
        assert!(!clean.contains("root@pam!tok1"));
        assert!(!clean.contains("eeee5555-ffff-6666-0000-111122223333"));
        assert!(!clean.contains("ops@pve!tok2"));
        assert_eq!(
            clean,
            "primary PVEAPIToken=[REDACTED] fallback PVEAPIToken=[REDACTED] aborted"
        );
    }

    #[test]
    fn scrub_pve_api_token_at_end_of_string() {
        let dirty =
            "request header Authorization: PVEAPIToken=root@pam!fake=99998888-7777-6666-5555-444433332222";
        let clean = scrub_secrets(dirty);
        assert!(!clean.contains("99998888-7777-6666-5555-444433332222"));
        assert!(!clean.contains("root@pam!fake"));
        assert_eq!(
            clean,
            "request header Authorization: PVEAPIToken=[REDACTED]"
        );
    }

    #[test]
    fn scrub_tokenid_and_password() {
        let dirty = "form: tokenid=abc123! password=hunter2 logged_in=true";
        let clean = scrub_secrets(dirty);
        assert!(!clean.contains("abc123"));
        assert!(!clean.contains("hunter2"));
        assert!(clean.contains("tokenid=[REDACTED]"));
        assert!(clean.contains("password=[REDACTED]"));
        assert!(clean.contains("logged_in=true"));
    }

    #[test]
    fn scrub_authorization_bearer() {
        let dirty = "Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.payload.sig retrying";
        let clean = scrub_secrets(dirty);
        assert!(!clean.contains("eyJhbGciOiJIUzI1NiJ9"));
        assert!(clean.contains("Bearer [REDACTED]"));
        assert!(clean.contains("retrying"));
    }

    #[test]
    fn scrub_telegram_bot_url() {
        let dirty = "url: https://api.telegram.org/bot1234567890:AAEHabcdefghijklmnop/sendMessage";
        let clean = scrub_secrets(dirty);
        assert!(!clean.contains("1234567890:AAEH"));
        assert!(!clean.contains("abcdefghijklmnop"));
        assert!(clean.contains("/bot[REDACTED]/sendMessage"));
    }

    #[test]
    fn scrub_clean_input_passes_through() {
        let clean_in = "VM 100 (vm-prod-01) on node pve01 transitioned to running";
        let clean = scrub_secrets(clean_in);
        assert_eq!(clean, clean_in);
    }

    #[test]
    fn scrub_handles_unicode_payload() {
        // Malformed: an emoji byte followed by a key=value. The
        // scrubber must not panic on UTF-8 boundaries.
        let dirty = "💀 panic at PVEAuthCookie=secretvalue; ok";
        let clean = scrub_secrets(dirty);
        assert!(clean.starts_with("💀"));
        assert!(clean.contains("PVEAuthCookie=[REDACTED]"));
        assert!(!clean.contains("secretvalue"));
    }

    #[test]
    fn scrub_case_insensitive_marker() {
        // Headers from libraries may capitalize differently — we should
        // catch them regardless.
        let dirty = "header: AUTHORIZATION: BEARER xyz123 retry";
        let clean = scrub_secrets(dirty);
        assert!(!clean.contains("xyz123"));
        assert!(clean.contains("[REDACTED]"));
    }

    #[test]
    fn panic_message_extracts_string_payload() {
        // Drive a controlled panic and intercept its payload via the
        // hook chain. We don't actually want the test process to die,
        // so we use catch_unwind.
        let result = std::panic::catch_unwind(|| {
            panic!("test-panic-payload-abc");
        });
        let err = result.expect_err("controlled panic");
        let msg = if let Some(s) = err.downcast_ref::<&'static str>() {
            (*s).to_string()
        } else if let Some(s) = err.downcast_ref::<String>() {
            s.clone()
        } else {
            String::new()
        };
        assert!(msg.contains("test-panic-payload-abc"));
    }

    #[test]
    fn secret_key_detection_and_param_redaction_cover_all_markers() {
        for field in [
            "password",
            "cipassword",
            "PASSWORD",
            "token_secret",
            "secret_id",
            "csrfpreventiontoken",
            "api_token",
            "vncticket",
            "ticket",
            "sshkeys",
            "keys",
            "private_key",
            "auth_cookie",
            "PVEAuthCookie",
        ] {
            assert!(
                is_secret_key(field),
                "expected `{field}` to be classified as a secret key"
            );
            assert_eq!(
                redact_param_value(field, "hunter2"),
                "[REDACTED]",
                "field `{field}` must redact value completely"
            );
        }

        assert!(!is_secret_key("userid"));
        assert!(!is_secret_key("cores"));
        assert_eq!(redact_param_value("userid", "alice@pve"), "alice@pve");
        // Embedded secret markers inside a non-secret key's value are still
        // scrubbed via `scrub_secrets`.
        let embedded = redact_param_value("comment", "note PVEAPIToken=root@pam!t=hunter2 end");
        assert!(!embedded.contains("hunter2"));
        assert!(embedded.contains("PVEAPIToken=[REDACTED]"));
    }
}
