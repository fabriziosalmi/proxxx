//! HMAC signing for HITL Telegram `callback_data` — Phase 17 audit fix.
//!
//! ## Threat model
//!
//! Before this release, callback authentication relied entirely on the
//! TLS channel to `api.telegram.org` and the secrecy of the bot token.
//! If the bot token leaked (env-var dump, log scrape, supply-chain
//! attack on a deploy step), an attacker could:
//!
//! 1. Send arbitrary messages from the bot, including a freshly-forged
//!    inline keyboard whose `callback_data` is `approve:delete:9001`.
//! 2. Coerce or social-engineer any chat member into clicking it.
//! 3. The proxxx HITL daemon, polling its own `getUpdates`, receives
//!    the forged callback and — pre-Phase-17 — happily dispatches the
//!    PVE-side delete because the callback parsed cleanly.
//!
//! Real-CA TLS doesn't protect against this: the attacker is sending
//! messages **through** the legitimate Telegram bot, not impersonating
//! the server.
//!
//! ## What HMAC adds
//!
//! Every legitimate `callback_data` proxxx emits ends with a 16-hex-char
//! HMAC-SHA256 truncated tag computed over the canonical payload
//! prefix. The receive side verifies before consuming. An attacker
//! holding the bot token but NOT the HMAC key cannot forge a tag —
//! 2^-64 forgery probability per attempt, and Telegram itself
//! rate-limits the surface.
//!
//! The HMAC key is auto-bootstrapped on first HITL daemon start at
//! `<config_dir>/telegram_hmac.key` (32 random bytes, 0600 perms).
//! Same-file persistence is required so callbacks issued by an earlier
//! daemon process verify after a restart. The file is treated as a
//! secret on par with the bot token; rotating it invalidates every
//! pending approval in flight (which is the intended behaviour).
//!
//! ## Backward compatibility
//!
//! Callbacks issued by a v0.1.20-or-earlier daemon don't carry a tag.
//! The verifier accepts unsigned legacy callbacks for one release and
//! logs a deprecation warning — Phase 18 will flip this to "refuse
//! unsigned". This staged rollout lets in-flight approvals at upgrade
//! time still resolve instead of dying with "invalid format".

use anyhow::{Context, Result};
// hmac 0.13: `new_from_slice` lives on the `KeyInit` trait which is no
// longer re-exported via the `Mac` trait like it was in 0.12. Explicit
// import is required.
use hmac::{Hmac, KeyInit, Mac};
use sha2::Sha256;
use std::path::PathBuf;

type HmacSha256 = Hmac<Sha256>;

/// Length of the raw HMAC key on disk. 32 bytes = 256 bits = the full
/// SHA-256 block size; using less risks the wrong-length panic in
/// `Hmac::new_from_slice`.
const KEY_BYTES: usize = 32;

/// Truncate the 32-byte HMAC tag to this many raw bytes before
/// hex-encoding. The result fits comfortably under Telegram's 64-byte
/// `callback_data` cap even alongside `approve:<action>:<vmid>-<ts>`.
/// 8 bytes = 64 bits of cryptographic strength — enough given the bot
/// is rate-limited and the operator notices anomalies.
const TAG_RAW_BYTES: usize = 8;
const TAG_HEX_CHARS: usize = TAG_RAW_BYTES * 2;

/// Resolve the on-disk path for the HMAC key file. Same
/// `directories::ProjectDirs` mechanism the TLS pinning code uses
/// (Phase 13) so the layout is consistent.
pub fn hmac_key_path() -> Result<PathBuf> {
    let dirs = directories::ProjectDirs::from("dev", "proxxx", "proxxx")
        .ok_or_else(|| anyhow::anyhow!("could not resolve proxxx config dir for HMAC key"))?;
    Ok(dirs.config_dir().join("telegram_hmac.key"))
}

/// Load the HMAC key from disk, generating + persisting a fresh one
/// if the file doesn't exist.
///
/// File format: 32 raw bytes, no header, no trailer, no newline. Mode
/// 0600 on creation. If the file exists but the wrong size (corrupt /
/// truncated / partially-written from a power loss), it's overwritten
/// with a fresh key — same recovery semantics as the TLS-pin file.
///
/// On platforms without `getrandom` support (none we target), this
/// surfaces the error rather than falling back to a weaker source.
pub fn load_or_generate_hmac_key() -> Result<Vec<u8>> {
    let path = hmac_key_path()?;
    match std::fs::read(&path) {
        Ok(bytes) if bytes.len() == KEY_BYTES => return Ok(bytes),
        Ok(other) => {
            tracing::warn!(
                "HITL HMAC key at {} has wrong length ({} bytes, expected {}); regenerating",
                path.display(),
                other.len(),
                KEY_BYTES
            );
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            tracing::info!("HITL: bootstrapping HMAC key at {}", path.display());
        }
        Err(e) => {
            return Err(e).with_context(|| format!("reading HMAC key at {}", path.display()));
        }
    }
    let mut key = [0u8; KEY_BYTES];
    getrandom::getrandom(&mut key).context("getrandom failed seeding HMAC key")?;
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("creating {}", parent.display()))?;
    }
    // Atomic write via temp + rename so a crash mid-write can't leave
    // a half-key the next start would silently accept as the wrong
    // length. 0600 perms on Unix; Windows inherits the directory ACL
    // which under ProjectDirs is per-user.
    let tmp = path.with_extension("key.proxxx-hmac-tmp");
    {
        use std::io::Write;
        let mut f = std::fs::File::create(&tmp)
            .with_context(|| format!("creating tmp {}", tmp.display()))?;
        f.write_all(&key)
            .with_context(|| format!("writing tmp {}", tmp.display()))?;
        f.sync_all().ok();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mut perms = f.metadata()?.permissions();
            perms.set_mode(0o600);
            f.set_permissions(perms)?;
        }
    }
    std::fs::rename(&tmp, &path).with_context(|| format!("renaming tmp to {}", path.display()))?;
    Ok(key.to_vec())
}

/// Compute the truncated hex tag for `payload` under `key`.
///
/// Tag layout: hex-encoded first 8 bytes of HMAC-SHA256(key, payload).
/// 16 ASCII chars — fits inside Telegram's 64-byte `callback_data` cap
/// alongside the canonical prefix.
///
/// On `Hmac::new_from_slice` failure (only theoretically possible for
/// pathologically-sized keys; our generator emits a fixed 32 bytes so
/// this branch never fires in practice) returns the empty string. An
/// empty tag fails the `tag.len() == 16` gate in [`verify`], so a
/// future regression that somehow produces a bad key fails closed —
/// the daemon rejects rather than executes.
#[must_use]
pub fn sign(key: &[u8], payload: &str) -> String {
    let Ok(mut mac) = HmacSha256::new_from_slice(key) else {
        return String::new();
    };
    mac.update(payload.as_bytes());
    let bytes = mac.finalize().into_bytes();
    hex::encode(&bytes[..TAG_RAW_BYTES])
}

/// Constant-time verify that `tag_hex` is a valid signature for
/// `payload` under `key`. Returns `false` on any failure — bad hex,
/// wrong length, mismatched tag. Callers must NOT distinguish these
/// for the user (uniform "invalid" surface defeats timing oracles).
#[must_use]
pub fn verify(key: &[u8], payload: &str, tag_hex: &str) -> bool {
    if tag_hex.len() != TAG_HEX_CHARS {
        return false;
    }
    let Ok(expected) = hex::decode(tag_hex) else {
        return false;
    };
    if expected.len() != TAG_RAW_BYTES {
        return false;
    }
    let Ok(mut mac) = HmacSha256::new_from_slice(key) else {
        return false;
    };
    mac.update(payload.as_bytes());
    let full = mac.finalize().into_bytes();
    // Constant-time comparison via the `subtle`-style truncated-left
    // helper from `hmac`. We additionally pinned `expected.len() ==
    // TAG_RAW_BYTES` above so a 1-byte tag (2 hex chars, 256-way
    // forgery surface) can't trivially succeed even though
    // `verify_truncated_left` would technically accept any prefix.
    let Ok(mut verifier) = HmacSha256::new_from_slice(key) else {
        return false;
    };
    verifier.update(payload.as_bytes());
    verifier.verify_truncated_left(&expected).is_ok()
        && expected.as_slice() == &full[..TAG_RAW_BYTES]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sign_is_deterministic_for_same_payload() {
        let key = b"0123456789abcdef0123456789abcdef".to_vec();
        let a = sign(&key, "approve:start:9999-1715634000");
        let b = sign(&key, "approve:start:9999-1715634000");
        assert_eq!(a, b);
        assert_eq!(a.len(), TAG_HEX_CHARS);
    }

    #[test]
    fn sign_changes_with_payload() {
        let key = b"0123456789abcdef0123456789abcdef".to_vec();
        let a = sign(&key, "approve:start:9999-1715634000");
        let b = sign(&key, "approve:stop:9999-1715634000");
        assert_ne!(a, b, "different payload must produce different tag");
    }

    #[test]
    fn sign_changes_with_key() {
        let payload = "approve:start:9999-1715634000";
        let a = sign(b"key-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", payload);
        let b = sign(b"key-bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", payload);
        assert_ne!(a, b, "different key must produce different tag");
    }

    #[test]
    fn verify_accepts_own_signature() {
        let key = b"0123456789abcdef0123456789abcdef".to_vec();
        let payload = "approve:start:9999-1715634000";
        let tag = sign(&key, payload);
        assert!(verify(&key, payload, &tag));
    }

    #[test]
    fn verify_rejects_tampered_payload() {
        // Classic forgery attempt: attacker captures a valid
        // start-vmid-9999 tag and tries to reuse it for delete-9999.
        let key = b"0123456789abcdef0123456789abcdef".to_vec();
        let tag = sign(&key, "approve:start:9999-1715634000");
        assert!(!verify(&key, "approve:delete:9999-1715634000", &tag));
    }

    #[test]
    fn verify_rejects_tampered_tag() {
        let key = b"0123456789abcdef0123456789abcdef".to_vec();
        let payload = "approve:start:9999-1715634000";
        let mut tag = sign(&key, payload);
        // Flip the last hex digit.
        let last = tag.pop().expect("tag non-empty");
        let flipped = if last == 'a' { 'b' } else { 'a' };
        tag.push(flipped);
        assert!(!verify(&key, payload, &tag));
    }

    #[test]
    fn verify_rejects_wrong_length_tag() {
        let key = b"0123456789abcdef0123456789abcdef".to_vec();
        let payload = "approve:start:9999-1715634000";
        // 14 hex chars instead of 16 — short tag must reject regardless
        // of whether the prefix happens to match. Defends against
        // forgery via byte-truncation.
        let short = &sign(&key, payload)[..14];
        assert!(!verify(&key, payload, short));
    }

    #[test]
    fn verify_rejects_non_hex_tag() {
        let key = b"0123456789abcdef0123456789abcdef".to_vec();
        let payload = "approve:start:9999-1715634000";
        // Right length, but not hex.
        assert!(!verify(&key, payload, "ZZZZZZZZZZZZZZZZ"));
    }

    #[test]
    fn verify_rejects_with_wrong_key() {
        let key_a = b"0123456789abcdef0123456789abcdef".to_vec();
        let key_b = b"fedcba9876543210fedcba9876543210".to_vec();
        let payload = "approve:start:9999-1715634000";
        let tag = sign(&key_a, payload);
        assert!(
            !verify(&key_b, payload, &tag),
            "tag signed with key_a must NOT verify under key_b — this is the bot-token-leak defence"
        );
    }

    /// Tag-length budget against Telegram's 64-byte `callback_data` cap.
    /// Worst-case: `approve:` + `restart:` + 5-digit vmid + `-` +
    /// 13-digit millis + `:` + 16-char tag = 49. Locks the budget so a
    /// future change to the tag length can't silently overflow.
    #[test]
    fn telegram_callback_data_budget_holds() {
        let key = b"0123456789abcdef0123456789abcdef".to_vec();
        let payload = "approve:restart:99999-1715634000000";
        let tag = sign(&key, payload);
        let full = format!("{payload}:{tag}");
        assert!(
            full.len() <= 64,
            "callback_data exceeded Telegram's 64-byte cap: {} bytes",
            full.len()
        );
    }
}
