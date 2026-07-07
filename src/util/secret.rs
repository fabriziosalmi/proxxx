//! `SecretString` — a heap string whose redaction is a property of the
//! type, not of the call sites that happen to remember it is sensitive.
//!
//! The v0.13.1 console-ticket fix gave `WsTarget` a hand-written
//! redacting `Debug` (src/wsterm/url.rs) after a `{:?}` at any log site
//! could have printed a live `vncticket`. Every other secret-bearing
//! struct (`AuthMethod`, `ProfileConfig`, `PbsConfig`, `TelegramConfig`)
//! still derived `Debug` over its `Zeroizing<String>` fields — and
//! `Zeroizing<T>` delegates `Debug` to the inner `T`, so a derived
//! `{:?}` prints the actual token/ticket/password. No call site logs
//! them today; this type makes sure none ever can.
//!
//! Guarantees, in order of importance:
//! 1. **`Debug` prints `[REDACTED]`** — never the value, never its length.
//! 2. **Zeroize-on-drop for the wrapped value** — heap bytes are
//!    overwritten when the value is dropped or replaced (inherited from
//!    [`Zeroizing`]). Note this covers the value *once constructed*, not
//!    the temporaries that produced it: `std::env::var`, the config-file
//!    `String`, and the `toml::Value` parse tree still hold unwiped
//!    plaintext copies of any inline secret until config load completes.
//!    Wiping those end-to-end is out of reach given serde/toml internals;
//!    the guarantee here is the wrapped value's drop, plus a redacted
//!    `Debug` so those copies can't be re-emitted through a log.
//! 3. **No `Display`** — `format!("{secret}")` is a compile error; the
//!    only way to reach the bytes is an explicit [`SecretString::expose`]
//!    (or the `Deref<Target = str>` it is built on), which greps cleanly.
//! 4. **No `Serialize`** — a `SecretString` can never ride a state
//!    export / JSON dump by accident (compile error). This is the same
//!    posture the frozen secret-ref design (issue #178) will inherit.
//!
//! Equality is a derived byte compare, NOT constant-time — it exists for
//! tests and config plumbing. Anything auth-shaped must keep using its
//! own constant-time gate (see `token_gate` in `src/mcp/http_server.rs`).

use zeroize::Zeroizing;

pub struct SecretString(Zeroizing<String>);

impl SecretString {
    #[must_use]
    pub fn new(value: String) -> Self {
        Self(Zeroizing::new(value))
    }

    /// Explicit access to the secret bytes. Prefer this over deref at
    /// boundaries where the secret leaves the process (HTTP headers,
    /// URLs) so the sites are grep-able: `grep -rn '\.expose()'`.
    #[must_use]
    pub fn expose(&self) -> &str {
        &self.0
    }

    /// `&str` view, mirroring `String::as_str` — used by `Option`
    /// plumbing like `.map(SecretString::as_str)`.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::ops::Deref for SecretString {
    type Target = str;
    fn deref(&self) -> &str {
        &self.0
    }
}

// The whole point of the type: `{:?}` can never print the value. No
// length either — "[REDACTED:43]" would leak which credential class it
// is (PVE token vs Telegram bot token differ visibly in length).
impl std::fmt::Debug for SecretString {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("[REDACTED]")
    }
}

impl Clone for SecretString {
    fn clone(&self) -> Self {
        Self(self.0.clone())
    }
}

impl PartialEq for SecretString {
    fn eq(&self, other: &Self) -> bool {
        *self.0 == *other.0
    }
}
impl Eq for SecretString {}

impl From<String> for SecretString {
    fn from(value: String) -> Self {
        Self::new(value)
    }
}

impl From<&str> for SecretString {
    fn from(value: &str) -> Self {
        Self::new(value.to_string())
    }
}

impl From<Zeroizing<String>> for SecretString {
    fn from(value: Zeroizing<String>) -> Self {
        Self(value)
    }
}

impl zeroize::Zeroize for SecretString {
    fn zeroize(&mut self) {
        self.0.zeroize();
    }
}

// Marker: honest because the only field is a `Zeroizing`, which wipes
// itself on drop. Lets tests statically assert the drop guarantee.
impl zeroize::ZeroizeOnDrop for SecretString {}

// Deserialize only. The final `String` is moved into the `Zeroizing`
// without an extra allocation — but the surrounding config-file `String`
// and the TOML parser's `Value` tree still hold unwiped secret bytes
// until load completes (see the module-level note on guarantee #2); this
// only wraps the value once it exists.
impl<'de> serde::Deserialize<'de> for SecretString {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        String::deserialize(deserializer).map(Self::new)
    }
}

// NOTE: deliberately NO `Display` and NO `Serialize` — see module docs.

#[cfg(test)]
mod tests {
    use super::*;

    const SENTINEL: &str = "s3cr3t-sentinel-XyZ";

    #[test]
    fn debug_is_redacted_plain_and_pretty() {
        let s = SecretString::from(SENTINEL);
        let plain = format!("{s:?}");
        let pretty = format!("{s:#?}");
        assert_eq!(plain, "[REDACTED]");
        assert_eq!(pretty, "[REDACTED]");
        assert!(!plain.contains(SENTINEL));
        // No length leak: same output for a different-length secret.
        assert_eq!(format!("{:?}", SecretString::from("x")), plain);
    }

    #[test]
    fn value_survives_clone_and_deref() {
        let s = SecretString::from(SENTINEL);
        let c = s.clone();
        assert_eq!(s.expose(), SENTINEL);
        assert_eq!(c.as_str(), SENTINEL);
        assert_eq!(&*c, SENTINEL);
        assert_eq!(s, c);
        assert!(!s.is_empty()); // str methods via Deref
    }

    #[test]
    fn deserializes_from_toml_string() {
        #[derive(serde::Deserialize)]
        struct Holder {
            secret: SecretString,
        }
        let h: Holder = toml::from_str(&format!("secret = \"{SENTINEL}\"")).expect("parse");
        assert_eq!(h.secret.expose(), SENTINEL);
        // ...and the holder's derived Debug would still be safe:
        assert_eq!(format!("{:?}", h.secret), "[REDACTED]");
    }

    #[test]
    fn statically_zeroize_on_drop() {
        fn assert_zod<T: zeroize::ZeroizeOnDrop>() {}
        assert_zod::<SecretString>();
    }
}
