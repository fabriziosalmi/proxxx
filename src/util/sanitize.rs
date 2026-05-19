//! Display-time sanitization of user-controlled strings.
//!
//! Phase 5.13 GAP 1 — defense against ANSI escape injection via
//! Proxmox-side strings the operator does not control. A malicious
//! tenant who can rename a VM to `\x1b[2J\x1b[H<spoofed prompt>` can,
//! before this filter, repaint the operator's TUI with arbitrary
//! content (e.g. a fake confirmation dialog) at render time. Same for
//! tags and PBS backup notes.
//!
//! Approach: strip C0 control characters (0x00–0x1F) **except** TAB
//! (0x09) and DEL (0x7F). Everything that ratatui can interpret as a
//! formatting command starts with ESC (0x1B) — which falls in this
//! range — so dropping the whole class is sufficient and avoids the
//! need to ship a full ANSI parser. NL (0x0A) and CR (0x0D) are also
//! dropped because the TUI table renderer wraps on them, breaking
//! row alignment.
//!
//! Boundary chosen: render-time, not deserialize-time. The API ingest
//! layer (`api::types`) preserves the raw value so audit logs (which
//! escape via `{:?}`) capture exactly what PVE returned. The TUI
//! widgets call `sanitize_display()` at the last moment before
//! handing strings to ratatui's `Span` / `Row` / `Paragraph`.

use std::borrow::Cow;

/// Strip C0 control codes (except TAB) and DEL from a display string.
///
/// Returns `Cow::Borrowed` when the input is already safe — the hot
/// path (every guest row, every frame, ~30 Hz) does not allocate.
/// Allocates only for actually-malicious input.
pub fn sanitize_display(s: &str) -> Cow<'_, str> {
    if s.bytes().all(is_safe_byte) {
        return Cow::Borrowed(s);
    }
    Cow::Owned(s.chars().filter(|c| is_safe_char(*c)).collect())
}

#[inline]
const fn is_safe_byte(b: u8) -> bool {
    b == b'\t' || (b >= 0x20 && b != 0x7F)
}

#[inline]
const fn is_safe_char(c: char) -> bool {
    if (c as u32) < 0x80 {
        is_safe_byte(c as u8)
    } else {
        // Multi-byte UTF-8: keep. The dangerous control chars all live
        // in the ASCII range; non-ASCII letters / emoji are safe to
        // render. ratatui handles wide chars correctly.
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn passes_through_clean_ascii() {
        let s = sanitize_display("vm-prod-01");
        assert!(matches!(s, Cow::Borrowed(_)));
        assert_eq!(s, "vm-prod-01");
    }

    #[test]
    fn passes_through_unicode() {
        // Non-ASCII letters and emoji are not control sequences.
        let s = sanitize_display("プロダクション-🐧");
        assert!(matches!(s, Cow::Borrowed(_)));
        assert_eq!(s, "プロダクション-🐧");
    }

    #[test]
    fn passes_through_tab() {
        // TAB is the one C0 char we keep — table widgets handle it.
        let s = sanitize_display("col1\tcol2");
        assert!(matches!(s, Cow::Borrowed(_)));
    }

    #[test]
    fn strips_ansi_clear_screen() {
        // The classic "repaint the operator's TUI" attack: ESC[2J
        // clears, ESC[H homes the cursor. After sanitization neither
        // ESC nor the bracket-encoded payload survives, but the
        // printable noise after them is preserved (we strip the
        // control bytes, not the parameter bytes — that's fine because
        // without ESC they're inert text).
        let dirty = "vm\x1b[2J\x1b[H<fake-prompt>";
        let clean = sanitize_display(dirty);
        assert!(matches!(clean, Cow::Owned(_)));
        assert!(!clean.contains('\x1b'));
        assert_eq!(clean, "vm[2J[H<fake-prompt>");
    }

    #[test]
    fn strips_newlines_and_cr() {
        // Newlines break table row alignment — drop them.
        let dirty = "row1\nINJECTED-ROW\rmore";
        let clean = sanitize_display(dirty);
        assert_eq!(clean, "row1INJECTED-ROWmore");
    }

    #[test]
    fn strips_del_byte() {
        let dirty = "abc\x7Fdef";
        let clean = sanitize_display(dirty);
        assert_eq!(clean, "abcdef");
    }

    #[test]
    fn strips_bell_and_backspace() {
        let dirty = "name\x07\x08end";
        let clean = sanitize_display(dirty);
        assert_eq!(clean, "nameend");
    }

    #[test]
    fn empty_string_is_borrowed() {
        let s = sanitize_display("");
        assert!(matches!(s, Cow::Borrowed(_)));
        assert_eq!(s, "");
    }
}

/// Property tests — invariants that hold for ANY input string.
///
/// The example tests above pin specific known-bad payloads (the
/// ESC[2J repaint, the NL row-injection, BEL/BS/DEL). These property
/// tests pin the broader contract: for any UTF-8 input — including
/// adversarially constructed mixes the unit tests didn't think of —
/// the output never contains a dangerous C0 byte, the length never
/// grows, and the operation is idempotent.
///
/// `proptest` runs 256 cases per test by default; failures shrink to
/// the minimal counterexample. Deterministic across CI runs via the
/// `PROPTEST_CASES` env var if a regression needs reproduction.
#[cfg(test)]
mod proptests {
    use super::*;
    use proptest::prelude::*;

    proptest! {
        /// For ANY UTF-8 input, the sanitized output contains no
        /// C0 control byte (except TAB) and no DEL — the full set of
        /// bytes ratatui interprets as escape sequence prefixes.
        ///
        /// This is the security invariant: a hostile VM name like
        /// `\x1b[2J\x1b[H<spoofed>` cannot reach the renderer.
        #[test]
        fn output_has_no_unsafe_bytes(s in any::<String>()) {
            let out = sanitize_display(&s);
            for ch in out.chars() {
                let code = ch as u32;
                if code < 0x80 {
                    let b = code as u8;
                    prop_assert!(
                        b == b'\t' || (b >= 0x20 && b != 0x7F),
                        "found unsafe byte 0x{b:02X} in output {out:?}"
                    );
                }
            }
        }

        /// Idempotent: running sanitize on already-clean input is a
        /// no-op. Prevents a regression where a future filter pass
        /// might re-introduce a byte that the first pass missed.
        #[test]
        fn idempotent(s in any::<String>()) {
            let once = sanitize_display(&s).into_owned();
            let twice = sanitize_display(&once).into_owned();
            prop_assert_eq!(once, twice);
        }

        /// Sanitize never adds bytes — it can only filter. A future
        /// implementation that tries to "substitute" unsafe bytes
        /// with placeholders (e.g. `\x1b` → `^[`) would break this
        /// invariant and need an explicit policy decision.
        #[test]
        fn output_never_longer_than_input(s in any::<String>()) {
            let out = sanitize_display(&s);
            prop_assert!(out.len() <= s.len());
        }

        /// Hot-path performance contract: a string that is already
        /// safe must round-trip as `Cow::Borrowed` (no allocation,
        /// no copy). Tests the `bytes().all(is_safe_byte)` fast path
        /// at line 32.
        #[test]
        fn clean_ascii_borrows(s in "[a-zA-Z0-9 \t._-]{0,200}") {
            let out = sanitize_display(&s);
            prop_assert!(
                matches!(out, Cow::Borrowed(_)),
                "expected Borrowed for clean input {s:?}, got {out:?}"
            );
        }

        /// Specific high-risk bytes the threat model singles out
        /// (ESC, BEL, BS, NL, CR, DEL) MUST NOT appear in any output.
        /// Sub-invariant of `output_has_no_unsafe_bytes` but explicit
        /// so a regression on any single one produces a focused
        /// failure message.
        #[test]
        fn high_risk_bytes_never_survive(s in any::<String>()) {
            let out = sanitize_display(&s);
            for &b in &[0x1B, 0x07, 0x08, 0x0A, 0x0D, 0x7F] {
                let ch = char::from(b);
                prop_assert!(
                    !out.contains(ch),
                    "unsafe byte 0x{b:02X} survived in {out:?}"
                );
            }
        }

        /// Non-ASCII passthrough: every char with codepoint >= 0x80
        /// in the input also appears in the output (in order). Pins
        /// the design choice that the filter is ASCII-class only;
        /// emoji, CJK, and accented Latin must NOT be stripped.
        #[test]
        fn non_ascii_chars_preserved(s in any::<String>()) {
            let in_non_ascii: String = s.chars().filter(|c| (*c as u32) >= 0x80).collect();
            let out = sanitize_display(&s);
            let out_non_ascii: String =
                out.chars().filter(|c| (*c as u32) >= 0x80).collect();
            prop_assert_eq!(in_non_ascii, out_non_ascii);
        }
    }
}
