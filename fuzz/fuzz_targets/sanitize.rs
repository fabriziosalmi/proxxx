//! Cluster strings (guest names, notes, journal lines) reach the terminal
//! through `sanitize_display` and `safe_text`. No C0 control except TAB,
//! no DEL and no C1 control may survive; the result keeps the input's
//! other characters in order; sanitizing twice changes nothing.
#![no_main]

use libfuzzer_sys::fuzz_target;
use proxxx::util::format::safe_text;
use proxxx::util::sanitize::{sanitize_display, truncate_ellipsis};

fn unsafe_char(c: char) -> bool {
    let u = c as u32;
    (u < 0x20 && c != '\t') || u == 0x7F || (0x80..=0x9F).contains(&u)
}

fuzz_target!(|data: &[u8]| {
    let Ok(s) = std::str::from_utf8(data) else {
        return;
    };
    let out = sanitize_display(s);
    assert!(
        !out.chars().any(unsafe_char),
        "unsafe char survived: {out:?}"
    );
    let kept: String = s.chars().filter(|c| !unsafe_char(*c)).collect();
    assert_eq!(
        out.as_ref(),
        kept,
        "sanitize_display must only drop unsafe chars"
    );
    assert_eq!(
        sanitize_display(&out),
        out,
        "sanitize_display must be idempotent"
    );

    let text = safe_text(s);
    assert!(
        !text.chars().any(|c| c != '\n' && unsafe_char(c)),
        "unsafe char survived safe_text: {text:?}"
    );
    assert_eq!(
        text.matches('\n').count(),
        s.matches('\n').count(),
        "safe_text keeps the line breaks"
    );

    let max = usize::from(data.first().copied().unwrap_or(0));
    let t = truncate_ellipsis(s, max);
    assert!(
        t.chars().count() <= max + 1,
        "truncate_ellipsis overran {max}"
    );
    if s.chars().count() <= max {
        assert_eq!(t, s);
    }
});
