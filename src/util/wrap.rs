//! Word wrapping for text printed to a terminal.
//!
//! A pre-flight risk or a fatal error is one long line; the terminal
//! breaks it at its edge, in the middle of a word (`irre` / `versible`,
//! `--allow-ris` / `k`). On a terminal these lines are wrapped between
//! words to its width, with the continuation lines indented under the
//! text. A pipe or a file gets the lines unchanged.

use std::io::IsTerminal as _;

/// The terminal width when `stream_is_terminal`, from the terminal itself
/// or `COLUMNS`; `None` otherwise (no wrapping).
#[must_use]
pub fn width_if_terminal(stream_is_terminal: bool) -> Option<usize> {
    if !stream_is_terminal {
        return None;
    }
    crossterm::terminal::size()
        .ok()
        .map(|(cols, _)| usize::from(cols))
        .filter(|w| *w >= 20)
        .or_else(|| {
            std::env::var("COLUMNS")
                .ok()
                .and_then(|c| c.parse().ok())
                .filter(|w: &usize| *w >= 20)
        })
}

/// The stderr width when stderr is a terminal.
#[must_use]
pub fn stderr_width() -> Option<usize> {
    width_if_terminal(std::io::stderr().is_terminal())
}

/// Wrap `text` to `width` columns between words. The first line starts
/// with `first`, the next ones with `indent` spaces. A word longer than
/// a line is split. Existing line breaks are kept.
#[must_use]
pub fn wrap(text: &str, width: usize, first: &str, indent: usize) -> String {
    let mut out = String::new();
    let pad = " ".repeat(indent);
    let mut prefix = first.to_string();
    for (n, para) in text.split('\n').enumerate() {
        if n > 0 {
            out.push('\n');
            prefix.clone_from(&pad);
        }
        let mut line = prefix.clone();
        let mut line_len = line.chars().count();
        let mut empty = true;
        for word in para.split(' ').filter(|w| !w.is_empty()) {
            let mut word: String = word.to_string();
            loop {
                let wlen = word.chars().count();
                let needed = wlen + usize::from(!empty);
                if line_len + needed <= width {
                    if !empty {
                        line.push(' ');
                    }
                    line.push_str(&word);
                    line_len += needed;
                    empty = false;
                    break;
                }
                if !empty {
                    out.push_str(&line);
                    out.push('\n');
                    line.clone_from(&pad);
                    line_len = indent;
                    empty = true;
                    continue;
                }
                // A word longer than the whole line: split it.
                let room = width.saturating_sub(line_len).max(1);
                let head: String = word.chars().take(room).collect();
                word = word.chars().skip(room).collect();
                line.push_str(&head);
                out.push_str(&line);
                out.push('\n');
                line.clone_from(&pad);
                line_len = indent;
                if word.is_empty() {
                    break;
                }
            }
        }
        out.push_str(&line);
    }
    out
}

/// `prefix` then `tail`, with `tail` wrapped under itself when stdout is
/// a terminal: for a fixed-column row whose last column is free text.
#[must_use]
pub fn hanging(prefix: &str, tail: &str) -> String {
    match width_if_terminal(std::io::stdout().is_terminal()) {
        Some(width) => wrap(tail, width, prefix, prefix.chars().count()),
        None => format!("{prefix}{tail}"),
    }
}

/// `eprintln!` that wraps to the terminal width when stderr is a
/// terminal; continuation lines are indented by `indent` (or by the
/// leading spaces of `line` plus `indent`).
pub fn eprint_wrapped(line: &str, indent: usize) {
    match stderr_width() {
        Some(width) => {
            let lead = line.len() - line.trim_start().len();
            let (head, rest) = line.split_at(lead);
            eprintln!("{}", wrap(rest, width, head, lead + indent));
        }
        None => eprintln!("{line}"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wraps_between_words_with_a_hanging_indent() {
        let text = "[NOTICE] no backup found on any backup-content storage of this node — destroying the guest is irreversible";
        let out = wrap(text, 60, "  ", 4);
        let lines: Vec<&str> = out.lines().collect();
        assert!(lines.len() > 1, "{out}");
        assert!(lines.iter().all(|l| l.chars().count() <= 60), "{out}");
        assert!(lines[0].starts_with("  [NOTICE]"), "{out}");
        assert!(
            lines[1].starts_with("    ") && !lines[1].starts_with("     "),
            "{out}"
        );
        assert!(out.contains("irreversible"), "a word was split: {out}");
        let rejoined: Vec<&str> = out.split_whitespace().collect();
        let original: Vec<&str> = text.split_whitespace().collect();
        assert_eq!(rejoined, original, "wrapping must not change the words");
    }

    #[test]
    fn a_word_longer_than_the_line_is_split_and_line_breaks_are_kept() {
        let out = wrap("aaaaaaaaaaaaaaaaaaaaaaaaa b\nc", 10, "", 2);
        assert!(out.lines().all(|l| l.chars().count() <= 10), "{out}");
        assert!(out.ends_with("\n  c"), "{out}");
        assert_eq!(out.replace(['\n', ' '], ""), "aaaaaaaaaaaaaaaaaaaaaaaaabc");
    }

    #[test]
    fn short_text_is_unchanged() {
        assert_eq!(wrap("hello world", 80, "", 4), "hello world");
        assert_eq!(width_if_terminal(false), None);
    }
}
