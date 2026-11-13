//! `--format table` for a person at a terminal.
//!
//! The table format is a TSV: the right shape for `cut` and `awk`, the
//! wrong one for a reader. On a terminal its columns do not line up, a
//! row longer than the screen breaks mid-word, timestamps are epoch
//! seconds and sizes are bytes; 26 of 50 read commands printed that way
//! on the lab (`doctor`, `tasks`, `cluster-log`, `config`, ...). When
//! stdout is a terminal, [`render`] prints the same data aligned to the
//! screen width instead:
//!
//! - an array of objects is a table; identity columns (vmid, name,
//!   node, ...) come first and free text (message, description, upid,
//!   ...) last, the last column wraps and the others are shortened with
//!   `…` when the row does not fit;
//! - an object is `key  value` lines, values wrapped under themselves,
//!   followed by a table per field that holds an array of objects;
//! - epoch timestamps read as local time, byte counts as `human_bytes`,
//!   uptimes as `human_uptime`, CPU fractions as percentages.
//!
//! A pipe, a file and the other formats keep their output byte for byte.

use serde_json::Value;

use crate::util::color::{self, Line, Paint};
use crate::util::format::{human_bytes, human_uptime, safe_text};
use crate::util::wrap::wrap;

/// Columns shown first, in this order, when present.
const LEADING: &[&str] = &[
    "vmid", "id", "name", "node", "storage", "check", "kind", "type", "status", "state",
];

/// Free-text columns, shown last (the last one wraps).
const TRAILING: &[&str] = &[
    "content",
    "comment",
    "description",
    "notes",
    "detail",
    "reason",
    "error",
    "message",
    "msg",
    "url",
    "digest",
    "fingerprint",
    "parameters",
    "upid",
];

/// Keys whose integer value is a Unix timestamp.
const TIME_KEYS: &[&str] = &[
    "time",
    "starttime",
    "endtime",
    "ctime",
    "mtime",
    "timestamp",
    "backup-time",
    "last_run",
    "next_run",
    "frozen_at",
];

/// Keys whose integer value is a byte count.
const BYTE_KEYS: &[&str] = &[
    "size",
    "maxdisk",
    "maxmem",
    "mem",
    "disk",
    "used",
    "avail",
    "total",
    "netin",
    "netout",
    "diskread",
    "diskwrite",
    "free",
];

/// The narrowest a non-last column is shortened to before giving up.
const MIN_COL: usize = 10;

/// Render `data` for a terminal `width` columns wide.
#[must_use]
pub fn render(data: &Value, width: usize, color: bool) -> String {
    match data {
        Value::Array(items) => table(items, width, color),
        Value::Object(map) => object(map, width, color),
        other => format!("{}\n", safe_text(&scalar(other))),
    }
}

/// A scalar as text: strings bare, `null` as `-`, arrays of scalars
/// comma-joined, anything else compact JSON.
fn scalar(v: &Value) -> String {
    match v {
        Value::String(s) => s.clone(),
        Value::Null => "-".to_string(),
        Value::Array(items) if items.iter().all(|i| !i.is_object() && !i.is_array()) => {
            if items.is_empty() {
                "-".to_string()
            } else {
                items.iter().map(scalar).collect::<Vec<_>>().join(", ")
            }
        }
        other => other.to_string(),
    }
}

/// A value as a reader sees it, given the key it sits under.
fn humanize(key: &str, v: &Value) -> String {
    let key = key.rsplit('.').next().unwrap_or(key).to_ascii_lowercase();
    if let Some(n) = v.as_u64() {
        if TIME_KEYS.contains(&key.as_str()) && (1_000_000_000..10_000_000_000).contains(&n) {
            return local_time(n);
        }
        if BYTE_KEYS.contains(&key.as_str()) {
            return human_bytes(n);
        }
        if key == "uptime" {
            return if n == 0 {
                "-".to_string()
            } else {
                human_uptime(n)
            };
        }
    }
    if key == "cpu" {
        if let Some(f) = v.as_f64() {
            if v.is_f64() && (0.0..=1.0).contains(&f) {
                return format!("{:.0}%", f * 100.0);
            }
        }
    }
    let text = scalar(v);
    if key == "content" {
        return text.replace(',', ", ");
    }
    text
}

/// `YYYY-MM-DD HH:MM` in the local time zone.
fn local_time(epoch: u64) -> String {
    use chrono::TimeZone as _;
    i64::try_from(epoch)
        .ok()
        .and_then(|e| chrono::Local.timestamp_opt(e, 0).single())
        .map_or_else(
            || epoch.to_string(),
            |t| t.format("%Y-%m-%d %H:%M").to_string(),
        )
}

/// Where a column sorts: leading ones by their place, then the rest by
/// name, then the free-text ones by their place.
fn rank(header: &str) -> (u8, usize, String) {
    let h = header.to_ascii_lowercase();
    if let Some(i) = LEADING.iter().position(|k| *k == h) {
        (0, i, String::new())
    } else if let Some(i) = TRAILING.iter().position(|k| *k == h) {
        (2, i, String::new())
    } else {
        (1, 0, h)
    }
}

/// Column headers and the path to each value, as the TSV builds them
/// (nested objects as `key.sub`, the fanout `data` envelope flattened),
/// in reading order.
fn columns(items: &[Value]) -> Vec<(String, Vec<String>)> {
    let mut cols = crate::util::format::table_columns(items)
        .into_iter()
        .collect::<Vec<_>>();
    cols.sort_by_key(|(h, _)| rank(h));
    cols
}

fn cell_value<'a>(item: &'a serde_json::Map<String, Value>, path: &[String]) -> Option<&'a Value> {
    let mut v = item.get(path.first()?)?;
    if let Some(sub) = path.get(1) {
        v = v.get(sub)?;
    }
    Some(v)
}

fn truncate(s: &str, width: usize) -> String {
    if s.chars().count() <= width {
        return s.to_string();
    }
    let mut out: String = s.chars().take(width.saturating_sub(1)).collect();
    out.push('…');
    out
}

/// Columns left out first when a table does not fit: identifiers and
/// hashes a reader rarely needs on screen (`--format json` has them).
const NOISE: &[&str] = &[
    "digest",
    "fingerprint",
    "upid",
    "parameters",
    "checksum.digest",
    "checksum.algo",
    "url",
    "wwn",
];

fn is_time_col(header: &str) -> bool {
    let key = header
        .rsplit('.')
        .next()
        .unwrap_or(header)
        .to_ascii_lowercase();
    TIME_KEYS.contains(&key.as_str())
}

/// The narrowest a column is shortened to: a timestamp keeps its 16
/// characters, anything else `MIN_COL`, never more than its widest value.
fn min_width(header: &str, natural: usize) -> usize {
    natural.min(if is_time_col(header) { 16 } else { MIN_COL })
}

/// Which columns to show in `width` columns. Columns empty in every row
/// go first; then, while even the narrowest layout is too wide, the
/// `NOISE` columns, then the ordinary ones from the right. The leading
/// columns (vmid, name, node, ...) and a free-text last column stay.
/// Returns the kept indices and the hidden headers.
fn choose_columns(
    cols: &[(String, Vec<String>)],
    rows: &[Vec<String>],
    natural: &[usize],
    width: usize,
) -> (Vec<usize>, Vec<String>) {
    let mut keep: Vec<usize> = (0..cols.len())
        .filter(|&c| {
            rows.iter()
                .any(|r| r.get(c).is_some_and(|v| !matches!(v.as_str(), "" | "-")))
        })
        .collect();
    if keep.is_empty() {
        keep = (0..cols.len()).collect();
    }
    let header = |c: usize| cols.get(c).map_or("", |(h, _)| h.as_str());
    let nat = |c: usize| natural.get(c).copied().unwrap_or(0);
    let narrowest = |keep: &[usize]| -> usize {
        let n = keep.len();
        keep.iter()
            .enumerate()
            .map(|(i, &c)| {
                if i + 1 == n {
                    nat(c).min(24)
                } else {
                    min_width(header(c), nat(c))
                }
            })
            .sum::<usize>()
            + 2 * n.saturating_sub(1)
    };
    let mut hidden = Vec::new();
    while keep.len() > 1 && narrowest(&keep) > width {
        let noise = keep
            .iter()
            .enumerate()
            .filter(|(_, &c)| NOISE.contains(&header(c).to_ascii_lowercase().as_str()))
            .min_by_key(|(_, &c)| {
                NOISE
                    .iter()
                    .position(|k| *k == header(c).to_ascii_lowercase())
            })
            .map(|(pos, _)| pos);
        let ordinary = || {
            keep.iter()
                .enumerate()
                .take(keep.len() - 1)
                .rev()
                .find(|(_, &c)| rank(header(c)).0 == 1)
                .map(|(pos, _)| pos)
        };
        let Some(pos) = noise.or_else(ordinary) else {
            break;
        };
        hidden.push(header(keep.remove(pos)).to_uppercase());
    }
    (keep, hidden)
}

/// Fit the column widths to `width`: the last column keeps up to 24
/// (it wraps); while the row is wider than the screen, the widest other
/// column is shortened, down to its minimum. The last column then gets
/// what is left.
fn fit(widths: &mut [usize], mins: &[usize], width: usize) {
    let n = widths.len();
    let last_natural = widths.last().copied().unwrap_or(0);
    let last_floor = last_natural.min(24);
    let rest =
        |w: &[usize]| w.iter().take(n.saturating_sub(1)).sum::<usize>() + 2 * n.saturating_sub(1);
    while rest(widths) + last_floor > width {
        let Some(i) = widths
            .iter()
            .enumerate()
            .take(n.saturating_sub(1))
            .filter(|(i, w)| **w > mins.get(*i).copied().unwrap_or(MIN_COL))
            .max_by_key(|(_, w)| **w)
            .map(|(i, _)| i)
        else {
            break;
        };
        if let Some(w) = widths.get_mut(i) {
            *w -= 1;
        }
    }
    let room = width.saturating_sub(rest(widths));
    if let Some(last) = widths.last_mut() {
        *last = last_natural.min(room.max(last_natural.min(MIN_COL)));
    }
}

/// The header and the rows, padded to `widths`; the last column wraps
/// under itself, the others are shortened with `…`.
fn draw_rows(
    headers: &[String],
    rows: &[Vec<String>],
    widths: &[usize],
    status_col: Option<usize>,
    color: bool,
) -> String {
    let n = widths.len();
    let indent: usize =
        widths.iter().take(n.saturating_sub(1)).sum::<usize>() + 2 * n.saturating_sub(1);
    let mut out = String::new();
    let mut header = Line::new();
    for (i, (h, w)) in headers.iter().zip(widths).enumerate() {
        let sep = if i == 0 { "" } else { "  " };
        // The last column is not padded: with colour on, trailing spaces
        // sit before the reset code and `trim_end` cannot remove them.
        let text = if i + 1 == n {
            truncate(h, *w)
        } else {
            format!("{:<w$}", truncate(h, *w))
        };
        header = header.paint(format!("{sep}{text}"), Some(Paint::Dim));
    }
    out.push_str(header.render(color).trim_end());
    out.push('\n');
    for row in rows {
        let mut line = Line::new();
        let mut tail: Vec<String> = Vec::new();
        for (i, (cell, w)) in row.iter().zip(widths).enumerate() {
            if i > 0 {
                line = line.plain("  ");
            }
            let shown = if i + 1 == n {
                let wrapped = wrap(cell, *w, "", 0);
                let mut parts = wrapped.split('\n').map(str::to_string);
                let first = parts.next().unwrap_or_default();
                tail = parts.collect();
                first
            } else {
                truncate(cell, *w)
            };
            let padded = if i + 1 == n {
                shown
            } else {
                format!("{shown:<w$}")
            };
            let paint = if Some(i) == status_col {
                color::status_word(cell)
            } else {
                None
            };
            line = line.paint(padded, paint);
        }
        out.push_str(line.render(color).trim_end());
        out.push('\n');
        for t in tail {
            out.push_str(format!("{}{t}", " ".repeat(indent)).trim_end());
            out.push('\n');
        }
    }
    out
}

fn table(items: &[Value], width: usize, color: bool) -> String {
    if items.is_empty() {
        return "(no results)\n".to_string();
    }
    if !items.iter().any(Value::is_object) {
        let mut out = String::new();
        for i in items {
            out.push_str(&safe_text(&scalar(i)));
            out.push('\n');
        }
        return out;
    }
    let all_cols = columns(items);
    let all_rows: Vec<Vec<String>> = items
        .iter()
        .filter_map(Value::as_object)
        .map(|item| {
            all_cols
                .iter()
                .map(|(header, path)| {
                    let text = cell_value(item, path)
                        .map_or_else(|| "-".to_string(), |v| humanize(header, v));
                    // One line per cell; the TSV escapes breaks as `\n`.
                    safe_text(&text.replace(['\n', '\r', '\t'], " "))
                })
                .collect()
        })
        .collect();
    let natural: Vec<usize> = (0..all_cols.len())
        .map(|c| {
            all_rows
                .iter()
                .filter_map(|r| r.get(c))
                .map(|v| v.chars().count())
                .chain(all_cols.get(c).map(|(h, _)| h.chars().count()))
                .max()
                .unwrap_or(0)
        })
        .collect();
    let (keep, hidden) = choose_columns(&all_cols, &all_rows, &natural, width);
    let cols: Vec<&(String, Vec<String>)> = keep.iter().filter_map(|&c| all_cols.get(c)).collect();
    let rows: Vec<Vec<String>> = all_rows
        .iter()
        .map(|r| keep.iter().filter_map(|&c| r.get(c).cloned()).collect())
        .collect();
    let headers: Vec<String> = cols.iter().map(|(h, _)| h.to_uppercase()).collect();
    let mut widths: Vec<usize> = keep
        .iter()
        .map(|&c| natural.get(c).copied().unwrap_or(0))
        .collect();
    let mins: Vec<usize> = cols
        .iter()
        .zip(&widths)
        .map(|((h, _), w)| min_width(h, *w))
        .collect();
    fit(&mut widths, &mins, width);
    let status_col = cols
        .iter()
        .position(|(h, _)| h.eq_ignore_ascii_case("status"));

    let mut out = draw_rows(&headers, &rows, &widths, status_col, color);
    if !hidden.is_empty() {
        let note = format!(
            "(not shown to fit the width: {}; --format json has every column)",
            hidden.join(", ")
        );
        out.push_str(
            &Line::new()
                .paint(wrap(&note, width, "", 0), Some(Paint::Dim))
                .render(color),
        );
        out.push('\n');
    }
    out
}

fn object(map: &serde_json::Map<String, Value>, width: usize, color: bool) -> String {
    let mut pairs: Vec<(String, String)> = Vec::new();
    let mut sections = String::new();
    // `metrics`: its help promises a sparkline and a summary; the
    // per-sample `points` (60 rows, all `-` for a stopped guest) are for
    // scripts, so a terminal gets their count instead.
    let is_metrics = map.contains_key("sparkline") && map.contains_key("points");
    for (key, value) in map {
        if is_metrics && key == "points" {
            let samples = value.as_array().map_or(0, |p| {
                p.iter()
                    .filter(|x| x.get("value").is_some_and(|v| !v.is_null()))
                    .count()
            });
            pairs.push((
                "points".to_string(),
                format!("{samples} samples (the series is in --format json)"),
            ));
            continue;
        }
        if is_metrics && key == "sparkline" && value.as_str().is_some_and(str::is_empty) {
            pairs.push((
                "sparkline".to_string(),
                "no samples in this window".to_string(),
            ));
            continue;
        }
        match value {
            Value::Array(items) if items.iter().any(Value::is_object) => {
                sections.push('\n');
                sections.push_str(
                    &Line::new()
                        .paint(key.to_uppercase(), Some(Paint::Dim))
                        .render(color),
                );
                sections.push('\n');
                sections.push_str(&table(items, width, color));
            }
            Value::Object(inner) if !inner.is_empty() => {
                for (sub, v) in inner {
                    pairs.push((format!("{key}.{sub}"), humanize(sub, v)));
                }
            }
            other => pairs.push((key.clone(), humanize(key, other))),
        }
    }
    let key_w = pairs
        .iter()
        .map(|(k, _)| k.chars().count())
        .max()
        .unwrap_or(0)
        .min(28);
    let value_w = width.saturating_sub(key_w + 2).max(MIN_COL);
    let mut out = String::new();
    for (k, v) in &pairs {
        let v = safe_text(&v.replace(['\r', '\t'], " "));
        let wrapped = wrap(&v, value_w, "", 0);
        let mut lines = wrapped.split('\n');
        let first = lines.next().unwrap_or_default();
        let key = Line::new()
            .paint(
                format!("{:<key_w$}", truncate(&safe_text(k), key_w)),
                Some(Paint::Dim),
            )
            .render(color);
        out.push_str(format!("{key}  {first}").trim_end());
        out.push('\n');
        for l in lines {
            out.push_str(format!("{}{l}", " ".repeat(key_w + 2)).trim_end());
            out.push('\n');
        }
    }
    out.push_str(&sections);
    out
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::indexing_slicing)]
mod tests {
    use super::*;
    use serde_json::json;

    fn widest(s: &str) -> usize {
        s.lines().map(|l| l.chars().count()).max().unwrap_or(0)
    }

    /// `doctor` on the lab: the status sat after a long message, so it
    /// started at a different column on each row. It now comes right
    /// after the check, and the message wraps under itself.
    #[test]
    fn a_table_puts_status_before_free_text_and_fits_the_width() {
        let data = json!([
            {"check": "config", "status": "ok", "message": "config.toml parsed — profile url: https://192.0.2.10:8006"},
            {"check": "tls", "status": "warn", "message": "verify_tls = false — TLS cert not validated (ok for homelab, not for production)"},
        ]);
        let out = render(&data, 60, false);
        let lines: Vec<&str> = out.lines().collect();
        assert!(lines[0].starts_with("CHECK"), "{out}");
        let s = lines[0].find("STATUS").unwrap();
        let m = lines[0].find("MESSAGE").unwrap();
        assert!(s < m, "status before message: {out}");
        assert!(widest(&out) <= 60, "wider than 60:\n{out}");
        assert!(
            out.contains("production)"),
            "the message must be complete:\n{out}"
        );
        assert!(!out.contains('\t'), "no tabs on a terminal:\n{out}");
    }

    #[test]
    fn epoch_bytes_uptime_and_cpu_read_like_the_web_ui() {
        let data = json!([{"starttime": 1_794_469_568_u64, "size": 137_438_953_472_u64, "uptime": 2_800_000, "cpu": 0.0536, "vmid": 7777}]);
        let out = render(&data, 120, false);
        assert!(!out.contains("1794469568"), "{out}");
        assert!(out.contains("2026-11-"), "{out}");
        assert!(out.contains("128.0G"), "{out}");
        assert!(out.contains("32d"), "{out}");
        assert!(out.contains("5%"), "{out}");
    }

    #[test]
    fn an_object_is_aligned_key_value_lines_with_tables_after() {
        let data = json!({
            "release": "9.1",
            "message": "There is no subscription key and this sentence is long enough to wrap at forty columns",
            "tools": [{"name": "list_nodes", "destructive": false}],
        });
        let out = render(&data, 40, false);
        assert!(out.starts_with("message  There is no"), "{out}");
        assert!(widest(&out) <= 40, "{out}");
        assert!(
            out.contains("\n         "),
            "continuation indented under the value:\n{out}"
        );
        assert!(out.contains("\nTOOLS\nNAME"), "{out}");
    }

    /// `metrics ct 7777` on a stopped guest printed 60 rows of `-`.
    #[test]
    fn metrics_show_the_sparkline_and_a_sample_count_not_every_point() {
        let points: Vec<Value> = (0..60)
            .map(|i| json!({"time": 1_794_513_300 + i * 60, "value": null}))
            .collect();
        let data = json!({"label": "LXC 7777", "field": "cpu", "sparkline": "", "summary": null, "points": points});
        let out = render(&data, 80, false);
        assert!(out.lines().count() < 8, "{out}");
        assert!(out.contains("no samples in this window"), "{out}");
        assert!(out.contains("0 samples"), "{out}");
    }

    /// `tasks` on 80 columns: eight columns plus a 60-character UPID did
    /// not fit even shortened, and the terminal broke every row. Empty
    /// columns go, then the noise ones, and the reader is told which.
    #[test]
    fn a_table_too_wide_drops_empty_and_noise_columns_and_says_so() {
        let data = json!([
            {"endtime": 1_794_469_572_u64, "id": "7777", "node": "pve-test-1", "starttime": 1_794_469_568_u64,
             "status": "OK", "type": "vzshutdown", "user": "root@pam", "lock": "",
             "upid": "UPID:pve-test-1:003EEBE5:10E3A8BD:6AF56EC0:vzshutdown:7777:root@pam!token:"},
        ]);
        let out = render(&data, 80, false);
        assert!(widest(&out) <= 80, "wider than 80:\n{out}");
        assert!(
            !out.contains("LOCK"),
            "an empty column is not shown:\n{out}"
        );
        assert!(!out.contains("UPID:pve"), "the UPID goes first:\n{out}");
        assert!(out.contains("not shown to fit the width: UPID"), "{out}");
        assert!(out.contains("2026-11-"), "times keep their width:\n{out}");
        assert!(!out.contains("2026-11-1…"), "a time is not cut:\n{out}");
    }

    /// When columns are shortened to fit, a long name gives way before a
    /// timestamp is cut to `2026-11-1…`.
    #[test]
    fn a_timestamp_keeps_its_width_while_other_columns_shrink() {
        let data = json!([{"name": "n".repeat(30), "time": 1_794_469_568_u64, "msg": "a message long enough to wrap twice here"}]);
        let out = render(&data, 56, false);
        assert!(widest(&out) <= 56, "{out}");
        let row = out.lines().nth(1).unwrap_or_default();
        let at = row.find("2026-").expect("time shown");
        let time: String = row[at..].chars().take(16).collect();
        assert!(!time.contains('…') && time.contains(':'), "time cut: {row}");
    }

    /// With colour on, no line ends in spaces before a reset code.
    #[test]
    fn coloured_lines_carry_no_trailing_padding() {
        let data = json!([{"vmid": 7777, "status": "error", "message": "short"}, {"vmid": 1, "status": "ok", "message": "a much longer message here"}]);
        let out = render(&data, 80, true);
        for line in out.lines() {
            let plain = line.replace("\u{1b}[0m", "").replace("\u{1b}[2m", "");
            assert_eq!(plain.trim_end(), plain, "trailing spaces: {line:?}");
        }
    }

    #[test]
    fn a_long_middle_column_is_shortened_with_an_ellipsis() {
        let data = json!([{"name": "x".repeat(80), "node": "pve1", "message": "short"}]);
        let out = render(&data, 50, false);
        assert!(widest(&out) <= 50, "{out}");
        assert!(out.contains('…'), "{out}");
    }
}
