use anyhow::Result;
use clap::ValueEnum;
use serde_json::Value;

#[derive(Debug, Clone, Copy, ValueEnum)]
pub enum OutputFormat {
    Json,
    /// JSON wrapped in a envelope carrying the producing version
    /// (audit 2026-09-09, #284).
    ///
    /// `--format json` emits the payload verbatim and always has, so a
    /// script cannot tell from the output which contract produced it.
    /// The additive-only promise protects a caller that keeps working
    /// against a newer proxxx; it does not help one that must work
    /// against several versions at once — a CI fleet mid-rollout, or a
    /// wrapper supporting the last two releases. Those had to shell out
    /// to `proxxx --version` and maintain their own mapping.
    ///
    /// A separate format rather than a change to `json`, because
    /// changing the existing one would break every parser that reads it
    /// today — which is exactly the compatibility problem being solved.
    JsonEnvelope,
    Table,
    Plain,
}

/// Wrap a JSON value in the `json-envelope` top-level object
/// (`{"proxxx": "<version>", "data": ...}`).
#[must_use]
pub fn wrap_json_envelope(data: &Value) -> Value {
    serde_json::json!({
        "proxxx": env!("CARGO_PKG_VERSION"),
        "data": data,
    })
}

/// Format a JSON payload according to `format` (`Json` -> pretty payload;
/// `JsonEnvelope` -> pretty `{"proxxx": "<version>", "data": payload}`).
pub fn render_json_output(data: &Value, format: OutputFormat) -> Result<String> {
    match format {
        OutputFormat::JsonEnvelope => Ok(serde_json::to_string_pretty(&wrap_json_envelope(data))?),
        OutputFormat::Json | OutputFormat::Table | OutputFormat::Plain => {
            Ok(serde_json::to_string_pretty(data)?)
        }
    }
}

/// Print data in the requested format to stdout
pub fn print(data: &Value, format: OutputFormat) -> Result<()> {
    match format {
        OutputFormat::Json | OutputFormat::JsonEnvelope => {
            println!("{}", render_json_output(data, format)?);
        }
        OutputFormat::Table => {
            print!("{}", render_table(data));
        }
        OutputFormat::Plain => {
            print!("{}", render_plain(data));
        }
    }
    Ok(())
}

/// One table cell (#365). A value is printed between tabs, so a raw tab or
/// newline inside it would split the row a script reads: they become the
/// two-character escapes `\t`, `\n` and `\r`. Every other control
/// character (ESC and the rest of C0, DEL, C1) is removed, so a string from
/// the API cannot move the cursor, retitle the terminal or write the
/// clipboard (OSC 52).
fn table_cell(s: &str) -> String {
    let escaped = s
        .replace('\t', "\\t")
        .replace('\n', "\\n")
        .replace('\r', "\\r");
    crate::util::sanitize::sanitize_display(&escaped).into_owned()
}

/// Whole-text output (pretty JSON, plain lines). JSON escapes C0 controls
/// inside strings but not DEL or C1, which are removed here (#365); the
/// line breaks of the layout are kept.
fn safe_text(s: &str) -> String {
    s.split('\n')
        .map(|line| crate::util::sanitize::sanitize_display(line))
        .collect::<Vec<_>>()
        .join("\n")
}

/// `--format table`: a TSV-like table for arrays of objects (header from the
/// first object's keys), pretty JSON for an object, the bare value otherwise.
fn render_table(data: &Value) -> String {
    use std::fmt::Write as _;
    let mut out = String::new();
    match data {
        Value::Array(items) => {
            if items.is_empty() {
                out.push_str("(no results)\n");
                return out;
            }
            // Extract headers from first item
            if let Some(Value::Object(first)) = items.first() {
                let headers: Vec<&str> = first.keys().map(String::as_str).collect();
                let header_row: Vec<String> = headers
                    .iter()
                    .map(|h| table_cell(&h.to_uppercase()))
                    .collect();
                out.push_str(&header_row.join("\t"));
                out.push('\n');
                for item in items {
                    if let Value::Object(obj) = item {
                        let row: Vec<String> = headers
                            .iter()
                            .map(|h| match obj.get(*h) {
                                Some(Value::String(s)) => table_cell(s),
                                Some(Value::Null) | None => "-".to_string(),
                                Some(other) => table_cell(&other.to_string()),
                            })
                            .collect();
                        out.push_str(&row.join("\t"));
                        out.push('\n');
                    }
                }
            }
        }
        Value::Object(_) => {
            let _ = writeln!(
                out,
                "{}",
                safe_text(&serde_json::to_string_pretty(data).unwrap_or_default())
            );
        }
        other => {
            let _ = writeln!(out, "{}", safe_text(&other.to_string()));
        }
    }
    out
}

/// `--format plain`: one compact JSON value per line.
fn render_plain(data: &Value) -> String {
    let mut out = String::new();
    match data {
        Value::Array(items) => {
            for item in items {
                out.push_str(&safe_text(&item.to_string()));
                out.push('\n');
            }
        }
        other => {
            out.push_str(&safe_text(&other.to_string()));
            out.push('\n');
        }
    }
    out
}

/// Render a fatal CLI error as `Json` or `JsonEnvelope` (#361).
///
/// Keeps the existing 1-element array shape (`[ { ... } ]`) for `Json` and
/// reuses [`render_json_output`] so `JsonEnvelope` wraps that array in the
/// standard `{"proxxx": "<version>", "data": [ ... ]}` envelope.
pub fn render_fatal_error(
    e: &anyhow::Error,
    exit_code: i32,
    hint: Option<&str>,
    format: OutputFormat,
) -> Result<String> {
    let causes: Vec<String> = e.chain().map(ToString::to_string).collect();
    let mut err_obj = serde_json::json!({
        "error": format!("{e:#}"),
        "causes": causes,
        "exit_code": exit_code,
        "status": "fatal_error",
    });
    if let Some(h) = hint {
        err_obj["hint"] = Value::String(h.to_string());
    }
    let err_json = Value::Array(vec![err_obj]);
    render_json_output(&err_json, format)
}

#[cfg(test)]
mod terminal_safety_tests {
    //! #365: table and plain output never pass control sequences from API
    //! strings to the terminal, and a cell never splits its row.
    use super::{render_plain, render_table};
    use serde_json::json;

    const OSC52: &str = "\u{1b}]52;c;ZXZpbA==\u{7}";
    const C1_CSI: &str = "\u{9b}2J";

    fn assert_no_controls(out: &str) {
        for c in out.chars() {
            let u = c as u32;
            assert!(
                c == '\n' || c == '\t' || (u >= 0x20 && u != 0x7f && !(0x80..=0x9f).contains(&u)),
                "control U+{u:04X} reached the output: {out:?}"
            );
        }
    }

    #[test]
    fn table_cells_lose_escape_sequences_and_keep_one_line_per_row() {
        let data = json!([
            {"name": format!("vm{OSC52}"), "comment": format!("a\tb\nc\rd{C1_CSI}"), "n": 1},
            {"name": "plain", "comment": "ok", "n": 2}
        ]);
        let out = render_table(&data);
        assert_no_controls(&out);
        let lines: Vec<&str> = out.lines().collect();
        assert_eq!(lines.len(), 3, "header + 2 rows, got {out:?}");
        for l in &lines {
            assert_eq!(l.matches('\t').count(), 2, "3 columns in {l:?}");
        }
        assert!(lines[1].contains("vm]52;c;ZXZpbA=="), "{out:?}");
        assert!(lines[1].contains("a\\tb\\nc\\rd2J"), "{out:?}");
        // Columns follow the sorted keys: comment, n, name.
        assert_eq!(lines[2], "ok\t2\tplain");
    }

    #[test]
    fn table_headers_are_sanitized() {
        let data = json!([{ format!("x{OSC52}"): 1 }]);
        let out = render_table(&data);
        assert_no_controls(&out);
        assert!(out.starts_with("X]52;C;ZXZPBA==\n"), "{out:?}");
    }

    #[test]
    fn table_object_and_plain_output_drop_c1_and_del_but_keep_layout() {
        let obj = json!({"comment": format!("x{C1_CSI}\u{7f}y"), "id": 1});
        let table = render_table(&obj);
        assert_no_controls(&table);
        assert!(
            table.lines().count() > 1,
            "pretty JSON keeps its lines: {table:?}"
        );
        assert!(table.contains("x2Jy"), "{table:?}");

        let plain = render_plain(&json!([obj, "z\u{9d}0;t\u{9c}"]));
        assert_no_controls(&plain);
        assert_eq!(plain.lines().count(), 2, "{plain:?}");
    }

    #[test]
    fn clean_values_render_as_before() {
        let data = json!([{"vmid": 100, "name": "web", "running": true, "tags": null}]);
        assert_eq!(
            render_table(&data),
            "NAME\tRUNNING\tTAGS\tVMID\nweb\ttrue\t-\t100\n"
        );
        assert_eq!(render_table(&json!([])), "(no results)\n");
        assert_eq!(render_plain(&json!([{"a": 1}, 2])), "{\"a\":1}\n2\n");
    }
}

#[cfg(test)]
mod fatal_error_json_tests {
    use super::*;

    fn sample_three_layer_error() -> anyhow::Error {
        anyhow::anyhow!("innermost root cause")
            .context("middle layer")
            .context("outermost context")
    }

    #[test]
    fn json_error_rendering_includes_full_chain_causes_and_exit_code() {
        let err = sample_three_layer_error();
        let rendered = render_fatal_error(&err, 5, Some("check the guest id"), OutputFormat::Json)
            .expect("render json error");
        let parsed: Value = serde_json::from_str(&rendered).expect("valid JSON");
        let arr = parsed.as_array().expect("top-level JSON array");
        assert_eq!(arr.len(), 1);
        let obj = &arr[0];

        let error_str = obj["error"].as_str().expect("error string");
        assert!(
            error_str.contains("outermost context")
                && error_str.contains("middle layer")
                && error_str.contains("innermost root cause"),
            "error field must contain all 3 layers via {{e:#}}, got: {error_str}"
        );
        assert_eq!(
            error_str,
            "outermost context: middle layer: innermost root cause"
        );

        let causes = obj["causes"]
            .as_array()
            .expect("causes must be an array of strings");
        let cause_strs: Vec<&str> = causes
            .iter()
            .map(|v| v.as_str().expect("cause entry is string"))
            .collect();
        assert_eq!(
            cause_strs,
            vec!["outermost context", "middle layer", "innermost root cause"]
        );

        assert_eq!(obj["exit_code"].as_i64(), Some(5));
        assert_eq!(obj["status"].as_str(), Some("fatal_error"));
        assert_eq!(obj["hint"].as_str(), Some("check the guest id"));
    }

    #[test]
    fn json_envelope_error_rendering_wraps_in_proxxx_envelope() {
        let err = sample_three_layer_error();
        let rendered = render_fatal_error(&err, 4, None, OutputFormat::JsonEnvelope)
            .expect("render json-envelope error");
        let parsed: Value = serde_json::from_str(&rendered).expect("valid JSON");
        let root = parsed
            .as_object()
            .expect("json-envelope must be a top-level JSON object");
        assert_eq!(
            root.get("proxxx").and_then(Value::as_str),
            Some(env!("CARGO_PKG_VERSION"))
        );
        let data = root
            .get("data")
            .and_then(Value::as_array)
            .expect("data must be an array");
        assert_eq!(data.len(), 1);
        let obj = &data[0];
        assert_eq!(
            obj["error"].as_str(),
            Some("outermost context: middle layer: innermost root cause")
        );
        assert_eq!(obj["causes"].as_array().map(Vec::len), Some(3));
        assert_eq!(obj["exit_code"].as_i64(), Some(4));
        assert_eq!(obj["status"].as_str(), Some("fatal_error"));
        assert!(obj.get("hint").is_none());
    }
}
