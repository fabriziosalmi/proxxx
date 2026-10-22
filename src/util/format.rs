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

/// `println!` for human-readable CLI output (#437): the formatted text
/// goes through [`safe_text`], so a control sequence inside an
/// interpolated cluster string (a guest name, a journal line, a resource
/// comment) is removed instead of reaching the terminal. Line breaks and
/// tabs are kept. Machine output (JSON, TOML documents) keeps `println!`
/// with a `// raw-output:` note, since removing characters would change
/// the data.
#[macro_export]
macro_rules! outln {
    () => {
        ::std::println!()
    };
    ($($arg:tt)*) => {
        ::std::println!("{}", $crate::util::format::safe_text(&::std::format!($($arg)*)))
    };
}

/// `print!` counterpart of [`outln!`](crate::outln).
#[macro_export]
macro_rules! out {
    ($($arg:tt)*) => {
        ::std::print!("{}", $crate::util::format::safe_text(&::std::format!($($arg)*)))
    };
}

/// Whole-text output (pretty JSON, plain lines). JSON escapes C0 controls
/// inside strings but not DEL or C1, which are removed here (#365); the
/// line breaks of the layout are kept.
#[must_use]
pub fn safe_text(s: &str) -> String {
    s.split('\n')
        .map(|line| crate::util::sanitize::sanitize_display(line))
        .collect::<Vec<_>>()
        .join("\n")
}

/// `--format table` (audit #385: objects and nested objects used to come
/// out as pretty or compact JSON):
/// - an array of objects is a TSV table whose columns are the union of
///   the rows' keys; a nested object expands into `key.sub` columns, and
///   the `data` envelope of `--all-profiles` / `find` rows into its own
///   keys;
/// - an object is `KEY<TAB>VALUE` rows, followed by one table per field
///   that holds an array of objects;
/// - anything else is printed bare.
fn render_table(data: &Value) -> String {
    match data {
        Value::Array(items) => rows_table(items),
        Value::Object(map) => object_table(map),
        other => format!("{}\n", table_cell(&cell_text(other))),
    }
}

/// A value as cell text: strings bare, `null` as `-`, an array of scalars
/// comma-joined, anything else compact JSON.
fn cell_text(v: &Value) -> String {
    match v {
        Value::String(s) => s.clone(),
        Value::Null => "-".to_string(),
        Value::Array(items) if items.iter().all(|i| !i.is_object() && !i.is_array()) => {
            if items.is_empty() {
                "-".to_string()
            } else {
                items.iter().map(cell_text).collect::<Vec<_>>().join(",")
            }
        }
        other => other.to_string(),
    }
}

/// Envelope keys whose object is the row itself (fanout rows carry the
/// payload under `data`).
const ENVELOPE_KEYS: &[&str] = &["data"];

fn rows_table(items: &[Value]) -> String {
    if items.is_empty() {
        return "(no results)\n".to_string();
    }
    if !items.iter().any(Value::is_object) {
        let mut out = String::new();
        for i in items {
            out.push_str(&table_cell(&cell_text(i)));
            out.push('\n');
        }
        return out;
    }
    // Columns as (header, path), sorted by header; the union over rows,
    // so an error row first does not hide the data columns.
    let mut columns: std::collections::BTreeMap<String, Vec<String>> =
        std::collections::BTreeMap::new();
    for item in items.iter().filter_map(Value::as_object) {
        for (key, value) in item {
            match value {
                Value::Object(inner) if !inner.is_empty() => {
                    for sub in inner.keys() {
                        let header =
                            if ENVELOPE_KEYS.contains(&key.as_str()) && !item.contains_key(sub) {
                                sub.clone()
                            } else {
                                format!("{key}.{sub}")
                            };
                        columns.insert(header, vec![key.clone(), sub.clone()]);
                    }
                }
                _ => {
                    columns.insert(key.clone(), vec![key.clone()]);
                }
            }
        }
    }
    let mut out = String::new();
    let header: Vec<String> = columns
        .keys()
        .map(|h| table_cell(&h.to_uppercase()))
        .collect();
    out.push_str(&header.join("\t"));
    out.push('\n');
    for item in items.iter().filter_map(Value::as_object) {
        let row: Vec<String> = columns
            .values()
            .map(|path| {
                let mut v = item.get(&path[0]);
                if let Some(sub) = path.get(1) {
                    v = v.and_then(|o| o.get(sub));
                }
                v.map_or_else(|| "-".to_string(), |v| table_cell(&cell_text(v)))
            })
            .collect();
        out.push_str(&row.join("\t"));
        out.push('\n');
    }
    out
}

fn object_table(map: &serde_json::Map<String, Value>) -> String {
    let mut out = String::from("KEY\tVALUE\n");
    let mut sections = String::new();
    for (key, value) in map {
        match value {
            Value::Array(items) if items.iter().any(Value::is_object) => {
                sections.push('\n');
                sections.push_str(&table_cell(&key.to_uppercase()));
                sections.push('\n');
                sections.push_str(&rows_table(items));
            }
            Value::Object(inner) if !inner.is_empty() => {
                for (sub, v) in inner {
                    out.push_str(&format!(
                        "{}\t{}\n",
                        table_cell(&format!("{key}.{sub}")),
                        table_cell(&cell_text(v))
                    ));
                }
            }
            other => {
                out.push_str(&format!(
                    "{}\t{}\n",
                    table_cell(key),
                    table_cell(&cell_text(other))
                ));
            }
        }
    }
    out.push_str(&sections);
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
        assert!(table.lines().count() > 1, "one line per key: {table:?}");
        assert!(table.contains("x2Jy"), "{table:?}");

        let plain = render_plain(&json!([obj, "z\u{9d}0;t\u{9c}"]));
        assert_no_controls(&plain);
        assert_eq!(plain.lines().count(), 2, "{plain:?}");
    }

    #[test]
    fn an_object_is_key_value_rows_with_a_table_per_array_of_objects() {
        let preview = json!({
            "failed_node": "pve1",
            "previews": [
                {"sid": "vm:100", "current_node": "pve1",
                 "outcome": {"kind": "relocate", "target": "pve2"}},
                {"sid": "vm:101", "current_node": "pve2",
                 "outcome": {"kind": "not_affected"}}
            ]
        });
        assert_eq!(
            render_table(&preview),
            "KEY\tVALUE\nfailed_node\tpve1\n\nPREVIEWS\n\
             CURRENT_NODE\tOUTCOME.KIND\tOUTCOME.TARGET\tSID\n\
             pve1\trelocate\tpve2\tvm:100\n\
             pve2\tnot_affected\t-\tvm:101\n"
        );
    }

    #[test]
    fn fanout_rows_spread_their_data_into_columns() {
        // `find` / `ls --all-profiles` rows: the payload sits under `data`,
        // an unreachable profile has `error` instead.
        let rows = json!([
            {"profile": "down", "error": "connection refused"},
            {"profile": "lab", "data": {"vmid": 100, "node": "pve1", "tags": ["a", "b"]}}
        ]);
        assert_eq!(
            render_table(&rows),
            "ERROR\tNODE\tPROFILE\tTAGS\tVMID\n\
             connection refused\t-\tdown\t-\t-\n\
             -\tpve1\tlab\ta,b\t100\n"
        );
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
