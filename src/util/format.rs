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
            print_table(data);
        }
        OutputFormat::Plain => {
            print_plain(data);
        }
    }
    Ok(())
}

fn print_table(data: &Value) {
    match data {
        Value::Array(items) => {
            if items.is_empty() {
                println!("(no results)");
                return;
            }
            // Extract headers from first item
            if let Some(Value::Object(first)) = items.first() {
                let headers: Vec<&str> = first.keys().map(String::as_str).collect();
                // Print header
                for (i, h) in headers.iter().enumerate() {
                    if i > 0 {
                        print!("\t");
                    }
                    print!("{}", h.to_uppercase());
                }
                println!();
                // Print rows
                for item in items {
                    if let Value::Object(obj) = item {
                        for (i, h) in headers.iter().enumerate() {
                            if i > 0 {
                                print!("\t");
                            }
                            match obj.get(*h) {
                                Some(Value::String(s)) => print!("{s}"),
                                Some(Value::Number(n)) => print!("{n}"),
                                Some(Value::Bool(b)) => print!("{b}"),
                                Some(Value::Null) | None => print!("-"),
                                Some(other) => print!("{other}"),
                            }
                        }
                        println!();
                    }
                }
            }
        }
        Value::Object(_) => {
            println!("{}", serde_json::to_string_pretty(data).unwrap_or_default());
        }
        other => {
            println!("{other}");
        }
    }
}

fn print_plain(data: &Value) {
    match data {
        Value::Array(items) => {
            for item in items {
                println!("{item}");
            }
        }
        other => println!("{other}"),
    }
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
