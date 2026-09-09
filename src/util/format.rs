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

/// Print data in the requested format to stdout
pub fn print(data: &Value, format: OutputFormat) -> Result<()> {
    match format {
        OutputFormat::Json => {
            println!("{}", serde_json::to_string_pretty(data)?);
        }
        OutputFormat::JsonEnvelope => {
            let enveloped = serde_json::json!({
                "proxxx": env!("CARGO_PKG_VERSION"),
                "data": data,
            });
            println!("{}", serde_json::to_string_pretty(&enveloped)?);
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
