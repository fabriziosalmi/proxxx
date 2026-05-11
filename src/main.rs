// Bin entry point. Consumes the library via `proxxx::*` rather than
// re-declaring `mod api; mod app; …` — that duplicate-compilation pattern
// caused 50+ spurious "dead code" warnings from clippy because each
// module appeared twice (once per crate target). Now main.rs is a thin
// orchestrator and the lib is the single compilation unit.
use anyhow::Result;
use clap::Parser;
use tracing::info;

use proxxx::{cli, tui, util};

#[derive(Parser)]
#[command(name = "proxxx", version, about = "The ultimate Proxmox TUI")]
struct Cli {
    /// Subcommand (omit for interactive TUI mode)
    #[command(subcommand)]
    command: Option<cli::Command>,

    /// Connection profile name
    #[arg(long, global = true)]
    profile: Option<String>,

    /// Output format (only in CLI mode)
    #[arg(long, global = true, default_value = "table")]
    format: util::format::OutputFormat,

    /// API Token Secret (Overrides env var and config file)
    #[arg(long, global = true)]
    token_secret: Option<String>,

    /// Require Telegram 2FA for all destructive operations (Self-HITL)
    #[arg(long, global = true)]
    secure: bool,
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    // Tracing → file only (TUI owns stdout).
    //
    // (macro audit) — capped log rotation. Without
    // `max_log_files` a daemon left running for months on a flapping
    // network would create one file per day forever (each potentially
    // multi-MB), eventually filling the disk or exhausting inodes.
    // Cap at 14 daily files (~2 weeks of forensic trail) — enough to
    // diagnose any incident without unbounded growth.
    //
    // (audit) — path traversal via $HOME injection.
    //
    // `directories::ProjectDirs` resolves XDG paths via $HOME (or
    // platform equivalents). A hostile $HOME like `/tmp/../../etc`
    // would land logs under `/etc/.local/share/proxxx/`. This is
    // ONLY exploitable if the attacker already controls proxxx's
    // process environment AND proxxx runs as root — at which point
    // they can write to `/etc/` directly, with or without proxxx.
    // The threat model says "the user controls their own env";
    // we don't try to defend against the user attacking themselves.
    //
    // Containerised / system-service deploys should pass an explicit
    // $XDG_DATA_HOME or run as a non-root user — the standard
    // hardening for any XDG-aware tool. proxxx documents this in
    // README; no in-app canonicalisation gate (it would break
    // legitimate $HOME=/var/lib/proxxx setups in containers).
    let log_dir = directories::ProjectDirs::from("dev", "proxxx", "proxxx").map_or_else(
        || std::path::PathBuf::from("/tmp/proxxx"),
        |d| d.data_local_dir().to_path_buf(),
    );
    std::fs::create_dir_all(&log_dir)?;
    let file_appender = tracing_appender::rolling::Builder::new()
        .rotation(tracing_appender::rolling::Rotation::DAILY)
        .filename_prefix("proxxx")
        .filename_suffix("log")
        .max_log_files(14)
        .build(&log_dir)
        .map_err(|e| anyhow::anyhow!("log appender init failed: {e}"))?;
    let (non_blocking, _guard) = tracing_appender::non_blocking(file_appender);
    tracing_subscriber::fmt()
        .with_writer(non_blocking)
        .with_env_filter("proxxx=debug")
        .init();

    info!("proxxx v{} starting", env!("CARGO_PKG_VERSION"));

    // flight recorder: install the flight-recorder panic hook BEFORE the
    // tokio runtime / TUI / CLI runs. This way a panic anywhere — in
    // either mode — restores the terminal and writes the trace to the
    // audit log. Idempotent: the install function guards against a
    // second tui::run-side install layering on top.
    util::panic_hook::install();

    let rt = tokio::runtime::Runtime::new()?;

    match cli.command {
        // CLI mode: no ratatui, no crossterm, just stdout
        Some(cmd) => {
            match rt.block_on(cli::execute(
                cmd,
                cli.profile.as_deref(),
                cli.token_secret.as_deref(),
                cli.secure,
            )) {
                Ok((result, exit_code)) => {
                    // Ensure the output is a JSON array if Json format is requested
                    let result_array = if matches!(cli.format, util::format::OutputFormat::Json)
                        && !result.is_array()
                    {
                        serde_json::json!([result])
                    } else {
                        result
                    };

                    let _ = util::format::print(&result_array, cli.format);
                    if exit_code != 0 {
                        std::process::exit(exit_code);
                    }
                }
                Err(e) => {
                    // Phase 10 audit fix: walk the anyhow chain for a
                    // typed ApiError and surface its actionable hint
                    // alongside the error. The v0.1.10 audit found that
                    // is_unauthorized() / is_not_found() / etc. were
                    // defined on ApiError but had zero call sites — the
                    // typed-error architecture existed but the operator
                    // saw the same generic message for 401/403/404/595.
                    // The hint is the differentiator: "rotate token via
                    // `proxxx init --interactive`" beats "Proxmox rejected
                    // our credentials" without follow-up.
                    let hint = proxxx::api::error::extract_hint(&e);
                    if matches!(cli.format, util::format::OutputFormat::Json) {
                        let mut err_obj = serde_json::json!({
                            "error": e.to_string(),
                            "status": "fatal_error",
                        });
                        if let Some(h) = hint {
                            err_obj["hint"] = serde_json::Value::String(h.to_string());
                        }
                        let err_json = serde_json::Value::Array(vec![err_obj]);
                        // Falls back to a hand-written JSON literal if
                        // pretty-printing fails (almost never — the
                        // payload is a tiny inline json! macro).
                        match serde_json::to_string_pretty(&err_json) {
                            Ok(s) => println!("{s}"),
                            Err(_) => println!(
                                "[{{\"error\":\"<unrenderable>\",\"status\":\"fatal_error\"}}]"
                            ),
                        }
                    } else {
                        // `{:#}` renders the anyhow Error chain — outermost
                        // context first, then `: <next>` for each wrapped
                        // cause. Without this, every "Failed to parse
                        // response from /X" message hid the actual serde
                        // / TLS / IO error one level down, leaving the
                        // operator with nothing to act on.
                        eprintln!("Fatal Error: {e:#}");
                        if let Some(h) = hint {
                            eprintln!("  hint: {h}");
                        }
                    }
                    std::process::exit(1);
                }
            }
        }
        // TUI mode: full ratatui
        None => {
            rt.block_on(tui::run(
                cli.profile.as_deref(),
                cli.token_secret.as_deref(),
                cli.secure,
            ))?;
        }
    }

    Ok(())
}
