//! `proxxx doctor` — self-diagnostic command.
//! Validates config, connectivity, auth, HITL, PBS, and SSH without
//! requiring a fully functional cluster.

use anyhow::Result;
use serde_json::{json, Value};

struct Check {
    name: &'static str,
    status: CheckStatus,
    message: String,
}

enum CheckStatus {
    Ok,
    Warn,
    Fail,
}

impl CheckStatus {
    fn symbol(&self) -> &'static str {
        match self {
            Self::Ok => "ok",
            Self::Warn => "warn",
            Self::Fail => "fail",
        }
    }
}

pub async fn run() -> Result<(Value, i32)> {
    let mut checks: Vec<Check> = Vec::new();
    let mut overall_ok = true;

    match crate::config::load_config(None) {
        Ok(cfg) => {
            checks.push(Check {
                name: "config",
                status: CheckStatus::Ok,
                message: format!("config.toml parsed — profile url: {}", cfg.url),
            });

            if !cfg.verify_tls {
                checks.push(Check {
                    name: "tls",
                    status: CheckStatus::Warn,
                    message: "verify_tls = false — TLS cert not validated (ok for homelab, not for production)".into(),
                });
            } else {
                checks.push(Check {
                    name: "tls",
                    status: CheckStatus::Ok,
                    message: "TLS verification enabled".into(),
                });
            }

            let url = format!("{}/api2/json/version", cfg.url.trim_end_matches('/'));
            let tls_skip = !cfg.verify_tls;
            match probe_url(&url, tls_skip).await {
                Ok(body) => {
                    let ver = body
                        .get("data")
                        .and_then(|d| d.get("version"))
                        .and_then(|v| v.as_str())
                        .unwrap_or("unknown");
                    checks.push(Check {
                        name: "connectivity",
                        status: CheckStatus::Ok,
                        message: format!("PVE reachable — version {ver}"),
                    });

                    match crate::api::PxClient::new(cfg.clone(), None).await {
                        Ok(client) => {
                            use crate::api::ProxmoxGateway;
                            match client.get_nodes().await {
                                Ok(nodes) => {
                                    checks.push(Check {
                                        name: "auth",
                                        status: CheckStatus::Ok,
                                        message: format!(
                                            "{} node(s) visible with current credentials",
                                            nodes.len()
                                        ),
                                    });
                                }
                                Err(e) => {
                                    overall_ok = false;
                                    checks.push(Check {
                                        name: "auth",
                                        status: CheckStatus::Fail,
                                        message: format!("GET /nodes failed: {e}"),
                                    });
                                }
                            }
                        }
                        Err(e) => {
                            overall_ok = false;
                            checks.push(Check {
                                name: "auth",
                                status: CheckStatus::Fail,
                                message: format!("client init failed: {e}"),
                            });
                        }
                    }
                }
                Err(e) => {
                    overall_ok = false;
                    checks.push(Check {
                        name: "connectivity",
                        status: CheckStatus::Fail,
                        message: format!("cannot reach {url}: {e}"),
                    });
                    checks.push(Check {
                        name: "auth",
                        status: CheckStatus::Warn,
                        message: "skipped — connectivity failed".into(),
                    });
                }
            }

            if let Some(ref tg) = cfg.telegram {
                let token_opt = tg.bot_token.as_deref().unwrap_or_default();
                if token_opt.is_empty() {
                    checks.push(Check {
                        name: "telegram",
                        status: CheckStatus::Warn,
                        message: "Telegram configured but bot_token is empty".into(),
                    });
                } else {
                    let bot_url = format!("https://api.telegram.org/bot{token_opt}/getMe");
                    match probe_url(&bot_url, false).await {
                        Ok(_) => {
                            checks.push(Check {
                                name: "telegram",
                                status: CheckStatus::Ok,
                                message: format!(
                                    "Telegram bot reachable, chat_id = {}",
                                    tg.chat_id
                                ),
                            });
                        }
                        Err(e) => {
                            checks.push(Check {
                                name: "telegram",
                                status: CheckStatus::Warn,
                                message: format!("Telegram probe failed: {e}"),
                            });
                        }
                    }
                }
            } else {
                checks.push(Check {
                    name: "telegram",
                    status: CheckStatus::Warn,
                    message: "not configured — HITL approval disabled".into(),
                });
            }

            if let Some(ref pbs) = cfg.pbs {
                let url = format!("{}/api2/json/version", pbs.url.trim_end_matches('/'));
                match probe_url(&url, true).await {
                    Ok(_) => {
                        checks.push(Check {
                            name: "pbs",
                            status: CheckStatus::Ok,
                            message: format!("PBS reachable at {}", pbs.url),
                        });
                    }
                    Err(e) => {
                        checks.push(Check {
                            name: "pbs",
                            status: CheckStatus::Warn,
                            message: format!("PBS unreachable: {e}"),
                        });
                    }
                }
            } else {
                checks.push(Check {
                    name: "pbs",
                    status: CheckStatus::Warn,
                    message: "not configured".into(),
                });
            }

            if let Some(ref ssh) = cfg.ssh {
                if let Some(ref key_path) = ssh.key_path {
                    if std::path::Path::new(key_path.as_str()).exists() {
                        checks.push(Check {
                            name: "ssh_key",
                            status: CheckStatus::Ok,
                            message: format!("SSH key readable: {key_path}"),
                        });
                    } else {
                        checks.push(Check {
                            name: "ssh_key",
                            status: CheckStatus::Fail,
                            message: format!("SSH key not found: {key_path}"),
                        });
                        overall_ok = false;
                    }
                } else {
                    checks.push(Check {
                        name: "ssh_key",
                        status: CheckStatus::Warn,
                        message: "no key_path configured".into(),
                    });
                }
            } else {
                checks.push(Check {
                    name: "ssh_key",
                    status: CheckStatus::Warn,
                    message: "SSH not configured".into(),
                });
            }
        }
        Err(e) => {
            overall_ok = false;
            checks.push(Check {
                name: "config",
                status: CheckStatus::Fail,
                message: format!("{e} — run `proxxx init --interactive` to create one"),
            });
        }
    }

    match crate::audit::AuditLogger::open() {
        Ok(_) => {
            checks.push(Check {
                name: "audit_log",
                status: CheckStatus::Ok,
                message: "audit log DB accessible".into(),
            });
        }
        Err(e) => {
            checks.push(Check {
                name: "audit_log",
                status: CheckStatus::Warn,
                message: format!("audit log not initialised: {e}"),
            });
        }
    }

    let result: Vec<Value> = checks
        .iter()
        .map(|c| {
            json!({
                "check": c.name,
                "status": c.status.symbol(),
                "message": c.message,
            })
        })
        .collect();

    let exit_code = if overall_ok { 0 } else { 1 };
    Ok((json!(result), exit_code))
}

async fn probe_url(url: &str, skip_tls: bool) -> Result<serde_json::Value> {
    let client = if skip_tls {
        reqwest::Client::builder()
            .danger_accept_invalid_certs(true)
            .timeout(std::time::Duration::from_secs(8))
            .build()?
    } else {
        reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(8))
            .build()?
    };
    let resp = client.get(url).send().await?;
    let val: serde_json::Value = resp.json().await?;
    Ok(val)
}
