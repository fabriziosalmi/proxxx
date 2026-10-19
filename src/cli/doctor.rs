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
    const fn symbol(&self) -> &'static str {
        match self {
            Self::Ok => "ok",
            Self::Warn => "warn",
            Self::Fail => "fail",
        }
    }
}

/// Extract the HTTP status code when an [`anyhow::Error`] wraps a typed
/// [`crate::api::ApiError::Unauthorized`] (`401`) or
/// [`crate::api::ApiError::Forbidden`] (`403`).
///
/// Matches on the typed [`crate::api::ApiError`] variant in the cause chain
/// rather than inspecting error strings (`#321`).
fn auth_rejection_status(err: &anyhow::Error) -> Option<u16> {
    err.chain()
        .find_map(|cause| cause.downcast_ref::<crate::api::ApiError>())
        .and_then(|api_err| match api_err {
            crate::api::ApiError::Unauthorized(_) => Some(401),
            crate::api::ApiError::Forbidden(_) => Some(403),
            _ => None,
        })
}

async fn probe_telegram_gateway(gw: &crate::hitl::telegram::TelegramGateway) -> Check {
    match gw.get_me().await {
        Ok(_) => Check {
            name: "telegram",
            status: CheckStatus::Ok,
            message: format!("Telegram bot reachable, chat_id = {}", gw.chat_id()),
        },
        Err(e) => Check {
            name: "telegram",
            status: CheckStatus::Warn,
            message: format!("Telegram probe failed: {e}"),
        },
    }
}

/// Run the `telegram` doctor check against an already-constructed
/// [`crate::hitl::telegram::TelegramGateway`].
///
/// Exposed so tests can inject a `wiremock` base URL via
/// [`crate::hitl::telegram::TelegramGateway::with_base_url`] (`#410`, `#411`).
pub async fn check_telegram_with_gateway(gw: &crate::hitl::telegram::TelegramGateway) -> Value {
    let check = probe_telegram_gateway(gw).await;
    json!({
        "check": check.name,
        "status": check.status.symbol(),
        "message": check.message,
    })
}

#[allow(clippy::too_many_lines)] // audit #272: wide, flat dispatch — see Cargo.toml
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

            // #321: PVE 8+/9 returns 401 to an unauthenticated GET /version.
            // Probe connectivity and auth through the real PxClient (single
            // attempt so a closed port fails in ~10 ms without 4x retry backoff).
            match crate::api::PxClient::new(cfg.clone(), None)
                .await
                .map(crate::api::PxClient::with_single_attempt)
            {
                Ok(client) => {
                    use crate::api::ProxmoxGateway;
                    match client.get_api_version().await {
                        Ok(v) => {
                            let ver = if v.version.is_empty() {
                                "unknown"
                            } else {
                                v.version.as_str()
                            };
                            checks.push(Check {
                                name: "connectivity",
                                status: CheckStatus::Ok,
                                message: format!("PVE reachable, version {ver}"),
                            });

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
                            if let Some(code) = auth_rejection_status(&e) {
                                checks.push(Check {
                                    name: "connectivity",
                                    status: CheckStatus::Ok,
                                    message: format!("PVE reachable (HTTP {code})"),
                                });
                                checks.push(Check {
                                    name: "auth",
                                    status: CheckStatus::Fail,
                                    message: format!("{e}"),
                                });
                            } else {
                                checks.push(Check {
                                    name: "connectivity",
                                    status: CheckStatus::Fail,
                                    message: format!("cannot reach {}: {e}", cfg.url),
                                });
                                checks.push(Check {
                                    name: "auth",
                                    status: CheckStatus::Warn,
                                    message: "skipped — connectivity failed".into(),
                                });
                            }
                        }
                    }
                }
                Err(init_err) => {
                    overall_ok = false;
                    match crate::cli::init_wizard::send_anon_version_probe(&cfg.url, cfg.verify_tls)
                        .await
                    {
                        Ok(resp) => {
                            checks.push(Check {
                                name: "connectivity",
                                status: CheckStatus::Ok,
                                message: format!("PVE reachable (HTTP {})", resp.status().as_u16()),
                            });
                        }
                        Err(probe_err) => {
                            checks.push(Check {
                                name: "connectivity",
                                status: CheckStatus::Fail,
                                message: format!("cannot reach {}: {probe_err}", cfg.url),
                            });
                        }
                    }
                    checks.push(Check {
                        name: "auth",
                        status: CheckStatus::Fail,
                        message: format!("client init failed: {init_err}"),
                    });
                }
            }

            if let Some(ref tg) = cfg.telegram {
                let inline_empty = tg.bot_token.as_ref().is_some_and(|s| s.is_empty())
                    && tg.bot_token_file.is_none()
                    && std::env::var_os("PROXXX_TELEGRAM_BOT_TOKEN").is_none();
                if inline_empty {
                    checks.push(Check {
                        name: "telegram",
                        status: CheckStatus::Warn,
                        message: "Telegram configured but bot_token is empty".into(),
                    });
                } else {
                    match tg.resolve_bot_token().await {
                        Ok(token) => match crate::hitl::telegram::TelegramGateway::new_for_probe(
                            token,
                            tg.chat_id.clone(),
                        ) {
                            Ok(gw) => {
                                checks.push(probe_telegram_gateway(&gw).await);
                            }
                            Err(e) => {
                                checks.push(Check {
                                    name: "telegram",
                                    status: CheckStatus::Warn,
                                    message: format!("Telegram client init failed: {e}"),
                                });
                            }
                        },
                        Err(e) => {
                            checks.push(Check {
                                name: "telegram",
                                status: CheckStatus::Warn,
                                message: format!("Telegram bot token unavailable: {e}"),
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
                match crate::pbs::PbsClient::new(pbs.clone(), None).await {
                    Ok(pbs_client) => {
                        use crate::pbs::PbsGateway;
                        match pbs_client.version().await {
                            Ok(ver) => {
                                let v = if ver.version.is_empty() {
                                    "unknown"
                                } else {
                                    ver.version.as_str()
                                };
                                checks.push(Check {
                                    name: "pbs",
                                    status: CheckStatus::Ok,
                                    message: format!("PBS reachable at {}, version {v}", pbs.url),
                                });
                            }
                            Err(e) => {
                                if let Some(code) = auth_rejection_status(&e) {
                                    checks.push(Check {
                                        name: "pbs",
                                        status: CheckStatus::Warn,
                                        message: format!(
                                            "PBS reachable at {} (HTTP {code}), credentials rejected: {e}",
                                            pbs.url
                                        ),
                                    });
                                } else {
                                    checks.push(Check {
                                        name: "pbs",
                                        status: CheckStatus::Warn,
                                        message: format!("PBS unreachable: {e}"),
                                    });
                                }
                            }
                        }
                    }
                    Err(init_err) => {
                        let reach_note = match crate::cli::init_wizard::send_anon_version_probe(
                            &pbs.url,
                            pbs.verify_tls,
                        )
                        .await
                        {
                            Ok(resp) => format!(
                                "PBS reachable at {} (HTTP {})",
                                pbs.url,
                                resp.status().as_u16()
                            ),
                            Err(probe_err) => {
                                format!("PBS unreachable at {} ({probe_err})", pbs.url)
                            }
                        };
                        checks.push(Check {
                            name: "pbs",
                            status: CheckStatus::Warn,
                            message: format!(
                                "{reach_note}; PBS credentials / client init failed: {init_err}"
                            ),
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
                    let expanded = crate::util::path::expand_tilde(key_path);
                    if expanded.exists() {
                        checks.push(Check {
                            name: "ssh_key",
                            status: CheckStatus::Ok,
                            message: format!(
                                "SSH key readable: {key_path} ({})",
                                expanded.display()
                            ),
                        });
                    } else {
                        checks.push(Check {
                            name: "ssh_key",
                            status: CheckStatus::Fail,
                            message: format!(
                                "SSH key not found: {key_path} ({})",
                                expanded.display()
                            ),
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

    // Audit 2026-09-09 (#281) — actually verify the chain.
    //
    // This used to report OK on the strength of the database opening,
    // while the README credited doctor with validating "audit log
    // integrity". A chain broken by an interrupted write, a partial
    // restore or tampering reported OK here — and since nothing else
    // runs `verify()` automatically, doctor was the most likely place
    // for that damage to go unnoticed.
    match crate::audit::AuditLogger::open() {
        Ok(logger) => match logger.verify() {
            Ok((ok, 0)) => {
                checks.push(Check {
                    name: "audit_log",
                    status: CheckStatus::Ok,
                    message: format!("audit chain verified — {ok} entries, chain intact"),
                });
            }
            Ok((ok, broken)) => {
                checks.push(Check {
                    name: "audit_log",
                    status: CheckStatus::Fail,
                    message: format!(
                        "audit chain BROKEN — {broken} of {} entries failed verification.                          Run `proxxx audit verify` for the first bad link. Entries after a                          break chain onto the damaged prefix, so the trail cannot be                          trusted from that point on.",
                        ok + broken
                    ),
                });
            }
            Err(e) => {
                checks.push(Check {
                    name: "audit_log",
                    status: CheckStatus::Warn,
                    message: format!("audit chain could not be verified: {e}"),
                });
            }
        },
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

    let exit_code = i32::from(!overall_ok);
    Ok((json!(result), exit_code))
}
