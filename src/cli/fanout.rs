//! Cross-profile fanout for read-only `ls` / `find` queries.
//!
//! Operators with `[profiles.dev]` + `[profiles.staging]` + `[profiles.prod]`
//! in `config.toml` can pass `--all-profiles` (or `-A`) to fan a
//! read-only query across every cluster concurrently. Each row gets
//! a `profile` field added so the operator can tell where it came
//! from. Per-cluster failures (unreachable, 401, etc.) surface as
//! synthetic rows tagged `error: …` — they NEVER fail the whole
//! command. The MVP rule: investigation should always make progress
//! against the clusters that *are* reachable.
//!
//! Writes are deliberately NOT plumbed through this fanout — too
//! easy to footgun ("stop every guest across every cluster"). For
//! writes, the operator must `--profile <name>` explicitly. Issue
//! #59 calls this out in its "Out of scope" section.

use anyhow::Result;
use serde::Serialize;
use serde_json::Value;
use std::sync::Arc;

use crate::api::{ProxmoxGateway, PxClient};

/// One row in a cross-profile result. The `profile` field is added
/// at fanout time; the rest is whatever the per-profile call
/// returned, serialised back through `serde_json::Value` so we
/// don't have to know the concrete shape per resource kind.
#[derive(Debug, Clone, Serialize)]
pub struct ProfileRow {
    pub profile: String,
    /// `data` for a successful row, `error` for a failure row.
    /// Serialised flat so JSON consumers see `{profile, data}` or
    /// `{profile, error}`.
    #[serde(flatten)]
    pub payload: ProfileRowPayload,
}

#[derive(Debug, Clone, Serialize)]
#[serde(untagged)]
pub enum ProfileRowPayload {
    Data { data: Value },
    Error { error: String },
}

/// Kinds of read-only query we know how to fan out. Each variant
/// maps to a single per-profile `async` call against `ProxmoxGateway`.
#[derive(Debug, Clone, Copy)]
pub enum FanoutKind {
    Nodes,
    Guests,
    Storage,
}

impl FanoutKind {
    /// Map the `ls` resource string from the CLI to a fanout kind.
    pub fn from_resource(s: &str) -> Option<Self> {
        match s {
            "nodes" => Some(Self::Nodes),
            "guests" => Some(Self::Guests),
            "storage" => Some(Self::Storage),
            _ => None,
        }
    }
}

/// Fanout a `ls <kind>` query across every named profile in the
/// config. Returns one or more rows per profile (depending on the
/// per-call result shape):
///   * Nodes → one row per cluster node
///   * Guests → one row per guest
///   * Storage → one row per storage pool
///   * Error → one synthetic row with `error: <message>`
///
/// Per-profile errors are caught and converted to error rows. Hard
/// `Err` is returned only if we can't even enumerate profiles (e.g.
/// config file is unreadable). The shape mirrors `events stream`'s
/// "graceful per-profile" pattern.
pub async fn fanout_ls(kind: FanoutKind, cli_secret: Option<&str>) -> Result<Vec<ProfileRow>> {
    let profiles = crate::config::list_profiles()?;
    if profiles.is_empty() {
        anyhow::bail!(
            "no named profiles in config.toml — `--all-profiles` requires at least one \
             `[profiles.NAME]` block (run `proxxx init` if this is a fresh setup)"
        );
    }

    let cli_secret_owned = cli_secret.map(str::to_owned);
    let handles: Vec<_> = profiles
        .into_iter()
        .map(|profile| {
            let cli_secret = cli_secret_owned.clone();
            tokio::spawn(async move {
                let rows = match query_one_profile(&profile, kind, cli_secret.as_deref()).await {
                    Ok(rows) => rows,
                    Err(e) => vec![ProfileRow {
                        profile: profile.clone(),
                        payload: ProfileRowPayload::Error {
                            error: format!("{e:#}"),
                        },
                    }],
                };
                rows
            })
        })
        .collect();

    let mut all_rows: Vec<ProfileRow> = Vec::new();
    for h in handles {
        // `join` itself could fail if the task panicked. Convert that
        // into an error row so the operator sees which profile blew up
        // rather than the whole command exiting non-zero.
        match h.await {
            Ok(rows) => all_rows.extend(rows),
            Err(e) => all_rows.push(ProfileRow {
                profile: "(unknown — task panicked)".into(),
                payload: ProfileRowPayload::Error {
                    error: format!("task join: {e}"),
                },
            }),
        }
    }
    // Sort by (profile, then a stable secondary if available). Stable
    // ordering matters for table rendering + scripted diff.
    all_rows.sort_by(|a, b| a.profile.cmp(&b.profile));
    Ok(all_rows)
}

/// Fanout a "find VMID X across every profile" query. Returns one
/// row per profile that owns the VMID, plus error rows for
/// unreachable profiles. Profiles that *don't* own the VMID are
/// silently filtered out — they're the common case (3 profiles, 1
/// owner) and would clutter the output otherwise.
pub async fn fanout_find_vmid(vmid: u32, cli_secret: Option<&str>) -> Result<Vec<ProfileRow>> {
    let profiles = crate::config::list_profiles()?;
    if profiles.is_empty() {
        anyhow::bail!("no named profiles in config.toml — `--all-profiles` requires at least one");
    }

    let cli_secret_owned = cli_secret.map(str::to_owned);
    let handles: Vec<_> = profiles
        .into_iter()
        .map(|profile| {
            let cli_secret = cli_secret_owned.clone();
            tokio::spawn(
                async move { find_one_profile(&profile, vmid, cli_secret.as_deref()).await },
            )
        })
        .collect();

    let mut rows: Vec<ProfileRow> = Vec::new();
    for h in handles {
        if let Ok(maybe_row) = h.await {
            match maybe_row {
                Ok(Some(row)) => rows.push(row),
                Ok(None) => {} // VMID not in this profile — silent
                Err(e) => rows.push(ProfileRow {
                    profile: "(unknown)".into(),
                    payload: ProfileRowPayload::Error {
                        error: format!("{e:#}"),
                    },
                }),
            }
        }
    }
    rows.sort_by(|a, b| a.profile.cmp(&b.profile));
    Ok(rows)
}

async fn query_one_profile(
    profile: &str,
    kind: FanoutKind,
    cli_secret: Option<&str>,
) -> Result<Vec<ProfileRow>> {
    let cfg = crate::config::load_config(Some(profile))?;
    let client = Arc::new(PxClient::new(cfg, cli_secret).await?);
    let payload = match kind {
        FanoutKind::Nodes => {
            let v = client.get_nodes().await?;
            serde_json::to_value(v)?
        }
        FanoutKind::Guests => serde_json::to_value(client.get_all_guests().await?)?,
        FanoutKind::Storage => serde_json::to_value(client.get_all_storage_pools().await?)?,
    };
    // Per-resource arrays get flattened to one row per element so
    // the table view shows N rows per profile, each with the
    // `profile` column. Scalars (or non-array shapes) become a
    // single row with the whole value.
    let rows: Vec<ProfileRow> = if let Some(arr) = payload.as_array() {
        arr.iter()
            .map(|item| ProfileRow {
                profile: profile.to_string(),
                payload: ProfileRowPayload::Data { data: item.clone() },
            })
            .collect()
    } else {
        vec![ProfileRow {
            profile: profile.to_string(),
            payload: ProfileRowPayload::Data { data: payload },
        }]
    };
    Ok(rows)
}

async fn find_one_profile(
    profile: &str,
    vmid: u32,
    cli_secret: Option<&str>,
) -> Result<Option<ProfileRow>> {
    let cfg = crate::config::load_config(Some(profile))?;
    let client = Arc::new(PxClient::new(cfg, cli_secret).await?);
    // Walk nodes; first hit wins. Could parallelise per-node but
    // each profile is itself fanned out at the outer level — a
    // sequential per-node sweep here keeps the API call count
    // proportional rather than explosive.
    if let Some(g) = client.find_guest(vmid).await? {
        return Ok(Some(ProfileRow {
            profile: profile.to_string(),
            payload: ProfileRowPayload::Data {
                data: serde_json::to_value(&g)?,
            },
        }));
    }
    Ok(None)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fanout_kind_recognises_known_resources() {
        assert!(matches!(
            FanoutKind::from_resource("nodes"),
            Some(FanoutKind::Nodes)
        ));
        assert!(matches!(
            FanoutKind::from_resource("guests"),
            Some(FanoutKind::Guests)
        ));
        assert!(matches!(
            FanoutKind::from_resource("storage"),
            Some(FanoutKind::Storage)
        ));
        assert!(FanoutKind::from_resource("acl").is_none());
        assert!(FanoutKind::from_resource("").is_none());
    }

    #[test]
    fn profile_row_data_serialises_flat() {
        let row = ProfileRow {
            profile: "dev".into(),
            payload: ProfileRowPayload::Data {
                data: serde_json::json!({"vmid": 100}),
            },
        };
        let v: serde_json::Value = serde_json::to_value(&row).unwrap();
        assert_eq!(v["profile"], "dev");
        assert_eq!(v["data"]["vmid"], 100);
        // No nested `payload` wrapper.
        assert!(v.get("payload").is_none());
    }

    #[test]
    fn profile_row_error_serialises_flat() {
        let row = ProfileRow {
            profile: "prod".into(),
            payload: ProfileRowPayload::Error {
                error: "connection refused".into(),
            },
        };
        let v: serde_json::Value = serde_json::to_value(&row).unwrap();
        assert_eq!(v["profile"], "prod");
        assert_eq!(v["error"], "connection refused");
        assert!(v.get("data").is_none());
    }
}
