//! Multi-client read-only fan-out for the fleet view.
//!
//! Mirrors the proven `src/cli/fanout.rs` pattern: enumerate every
//! named profile, build one `PxClient` per profile, fan out
//! concurrently with one task per cluster. A failed cluster yields a
//! [`FleetDataMsg::ClusterError`] and NEVER aborts the others — the
//! same "make progress against the reachable clusters" rule the CLI
//! fanout uses.
//!
//! Read-only by construction: [`fetch_with_gateway`] calls ONLY the
//! `get_nodes` / `get_all_guests` / `get_all_storage_pools` read
//! methods. No write method on `ProxmoxGateway` is referenced anywhere
//! in this file.

use std::sync::Arc;

use anyhow::Result;
use tokio::sync::mpsc::Sender;

use crate::api::types::{Guest, Node, StoragePool};
use crate::api::{ProxmoxGateway, PxClient};

/// Worker → controller. One message per profile per poll cycle. The
/// reducer (`super::apply`) merges by `profile` into `FleetState`.
#[derive(Debug)]
pub enum FleetDataMsg {
    /// A profile's full read snapshot for this cycle.
    ClusterSnapshot {
        profile: String,
        nodes: Vec<Node>,
        guests: Vec<Guest>,
        storage: Vec<StoragePool>,
    },
    /// A profile failed this cycle (connect / auth / network / panic).
    ClusterError { profile: String, error: String },
    /// Could not even enumerate profiles (config unreadable / empty).
    FatalError(String),
}

/// One `PxClient` per profile, kept across poll cycles (#379).
///
/// The fleet view polls every 10 s. It used to build a new client per
/// profile per cycle: a password profile logged in again each time (360
/// ticket logins an hour per cluster in the PVE auth log), a new TLS pool
/// was set up, and the "Connected to ..." line was logged each time. A
/// client is now built once and reused; `PxClient` renews its own ticket.
/// A cycle that fails drops the profile's client, so the next cycle
/// builds a fresh one (new credentials, a moved endpoint); a profile that
/// left `config.toml` is dropped too.
#[derive(Default)]
pub struct FleetClients {
    clients: std::collections::HashMap<String, Arc<PxClient>>,
}

impl FleetClients {
    /// Number of cached clients.
    #[must_use]
    pub fn len(&self) -> usize {
        self.clients.len()
    }

    /// True when no client is cached.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.clients.is_empty()
    }
}

/// Fan a read-only sweep across every configured profile, sending one
/// message per profile to `tx`. Returns once all per-cluster tasks have
/// reported. Enumeration failure (no/unreadable config) sends a single
/// [`FleetDataMsg::FatalError`] and returns. Clients are reused from
/// `cache` and kept there for the next cycle.
pub async fn fleet_fetch_all(
    cli_secret: Option<&str>,
    tx: &Sender<FleetDataMsg>,
    cache: &mut FleetClients,
) {
    let profiles = match crate::config::list_profiles() {
        Ok(p) if !p.is_empty() => p,
        Ok(_) => {
            let _ = tx
                .send(FleetDataMsg::FatalError(
                    "no named profiles in config.toml — fleet view requires at least one \
                     [profiles.NAME] block (run `proxxx init` for a fresh setup)"
                        .into(),
                ))
                .await;
            return;
        }
        Err(e) => {
            let _ = tx.send(FleetDataMsg::FatalError(format!("{e:#}"))).await;
            return;
        }
    };
    cache.clients.retain(|name, _| profiles.contains(name));

    let secret = cli_secret.map(str::to_owned);
    let mut set = tokio::task::JoinSet::new();
    for profile in profiles {
        let tx = tx.clone();
        let secret = secret.clone();
        let cached = cache.clients.get(&profile).cloned();
        set.spawn(async move {
            let (client, result) = match cached {
                Some(c) => {
                    let r = fetch_with_gateway(c.as_ref()).await;
                    (Some(c), r)
                }
                None => match build_client(&profile, secret.as_deref()).await {
                    Ok(c) => {
                        let r = fetch_with_gateway(c.as_ref()).await;
                        (Some(c), r)
                    }
                    Err(e) => (None, Err(e)),
                },
            };
            let (msg, keep) = match result {
                Ok((nodes, guests, storage)) => (
                    FleetDataMsg::ClusterSnapshot {
                        profile: profile.clone(),
                        nodes,
                        guests,
                        storage,
                    },
                    client,
                ),
                Err(e) => (
                    FleetDataMsg::ClusterError {
                        profile: profile.clone(),
                        error: format!("{e:#}"),
                    },
                    None,
                ),
            };
            let _ = tx.send(msg).await;
            (profile, keep)
        });
    }
    // Drain the JoinSet; each task already sent its own message. A
    // panicked task is swallowed here (its cluster simply shows no
    // update this cycle and stays at its prior state) — it cannot take
    // down the others.
    while let Some(joined) = set.join_next().await {
        if let Ok((profile, keep)) = joined {
            match keep {
                Some(c) => {
                    cache.clients.insert(profile, c);
                }
                None => {
                    cache.clients.remove(&profile);
                }
            }
        }
    }
}

/// Build the client for one profile. Same client-construction path as
/// `fanout.rs::query_one_profile`.
async fn build_client(profile: &str, cli_secret: Option<&str>) -> Result<Arc<PxClient>> {
    let cfg = crate::config::load_config(Some(profile))?;
    Ok(Arc::new(PxClient::new(cfg, cli_secret).await?))
}

/// The read sweep itself, against any `ProxmoxGateway`. Factored out as
/// the testable seam so integration tests can drive it with a
/// wiremock-backed `PxClient` (or any fake) without a config file.
///
/// Reads `/nodes` once and then each online node's guests and storage
/// (#379: the trait-default `get_all_guests` / `get_all_storage_pools`
/// each read `/nodes` again, three times per cycle). A per-node fetch
/// failure propagates rather than silently truncating. The isolation
/// granularity is the PROFILE: a failure here marks the whole cluster
/// unreachable, which is the right grain for an at-a-glance fleet
/// overview.
pub async fn fetch_with_gateway(
    g: &dyn ProxmoxGateway,
) -> Result<(Vec<Node>, Vec<Guest>, Vec<StoragePool>)> {
    let nodes = g.get_nodes().await?;
    let mut guests = Vec::new();
    let mut storage = Vec::new();
    for n in &nodes {
        if matches!(n.status, crate::api::types::NodeStatus::Online) {
            guests.extend(g.get_guests(&n.node).await?);
            storage.extend(g.get_storage_pools(&n.node).await?);
        }
    }
    Ok((nodes, guests, storage))
}
