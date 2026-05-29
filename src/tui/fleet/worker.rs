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

/// Fan a read-only sweep across every configured profile, sending one
/// message per profile to `tx`. Returns once all per-cluster tasks have
/// reported. Enumeration failure (no/unreadable config) sends a single
/// [`FleetDataMsg::FatalError`] and returns.
pub async fn fleet_fetch_all(cli_secret: Option<&str>, tx: &Sender<FleetDataMsg>) {
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

    let secret = cli_secret.map(str::to_owned);
    let mut set = tokio::task::JoinSet::new();
    for profile in profiles {
        let tx = tx.clone();
        let secret = secret.clone();
        set.spawn(async move {
            let msg = match fetch_one_cluster(&profile, secret.as_deref()).await {
                Ok((nodes, guests, storage)) => FleetDataMsg::ClusterSnapshot {
                    profile,
                    nodes,
                    guests,
                    storage,
                },
                Err(e) => FleetDataMsg::ClusterError {
                    profile,
                    error: format!("{e:#}"),
                },
            };
            let _ = tx.send(msg).await;
        });
    }
    // Drain the JoinSet; each task already sent its own message. A
    // panicked task is swallowed here (its cluster simply shows no
    // update this cycle and stays at its prior state) — it cannot take
    // down the others.
    while set.join_next().await.is_some() {}
}

/// Build a fresh `PxClient` for one profile and run the read sweep.
/// Same client-construction path as `fanout.rs::query_one_profile`.
async fn fetch_one_cluster(
    profile: &str,
    cli_secret: Option<&str>,
) -> Result<(Vec<Node>, Vec<Guest>, Vec<StoragePool>)> {
    let cfg = crate::config::load_config(Some(profile))?;
    let client = Arc::new(PxClient::new(cfg, cli_secret).await?);
    fetch_with_gateway(client.as_ref()).await
}

/// The read sweep itself, against any `ProxmoxGateway`. Factored out as
/// the testable seam so integration tests can drive it with a
/// wiremock-backed `PxClient` (or any fake) without a config file.
///
/// Uses the trait-default `get_all_guests` / `get_all_storage_pools`
/// (online nodes only; a per-node fetch failure propagates rather than
/// silently truncating). The isolation granularity is the PROFILE: a
/// failure here marks the whole cluster unreachable, which is the right
/// grain for an at-a-glance fleet overview.
pub async fn fetch_with_gateway(
    g: &dyn ProxmoxGateway,
) -> Result<(Vec<Node>, Vec<Guest>, Vec<StoragePool>)> {
    let nodes = g.get_nodes().await?;
    let guests = g.get_all_guests().await?;
    let storage = g.get_all_storage_pools().await?;
    Ok((nodes, guests, storage))
}
