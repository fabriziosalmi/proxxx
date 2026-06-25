//! Shared `#[cfg(test)]` helpers for the `state` module.
//!
//! Houses [`RecordingClient`], an in-process [`StateWriteView`] that records
//! every write it's asked to perform (and can synthesise a failure on a chosen
//! call). Both `apply`'s dispatch tests and `converge`'s orchestration tests
//! drive it, so it lives here instead of inside one module's private `tests`.

use anyhow::Result;
use async_trait::async_trait;

use crate::api::types::{Pool, PoolDetails};
use crate::state::apply::StateWriteView;

/// In-process implementation of [`StateWriteView`] that records every method
/// call. Read methods return empty/default; write methods append a one-line
/// description to `log`. Set `fail_on` to a substring to make any matching call
/// return a synthetic error (used to exercise failure / abort paths).
#[derive(Default)]
pub(crate) struct RecordingClient {
    log: tokio::sync::Mutex<Vec<String>>,
    pub(crate) fail_on: Option<String>,
}

impl RecordingClient {
    /// A client that returns a synthetic error on any call whose recorded
    /// description contains `substr` (used to exercise failure / abort paths).
    pub(crate) fn failing_on(substr: impl Into<String>) -> Self {
        Self {
            fail_on: Some(substr.into()),
            ..Default::default()
        }
    }

    async fn record(&self, entry: String) -> Result<()> {
        if let Some(fail) = &self.fail_on {
            if entry.contains(fail) {
                return Err(anyhow::anyhow!("synthetic failure on {entry}"));
            }
        }
        self.log.lock().await.push(entry);
        Ok(())
    }

    /// Every write the dispatch issued, in order. Empty ⇒ no PVE call was made
    /// (the assertion the dry-run / pre-flight-refusal tests hang on).
    pub(crate) async fn lines(&self) -> Vec<String> {
        self.log.lock().await.clone()
    }
}

#[async_trait]
impl StateWriteView for RecordingClient {
    async fn list_pools_view(&self) -> Result<Vec<Pool>> {
        Ok(vec![])
    }
    async fn get_pool_view(&self, _: &str) -> Result<PoolDetails> {
        Ok(PoolDetails::default())
    }
    async fn create_pool_view(&self, params: &[(&str, &str)]) -> Result<()> {
        self.record(format!("create_pool {params:?}")).await
    }
    async fn update_pool_view(&self, poolid: &str, params: &[(&str, &str)]) -> Result<()> {
        self.record(format!("update_pool({poolid}) {params:?}"))
            .await
    }
    async fn delete_pool_view(&self, poolid: &str) -> Result<()> {
        self.record(format!("delete_pool({poolid})")).await
    }
    async fn modify_acl_view(
        &self,
        path: &str,
        roles: &str,
        users: Option<&str>,
        groups: Option<&str>,
        tokens: Option<&str>,
        propagate: bool,
        delete: bool,
    ) -> Result<()> {
        self.record(format!(
            "modify_acl path={path} roles={roles} users={users:?} groups={groups:?} tokens={tokens:?} propagate={propagate} delete={delete}"
        ))
        .await
    }
    async fn create_cluster_storage_view(&self, params: &[(&str, &str)]) -> Result<()> {
        self.record(format!("create_storage {params:?}")).await
    }
    async fn update_cluster_storage_view(
        &self,
        storage: &str,
        params: &[(&str, &str)],
    ) -> Result<()> {
        self.record(format!("update_storage({storage}) {params:?}"))
            .await
    }
    async fn delete_cluster_storage_view(&self, storage: &str) -> Result<()> {
        self.record(format!("delete_storage({storage})")).await
    }
    async fn create_backup_job_view(&self, params: &[(&str, &str)]) -> Result<()> {
        self.record(format!("create_backup_job {params:?}")).await
    }
    async fn update_backup_job_view(&self, id: &str, params: &[(&str, &str)]) -> Result<()> {
        self.record(format!("update_backup_job({id}) {params:?}"))
            .await
    }
    async fn delete_backup_job_view(&self, id: &str) -> Result<()> {
        self.record(format!("delete_backup_job({id})")).await
    }
    async fn update_cluster_firewall_options_view(&self, params: &[(&str, &str)]) -> Result<()> {
        self.record(format!("update_fw_options {params:?}")).await
    }
    async fn create_cluster_firewall_alias_view(&self, params: &[(&str, &str)]) -> Result<()> {
        self.record(format!("create_fw_alias {params:?}")).await
    }
    async fn update_cluster_firewall_alias_view(
        &self,
        name: &str,
        params: &[(&str, &str)],
    ) -> Result<()> {
        self.record(format!("update_fw_alias({name}) {params:?}"))
            .await
    }
    async fn delete_cluster_firewall_alias_view(&self, name: &str) -> Result<()> {
        self.record(format!("delete_fw_alias({name})")).await
    }
    async fn create_cluster_firewall_ipset_view(&self, params: &[(&str, &str)]) -> Result<()> {
        self.record(format!("create_fw_ipset {params:?}")).await
    }
    async fn delete_cluster_firewall_ipset_view(&self, name: &str) -> Result<()> {
        self.record(format!("delete_fw_ipset({name})")).await
    }
    async fn add_cluster_firewall_ipset_cidr_view(
        &self,
        name: &str,
        params: &[(&str, &str)],
    ) -> Result<()> {
        self.record(format!("add_fw_cidr({name}) {params:?}")).await
    }
    async fn remove_cluster_firewall_ipset_cidr_view(&self, name: &str, cidr: &str) -> Result<()> {
        self.record(format!("remove_fw_cidr({name}, {cidr})")).await
    }
    async fn create_cluster_firewall_group_view(&self, params: &[(&str, &str)]) -> Result<()> {
        self.record(format!("create_fw_group {params:?}")).await
    }
    async fn delete_cluster_firewall_group_view(&self, group: &str) -> Result<()> {
        self.record(format!("delete_fw_group({group})")).await
    }
    async fn create_notification_matcher_view(&self, params: &[(&str, &str)]) -> Result<()> {
        self.record(format!("create_matcher {params:?}")).await
    }
    async fn update_notification_matcher_view(
        &self,
        name: &str,
        params: &[(&str, &str)],
    ) -> Result<()> {
        self.record(format!("update_matcher({name}) {params:?}"))
            .await
    }
    async fn delete_notification_matcher_view(&self, name: &str) -> Result<()> {
        self.record(format!("delete_matcher({name})")).await
    }
    async fn create_ha_rule_view(&self, params: &[(&str, &str)]) -> Result<()> {
        self.record(format!("create_ha_rule {params:?}")).await
    }
    async fn update_ha_rule_view(&self, rule: &str, params: &[(&str, &str)]) -> Result<()> {
        self.record(format!("update_ha_rule({rule}) {params:?}"))
            .await
    }
    async fn delete_ha_rule_view(&self, rule: &str) -> Result<()> {
        self.record(format!("delete_ha_rule({rule})")).await
    }
    async fn create_ha_resource_view(&self, params: &[(&str, &str)]) -> Result<()> {
        self.record(format!("create_ha_resource {params:?}")).await
    }
    async fn update_ha_resource_view(&self, sid: &str, params: &[(&str, &str)]) -> Result<()> {
        self.record(format!("update_ha_resource({sid}) {params:?}"))
            .await
    }
    async fn delete_ha_resource_view(&self, sid: &str) -> Result<()> {
        self.record(format!("delete_ha_resource({sid})")).await
    }
    async fn create_mapping_pci_view(&self, params: &[(&str, &str)]) -> Result<()> {
        self.record(format!("create_mapping_pci {params:?}")).await
    }
    async fn update_mapping_pci_view(&self, id: &str, params: &[(&str, &str)]) -> Result<()> {
        self.record(format!("update_mapping_pci({id}) {params:?}"))
            .await
    }
    async fn delete_mapping_pci_view(&self, id: &str) -> Result<()> {
        self.record(format!("delete_mapping_pci({id})")).await
    }
    async fn create_mapping_usb_view(&self, params: &[(&str, &str)]) -> Result<()> {
        self.record(format!("create_mapping_usb {params:?}")).await
    }
    async fn update_mapping_usb_view(&self, id: &str, params: &[(&str, &str)]) -> Result<()> {
        self.record(format!("update_mapping_usb({id}) {params:?}"))
            .await
    }
    async fn delete_mapping_usb_view(&self, id: &str) -> Result<()> {
        self.record(format!("delete_mapping_usb({id})")).await
    }
}
