use serde::{Deserialize, Serialize};

/// One row of `GET /pools`. Just the id + free-form comment — to see
/// which guests/storages are in a pool you need a separate
/// `GET /pools/{poolid}` call.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct Pool {
    pub poolid: String,
    pub comment: String,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct PoolDetails {
    pub poolid: String,
    pub comment: String,
    pub members: Vec<PoolMember>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct PoolMember {
    /// e.g. `qemu/100`, `lxc/200`, `storage/pve1/local`.
    pub id: String,
    /// `qemu` | `lxc` | `storage`.
    #[serde(rename = "type")]
    pub member_type: String,
    pub node: String,
    pub vmid: u32,
    pub storage: String,
    pub status: String,
    pub name: String,
}
