use serde::{Deserialize, Serialize};

use super::deserialize_bool_from_int;

/// One ACL entry. Returned by `GET /access/acl`.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct AclEntry {
    /// ACL path, e.g. `"/"`, `"/vms/100"`, `"/storage/local"`.
    pub path: String,
    /// `"user"` | `"group"` | `"token"`.
    #[serde(rename = "type", default)]
    pub kind: String,
    /// User/group/token id.
    pub ugid: String,
    pub roleid: String,
    /// Whether the permission propagates to children.
    #[serde(
        default = "default_true_int",
        deserialize_with = "deserialize_bool_from_int"
    )]
    pub propagate: bool,
}

const fn default_true_int() -> bool {
    true
}

#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct User {
    /// `<user>@<realm>` — Proxmox's canonical id.
    pub userid: String,
    #[serde(default, deserialize_with = "deserialize_bool_from_int")]
    pub enable: bool,
    #[serde(default)]
    pub email: String,
    #[serde(default)]
    pub firstname: String,
    #[serde(default)]
    pub lastname: String,
    #[serde(default)]
    pub comment: String,
    /// Optional expiration (Unix seconds, 0 = never).
    #[serde(default)]
    pub expire: u64,
}

#[derive(Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct ApiToken {
    pub tokenid: String,
    /// Privilege separation: when true, ACL on the token is independent
    /// from the parent user's ACL (recommended for least-privilege).
    #[serde(
        default = "default_true_int",
        deserialize_with = "deserialize_bool_from_int"
    )]
    pub privsep: bool,
    #[serde(default)]
    pub comment: String,
    #[serde(default)]
    pub expire: u64,
    /// Only set on creation responses. None on list. This is the token
    /// SECRET PVE returns exactly once on `token create` — a live
    /// credential. `Serialize` stays (the `--json` output emits it by
    /// design), but `Debug` is hand-written to redact it so a `{:?}` at
    /// any log site can't leak it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub value: Option<String>,
}

impl std::fmt::Debug for ApiToken {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ApiToken")
            .field("tokenid", &self.tokenid)
            .field("privsep", &self.privsep)
            .field("comment", &self.comment)
            .field("expire", &self.expire)
            .field(
                "value",
                match &self.value {
                    Some(_) => &"Some([REDACTED])",
                    None => &"None",
                },
            )
            .finish()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct Group {
    pub groupid: String,
    #[serde(default)]
    pub comment: String,
    /// Comma-separated user list (Proxmox quirk).
    #[serde(default)]
    pub users: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct Role {
    pub roleid: String,
    /// Comma-separated privilege list (e.g. `"VM.Allocate,VM.Audit"`).
    #[serde(default)]
    pub privs: String,
    /// Built-in roles can't be deleted.
    #[serde(default, deserialize_with = "deserialize_bool_from_int")]
    pub special: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct Realm {
    pub realm: String,
    /// `"pam"` | `"pve"` | `"ad"` | `"ldap"` | `"openid"`.
    #[serde(rename = "type", default)]
    pub kind: String,
    #[serde(default)]
    pub comment: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct TfaEntry {
    /// Internal id (PVE assigns).
    pub id: String,
    /// `"totp"` | `"webauthn"` | `"recovery"` | `"yubico"`.
    #[serde(rename = "type", default)]
    pub kind: String,
    #[serde(default)]
    pub description: String,
    #[serde(default)]
    pub created: u64,
    #[serde(default, deserialize_with = "deserialize_bool_from_int")]
    pub enable: bool,
}
