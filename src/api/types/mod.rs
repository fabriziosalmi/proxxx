//! Wire-level types for the Proxmox VE API.
//!
//! Organised by PVE URL category (one submodule per neighbourhood).
//! Every type is re-exported at this module's path so external
//! callers continue to write `crate::api::types::Foo` unchanged.
//!
//! ── Forward-compat deserialization contract ───────────────────
//! PVE has historically renamed and removed fields between point
//! releases. To avoid a single missing key panicking the entire
//! API ingest, every API response struct follows two rules:
//!   1. Every field carries `#[serde(default)]` (or is `Option<T>`).
//!   2. The struct derives `Default` so the struct-level helper has
//!      something to fall back on.
//! Concrete consequence: PVE 8.3 silently dropping `Node.uptime`
//! surfaces as `uptime: 0` (cosmetic) instead of crashing the entire
//! `get_nodes` deserialization.

pub mod access;
pub mod acme;
pub mod backup;
pub mod cluster;
pub mod console;
pub mod firewall;
pub mod guest;
pub mod guest_agent;
pub mod ha;
pub mod node;
pub mod node_hw;
pub mod notifications;
pub mod pool;
pub mod replication;
pub mod storage;
pub mod task;

pub use access::*;
pub use acme::*;
pub use backup::*;
pub use cluster::*;
pub use console::*;
pub use firewall::*;
pub use guest::*;
pub use guest_agent::*;
pub use ha::*;
pub use node::*;
pub use node_hw::*;
pub use notifications::*;
pub use pool::*;
pub use replication::*;
pub use storage::*;
pub use task::*;

/// Tolerant u32 deserializer: accepts JSON number OR JSON string.
/// PVE serializes some numeric fields as strings depending on
/// version + endpoint (e.g. `port: "5900"` from termproxy/vncproxy
/// on PVE 9). Without this, deserialization fails with a confusing
/// "invalid type: string, expected u32" error.
pub(crate) fn deserialize_u32_from_str_or_num<'de, D>(
    deserializer: D,
) -> std::result::Result<u32, D::Error>
where
    D: serde::Deserializer<'de>,
{
    use serde::de;

    struct StrOrNum;
    impl de::Visitor<'_> for StrOrNum {
        type Value = u32;
        fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
            f.write_str("a u32 number or a string containing a u32")
        }
        fn visit_u64<E: de::Error>(self, v: u64) -> std::result::Result<u32, E> {
            u32::try_from(v).map_err(|_| E::custom(format!("u64 {v} doesn't fit in u32")))
        }
        fn visit_i64<E: de::Error>(self, v: i64) -> std::result::Result<u32, E> {
            u32::try_from(v).map_err(|_| E::custom(format!("i64 {v} doesn't fit in u32")))
        }
        fn visit_str<E: de::Error>(self, v: &str) -> std::result::Result<u32, E> {
            v.parse::<u32>()
                .map_err(|e| E::custom(format!("cannot parse {v:?} as u32: {e}")))
        }
        fn visit_string<E: de::Error>(self, v: String) -> std::result::Result<u32, E> {
            self.visit_str(&v)
        }
    }
    deserializer.deserialize_any(StrOrNum)
}

/// Same as [`deserialize_u32_from_str_or_num`] but for `u64`. Used for
/// fields like `ClusterLogEntry::uid` where PVE serializes the row's
/// monotonic id as a JSON string (`"2957"`) rather than a number.
pub(crate) fn deserialize_u64_from_str_or_num<'de, D>(
    deserializer: D,
) -> std::result::Result<u64, D::Error>
where
    D: serde::Deserializer<'de>,
{
    use serde::de;

    struct StrOrNum;
    impl de::Visitor<'_> for StrOrNum {
        type Value = u64;
        fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
            f.write_str("a u64 number or a string containing a u64")
        }
        fn visit_u64<E: de::Error>(self, v: u64) -> std::result::Result<u64, E> {
            Ok(v)
        }
        fn visit_i64<E: de::Error>(self, v: i64) -> std::result::Result<u64, E> {
            u64::try_from(v).map_err(|_| E::custom(format!("i64 {v} doesn't fit in u64")))
        }
        fn visit_str<E: de::Error>(self, v: &str) -> std::result::Result<u64, E> {
            v.parse::<u64>()
                .map_err(|e| E::custom(format!("cannot parse {v:?} as u64: {e}")))
        }
        fn visit_string<E: de::Error>(self, v: String) -> std::result::Result<u64, E> {
            self.visit_str(&v)
        }
    }
    deserializer.deserialize_any(StrOrNum)
}

pub(crate) fn deserialize_bool_from_int<'de, D>(
    deserializer: D,
) -> std::result::Result<bool, D::Error>
where
    D: serde::Deserializer<'de>,
{
    use serde::de;

    struct BoolOrInt;
    impl de::Visitor<'_> for BoolOrInt {
        type Value = bool;
        fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
            formatter.write_str("a boolean or integer 0/1")
        }
        fn visit_bool<E: de::Error>(self, v: bool) -> std::result::Result<bool, E> {
            Ok(v)
        }
        fn visit_i64<E: de::Error>(self, v: i64) -> std::result::Result<bool, E> {
            Ok(v != 0)
        }
        fn visit_u64<E: de::Error>(self, v: u64) -> std::result::Result<bool, E> {
            Ok(v != 0)
        }
    }

    deserializer.deserialize_any(BoolOrInt)
}
