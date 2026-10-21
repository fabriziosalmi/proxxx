//! PVE and PBS responses are deserialized into the API types, several with
//! hand-written deserializers (0/1 booleans, numbers as strings). A response
//! body is attacker-controlled when the node is: deserializing must never
//! panic.
#![no_main]

use libfuzzer_sys::fuzz_target;
use proxxx::api::types::{
    ClusterResource, Guest, HaManagerStatus, Node, NodeStatusDetail, StoragePool, TaskStatus,
};

fuzz_target!(|data: &[u8]| {
    let _ = serde_json::from_slice::<Vec<Node>>(data);
    let _ = serde_json::from_slice::<Vec<Guest>>(data);
    let _ = serde_json::from_slice::<Vec<ClusterResource>>(data);
    let _ = serde_json::from_slice::<Vec<StoragePool>>(data);
    let _ = serde_json::from_slice::<NodeStatusDetail>(data);
    let _ = serde_json::from_slice::<TaskStatus>(data);
    let _ = serde_json::from_slice::<HaManagerStatus>(data);
});
