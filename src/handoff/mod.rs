//! External console handoff (feature #1c) — SPICE + noVNC.
//!
//! Per the original review: rendering graphical frames inside a TUI is
//! impossible to do well. Every other Proxmox tool (web UI, pvetui,
//! PDM) hands off to an external client; we do the same.
//!
//! Two paths:
//! - `spice`: write a virt-viewer `.vv` `ConfigFile`, launch
//!   `remote-viewer` (preferred) or fall back to system default.
//! - `novnc`: build a deep-link URL into the Proxmox web UI's console
//!   panel, open in the user's browser.
//!
//! No frame data ever flows through proxxx — we just coordinate the
//! handoff and exit.

pub mod launcher;
pub mod novnc;
pub mod spice;

pub use launcher::{open_spice_vv, open_with_default, which};
pub use novnc::{build_novnc_url, token_page_url};
pub use spice::{write_vv_at, write_vv_file};
