//! Alerting & notification routing (feature #8).
//!
//! Honest scope (per draconian review):
//! - **No expression DSL.** Closed enum of 3 predicates.
//! - **3 channels** (Telegram, ntfy.sh, webhook). Email/Gotify/syslog
//!   are deferred — each adds a new dep and edge cases.
//! - **No oncall scheduler / time windows / escalation / ack-via-reply.**
//!   PagerDuty-in-miniature is post-MVP.
//!
//! What's here:
//! - `engine`: pure rule evaluation against a cluster snapshot
//! - `notifier`: per-channel HTTP senders
//! - `dedup`: in-memory suppression window
//! - `Orchestrator`: ties config → engine → notifier together
//!
//! Polling lives in `cli::execute_alerts_watch` — the engine itself
//! is stateless besides the offline-since timestamps it returns/accepts.

pub mod dedup;
pub mod engine;
pub mod notifier;
pub mod types;

pub use dedup::DedupCache;
pub use engine::{evaluate, EngineState};
pub use notifier::{parse_route, send_event, Channel};
pub use types::{AlertEvent, Severity};
