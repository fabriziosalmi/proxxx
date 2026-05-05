// HITL — Human-in-the-Loop approval gates
// Zero new dependencies (reuses reqwest + tokio)

pub mod daemon;
pub mod pending;
pub mod policy;
pub mod telegram;
