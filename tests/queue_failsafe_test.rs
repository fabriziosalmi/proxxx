#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]
//! Operation-queue crash-recovery idempotency — the reducer-level contract
//! behind "proxxx crashed mid-op; does it re-execute on restart?".
//!
//! The `op_queue` persists INTENT + status. On restart the queue is re-rendered
//! (not auto-run) and only a user-triggered `ExecuteQueue` dispatches. The
//! load-bearing safety property: `ExecuteQueue` dispatches ONLY `Pending` ops —
//! so an op that was already dispatched (restored as `Running`) is NEVER
//! re-executed. Combined with the write-ahead persist in `dispatch_side_effect`
//! (status → Running is durable before any PVE call), a crash cannot turn into
//! a double-execute of a non-idempotent op (migrate / delete / move-disk).
//!
//! These pin the pure reducer half; the write-ahead ordering lives in the async
//! TUI dispatch and is covered by review + the AR-6 threat note.

use proxxx::app::queue::{OpStatus, QueuedOp};
use proxxx::app::{update, Action, AppState, SideEffect};

fn qop(id: &str, status: OpStatus) -> QueuedOp {
    QueuedOp {
        id: id.into(),
        action: Box::new(Action::MigrateGuest {
            vmid: 100,
            target_node: "pve2".into(),
        }),
        description: format!("op {id}"),
        diff: String::new(),
        status,
        created_at_secs: 0,
        bypass_preflight: false,
    }
}

#[test]
fn execute_queue_dispatches_only_pending_never_restored_running() {
    let mut state = AppState::new();
    // A queue as it would look after restart: a mix of a still-pending op and
    // ops restored from disk in every non-pending state.
    state.op_queue = vec![
        qop("pending-1", OpStatus::Pending),
        qop("running-restored", OpStatus::Running),
        qop("success-restored", OpStatus::Success),
        qop("error-restored", OpStatus::Error("boom".into())),
        qop("pending-2", OpStatus::Pending),
    ];

    let effect = update(&mut state, Action::ExecuteQueue);

    // Only the two Pending ops are handed to the dispatcher.
    let Some(SideEffect::ExecuteQueue(dispatched)) = effect else {
        panic!("ExecuteQueue must return a dispatch side-effect");
    };
    let ids: Vec<&str> = dispatched.iter().map(|o| o.id.as_str()).collect();
    assert_eq!(
        ids,
        vec!["pending-1", "pending-2"],
        "ONLY previously-Pending ops may dispatch — a restored Running op must never re-execute"
    );

    // In-memory state: Pending → Running; every other status untouched.
    let by_id = |id: &str| {
        state
            .op_queue
            .iter()
            .find(|o| o.id == id)
            .unwrap()
            .status
            .clone()
    };
    assert_eq!(by_id("pending-1"), OpStatus::Running);
    assert_eq!(by_id("pending-2"), OpStatus::Running);
    assert_eq!(by_id("running-restored"), OpStatus::Running, "unchanged");
    assert_eq!(by_id("success-restored"), OpStatus::Success, "unchanged");
    assert_eq!(
        by_id("error-restored"),
        OpStatus::Error("boom".into()),
        "unchanged"
    );
}

#[test]
fn re_executing_after_restore_is_a_noop_no_double_dispatch() {
    // Simulate: user ran the queue, proxxx persisted Running, then restarted.
    // Everything reloads as Running. Hitting "execute" again must dispatch
    // NOTHING — the crux of crash-recovery idempotency.
    let mut state = AppState::new();
    state.op_queue = vec![qop("a", OpStatus::Running), qop("b", OpStatus::Running)];

    let effect = update(&mut state, Action::ExecuteQueue);

    match effect {
        Some(SideEffect::ExecuteQueue(ops)) => assert!(
            ops.is_empty(),
            "no Pending ops → nothing may be dispatched, got {} op(s)",
            ops.len()
        ),
        None => {} // also acceptable: nothing to do
        other => panic!("unexpected side effect: {other:?}"),
    }
}

#[test]
fn persist_round_trip_preserves_running_status() {
    // The restored status must survive persistence: a dispatched op that was
    // saved as Running must NOT come back as Pending (which would make it
    // re-dispatchable). This is what makes the property above hold across a
    // real save → crash → load cycle.
    let running = qop("x", OpStatus::Running);
    let persisted = running.to_persisted().expect("migrate op is persistable");
    let restored = QueuedOp::from_persisted(persisted);
    assert_eq!(
        restored.status,
        OpStatus::Running,
        "Running must round-trip as Running, never reset to Pending"
    );

    // And the break-glass override must NOT survive a reload (safety default).
    let mut forced = qop("y", OpStatus::Pending);
    forced.bypass_preflight = true;
    let restored_forced = QueuedOp::from_persisted(forced.to_persisted().unwrap());
    assert!(
        !restored_forced.bypass_preflight,
        "a persisted force-override must re-prompt, not silently bypass preflight after restart"
    );
}
