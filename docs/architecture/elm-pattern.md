# Elm pattern

The TUI uses the Elm Architecture: a pure reducer + a side-effect
dispatcher + an event loop. The reducer is sync, total, and trivially
testable.

## Three pieces

```rust
// Pure data
struct AppState { /* views, selections, cache, … */ }

// Discrete user / data events
enum Action {
    KeyPressed(KeyEvent),
    GuestsLoaded(Vec<Guest>),
    HitlApproved { txn_id: String, approved: bool },
    OpenSshSession { vmid: u32 },
    /* ~80 variants */
}

// Things to do (or not) after the reducer
enum SideEffect {
    StartGuest { vmid: u32 },
    OpenSshSession { vmid: u32 },
    ListGuests,
    /* ~30 variants */
}

// The reducer — no I/O, no async
fn update(state: &mut AppState, action: Action) -> Option<SideEffect>;
```

## The loop

```rust
async fn run(...) -> Result<()> {
    let mut state = AppState::new();
    let (data_tx, mut data_rx) = mpsc::channel::<DataMsg>(64);

    // ── Terminal RAII  ──
    let mut term = TerminalGuard::install()?;

    loop {
        tokio::select! {
            // 1. Keyboard input
            key_event = read_key() => {
                let action = event::map_key(&state, key_event);
                if let Some(effect) = update(&mut state, action) {
                    dispatch_side_effect(effect, &state, &client, &data_tx, ...).await;
                }
            }
            // 2. Async results from previous side effects
            Some(msg) = data_rx.recv() => {
                let action = msg.into_action();
                if let Some(effect) = update(&mut state, action) {
                    dispatch_side_effect(effect, ...).await;
                }
            }
            // 3. Periodic poll tick
            _ = tokio::time::sleep(Duration::from_secs(5)) => {
                update(&mut state, Action::Tick);
            }
        }
        term.terminal_mut().draw(|f| views::render(f, &state))?;
    }
}
```

## Why pure reducer

- **Test the whole TUI without a runtime.** Construct an `AppState`,
  feed actions, assert state transitions and emitted side effects.
  Zero mocks, zero tokio.
- **Replay any user session** for regression tests. The 64-test
  `app_test.rs` does exactly this.
- **No race conditions in the reducer.** Single-threaded execution
  by construction.

Compare with stateful imperative TUIs that mix render, input, and
I/O — they are intractable to test and prone to "it works on my
machine" race bugs.

## Side-effect dispatch

`dispatch_side_effect` is the only async function on the hot path.
For a destructive op like `SideEffect::DeleteGuest`:

```rust
match effect {
    SideEffect::DeleteGuest { vmid } => {
        // 1. Pre-flight risk gate (V27.x)
        if !enforce_preflight(client, Op::Delete, &guest, allow_risk).await {
            return;
        }
        // 2. HITL gate (an earlier review)
        if check_hitl("delete", vmid, effect.clone(), policies, hitl_coord).await {
            return; // queued; will arrive as HitlApproved later
        }
        // 3. Actual API call (spawned, non-blocking)
        tokio::spawn(async move {
            let result = client.delete_guest(node, vmid, guest_type).await;
            data_tx.send(DataMsg::TaskStarted(result)).await
        });
    }
    /* … */
}
```

The reducer never sees the API call. It receives `DataMsg::TaskStarted(upid)`
back as another `Action::TaskStarted(upid)` and updates the queue
view. Pure functional core, imperative shell.

## HITL is part of the reducer's contract

When `check_hitl` matches a policy, it:

1. Sends `Action::ApprovalRequested` so the reducer pushes the
   approval view onto the navigation stack.
2. Spawns a task that calls `tg.request_approval` and awaits a
   `oneshot` from `HitlCoordinator`.
3. On callback, sends `Action::ApprovalReceived { txn_id, approved }`
   back through the data channel.
4. The reducer now updates the queue view. If approved, the
   dispatcher executes the original side effect (with `skip_hitl =
   true` to prevent loops).

The reducer is unaware of Telegram. It only knows about
`ApprovalRequested` / `ApprovalReceived`. Mock the bot, test the
state transitions.

## Action / SideEffect / DataMsg contract

The triple is what keeps the reducer pure.

| Layer | Direction | Type |
| :--- | :--- | :--- |
| User keypress → reducer | inbound | `Action` |
| Reducer → dispatcher | outbound | `Option<SideEffect>` |
| Dispatcher → reducer | inbound | `DataMsg` (which converts to `Action`) |

`DataMsg` is the side-effect-result envelope. Adding a new
`SideEffect` typically requires a matching `DataMsg::XxxLoaded` /
`DataMsg::XxxFailed` so the reducer can react to completion.

## Why not Redux / signals / channels-everywhere

- Redux toolkit-style "thunks" muddy the pure-vs-effect line. We want
  the line stark.
- Signals (Vue, Solid) reactivity is impossibly heavy for a TUI's
  ~30 fps and hard to test offline.
- Direct channels everywhere lose the "single state machine"
  property — you can't replay a session if events fork at runtime.

The Elm pattern is the right shape for a TUI with discrete
keystrokes, async I/O results, and a need to be testable.

## Pure reducer, pure tests

```rust
// tests/app_test.rs
#[test]
fn approval_received_executes_queued_effect() {
    let mut state = sample_state_with_pending_approval("delete:100");
    let action = Action::ApprovalReceived {
        txn_id: "delete:100".into(),
        approved: true,
    };
    let effect = update(&mut state, action);
    assert!(matches!(effect, Some(SideEffect::DeleteGuest { vmid: 100 })));
    assert_eq!(state.approval_view.pending.len(), 0);
}
```

64 tests in `app_test.rs` follow this shape. Together with 213 lib
tests, 70 api wiremock tests, and the rest, that's the 380+ passing
suite.

## See also

- [Architecture overview](/architecture/overview)
- [Error handling](/architecture/error-handling) — `ApiError` and the
  reducer's relationship to typed errors
