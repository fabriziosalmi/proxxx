# TUI reference

Run `proxxx` with no arguments to enter the TUI. All views render in
ratatui over crossterm; the terminal is restored on every exit path
(happy, `?` early-return, panic).

## Views

| Number | View | Source |
| :---: | :--- | :--- |
| `1` | Dashboard               | `src/tui/views/dashboard.rs` |
| `2` | Nodes                   | `src/tui/views/nodes.rs` |
| `3` | Guests (VM + LXC)       | `src/tui/views/guests.rs` |
| `4` | Storage                 | `src/tui/views/storage.rs` |
|     | Tasks (live log)        | `src/tui/views/tasks.rs` |
|     | Heatmap (`H`)           | `src/tui/views/heatmap.rs` |
|     | Backup board (`B`)      | `src/tui/views/backup.rs` |
|     | Config grep (`G`)       | `src/tui/views/grep.rs` |
|     | Operation queue (`Q`)   | `src/tui/views/queue.rs` |
|     | Audit timeline (`T`)    | `src/tui/views/timeline.rs` |
|     | Snapshot tree (`Z`)     | `src/tui/views/snaptree.rs` |
|     | Compare (drift, `D`)    | `src/tui/views/compare.rs` |
|     | Hardware (`W`)          | `src/tui/views/hardware.rs` |
|     | HA console              | `src/tui/views/ha_console.rs` |
|     | ISO library             | `src/tui/views/iso_library.rs` |
|     | Search                  | `src/tui/views/search.rs` |
|     | Approvals (HITL)        | `src/tui/views/approval.rs` |
|     | SSH session             | `src/tui/views/ssh_session.rs` |

## Keymap

Press `?` inside the TUI for the live keymap reference. Generated
from a single source; the help overlay never drifts from the actual
binding.

### Navigation

| Key | Action |
| :--- | :--- |
| `j` / `Down`   | move selection down |
| `k` / `Up`     | move selection up |
| `Enter` / `l`  | select / drill in |
| `h` / `Esc`    | back / parent view |
| `g` / `G`      | top / bottom |
| `Tab`          | switch pane |
| `q`            | quit |
| `R`            | force refresh |
| `Ctrl+L`       | redraw (recover from SIGCONT after suspend) |

### View switching

| Key | View |
| :--- | :--- |
| `1` Dashboard | `2` Nodes | `3` Guests | `4` Storage |
| `H` Heatmap | `B` Backup | `G` Grep | `Q` Queue | `T` Timeline |
| `Z` Snapshot tree | `D` Compare drift | `W` Hardware passthrough |

### Selection (Guest list)

| Key | Action |
| :--- | :--- |
| `Space`        | toggle selection on current row |
| `V`            | select all visible |
| `t`            | filter / select by tag (prompt) |

### Actions (Guest list)

| Key | Action |
| :--- | :--- |
| `s`            | start selected guest(s) |
| `S`            | graceful shutdown selected |
| `r`            | restart |
| `d`            | delete (with confirm modal) |
| `c`            | open SSH console (`:ssh <vmid>`) |
| `X`            | broadcast guest-agent command |
| `Z`            | open snapshot tree for selected |
| `C`            | execute the operation queue (in queue view) |

### Modes

| Key | Mode |
| :--- | :--- |
| `/`            | fuzzy search across all kinds |
| `:`            | command palette (e.g. `:ssh 100`, `:hw pve1`, `:tree 100`) |
| `Ctrl+K`       | quick-open palette |
| `Ctrl+]`       | exit SSH session (PTY chord) |
| `Ctrl+C`       | quit (always wins) |

## Operation queue

Destructive operations enqueue. The queue view (`Q`) shows pending
items, dry-run output, diff preview, and per-item replay-as-script
export (proxxx CLI / pvesh / curl / Ansible). Press `C` in the queue
view to execute everything; HITL gates fire here if configured.

## Confirm modals

Every destructive operation pops a centered modal. Press `y` or
`Enter` to confirm, `n` or `Esc` to cancel. The modal is rendered
in `Theme::DANGER` colour and clears the background underneath.

## Help overlay

Press `?` anywhere. The overlay is rendered from a single static
keymap table reviewed alongside `event::map_key`. Press any key to
dismiss.

## Theming

The colour palette adapts to terminal background (light / dark
detected at launch). Brand colour is `#2563eb` blue. Status pills:

| Pill | Status |
| :--- | :--- |
| `running`   | green |
| `stopped`   | dim |
| `paused`    | yellow |
| `unknown`   | red |

## Terminal restore

`TerminalGuard` (RAII) wraps the ratatui `Terminal`. Drop teardown
runs on the happy path, on `?` early returns, and after a panic (the
panic hook flight-recorder also fires). You should never end a session
with a broken cooked-mode terminal.
