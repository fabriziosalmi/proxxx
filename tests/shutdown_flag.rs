#![allow(clippy::unwrap_used, clippy::expect_used)]
//! #366: the process-wide shutdown flag. Own test binary, because a request
//! is permanent for the process and would stop every other test's loops.

use proxxx::util::shutdown::{
    is_shutting_down, request_shutdown, sleep_unless_shutdown, wait_for_shutdown_signal,
};
use std::time::Duration;

/// Every waiter sees the request, including one created after it, and
/// `sleep_unless_shutdown` returns early.
#[tokio::test]
async fn a_request_reaches_waiters_created_before_and_after_it() {
    assert!(!is_shutting_down());
    let before = tokio::spawn(wait_for_shutdown_signal());
    tokio::task::yield_now().await;
    request_shutdown();
    tokio::time::timeout(Duration::from_secs(2), before)
        .await
        .expect("a waiter created before the request resolves")
        .expect("join");
    assert!(is_shutting_down());
    tokio::time::timeout(Duration::from_secs(2), wait_for_shutdown_signal())
        .await
        .expect("a waiter created after the request resolves at once");
    assert!(
        !sleep_unless_shutdown(Duration::from_mins(1)).await,
        "the sleep is cut short by the request"
    );
}
