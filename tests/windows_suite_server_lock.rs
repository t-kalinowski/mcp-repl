#![cfg(target_os = "windows")]

mod common;

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc;
use std::thread;
use std::time::Duration;

use common::TestResult;

#[test]
fn suite_server_lock_waits_on_each_acquire() -> TestResult<()> {
    let first = common::acquire_suite_server_lock_for_tests()?;
    let started = Arc::new(AtomicBool::new(false));
    let acquired = Arc::new(AtomicBool::new(false));
    let (tx, rx) = mpsc::channel();

    let thread_started = Arc::clone(&started);
    let thread_acquired = Arc::clone(&acquired);
    let waiter = thread::spawn(move || {
        thread_started.store(true, Ordering::SeqCst);
        let second = common::acquire_suite_server_lock_for_tests().expect("second lock");
        thread_acquired.store(true, Ordering::SeqCst);
        tx.send(()).expect("lock acquisition signal");
        drop(second);
    });

    while !started.load(Ordering::SeqCst) {
        thread::sleep(Duration::from_millis(5));
    }
    thread::sleep(Duration::from_millis(50));
    assert!(
        !acquired.load(Ordering::SeqCst),
        "second suite lock acquisition should wait until the first token is dropped"
    );

    drop(first);
    rx.recv_timeout(Duration::from_secs(2))
        .expect("second lock should acquire after the first is released");
    waiter.join().expect("waiter thread should join");
    Ok(())
}
