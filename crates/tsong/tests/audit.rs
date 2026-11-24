//! The audit writer: its own thread, a bounded queue, and a bounded
//! shutdown.

use std::error::Error;
use std::io::Write;
use std::sync::mpsc::{self, Receiver, Sender};
use std::sync::{Arc, Condvar, Mutex, PoisonError};
use std::time::{Duration, Instant};

use prometheus_client::metrics::counter::Counter;
use tsong::audit::Audit;
use tsong::audit::Queued;

type TestResult<T = ()> = Result<T, Box<dyn Error + Send + Sync>>;

/// How long a test waits for the writer thread to reach its writer.
const WAIT: Duration = Duration::from_secs(5);

/// A writer that holds what it is given. Each write reports that it was
/// entered, then waits for the gate to open.
#[derive(Clone)]
struct Gated {
    written: Arc<Mutex<Vec<u8>>>,
    gate: Arc<(Mutex<bool>, Condvar)>,
    entered: Sender<()>,
}

impl Gated {
    fn new(open: bool) -> (Self, Receiver<()>) {
        let (entered, receiver) = mpsc::channel();
        let gated = Self {
            written: Arc::default(),
            gate: Arc::new((Mutex::new(open), Condvar::new())),
            entered,
        };
        (gated, receiver)
    }

    fn open(&self) {
        let (open, changed) = &*self.gate;
        *open.lock().unwrap_or_else(PoisonError::into_inner) = true;
        changed.notify_all();
    }

    fn lines(&self) -> TestResult<Vec<String>> {
        let written = self.written.lock().unwrap_or_else(PoisonError::into_inner);
        let text = String::from_utf8(written.clone())?;
        Ok(text.lines().map(str::to_owned).collect())
    }
}

impl Write for Gated {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        let _ = self.entered.send(());
        let (open, changed) = &*self.gate;
        let mut open = open.lock().unwrap_or_else(PoisonError::into_inner);
        while !*open {
            open = changed.wait(open).unwrap_or_else(PoisonError::into_inner);
        }
        self.written
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .extend_from_slice(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

#[test]
fn lines_are_written_in_order_by_their_own_thread() -> TestResult {
    let (writer, _entered) = Gated::new(true);
    let dropped = Counter::<u64>::default();
    let queued = Queued::spawn(writer.clone(), 16, dropped.clone(), WAIT)?;
    for n in 0..10 {
        queued.record(&format!("{n}"));
    }
    drop(queued);
    let expected: Vec<String> = (0..10).map(|n| n.to_string()).collect();
    assert_eq!(writer.lines()?, expected);
    assert_eq!(dropped.get(), 0);
    Ok(())
}

#[test]
fn a_full_queue_drops_and_counts_without_blocking() -> TestResult {
    let (writer, entered) = Gated::new(false);
    let dropped = Counter::<u64>::default();
    let queued = Queued::spawn(writer.clone(), 2, dropped.clone(), WAIT)?;
    queued.record("first");
    entered.recv_timeout(WAIT)?;
    for n in 0..5 {
        queued.record(&format!("{n}"));
    }
    assert_eq!(dropped.get(), 3);
    writer.open();
    drop(queued);
    assert_eq!(writer.lines()?, ["first", "0", "1"]);
    Ok(())
}

#[test]
fn shutdown_leaves_a_stuck_writer_behind_and_counts_what_it_never_wrote() -> TestResult {
    let (writer, entered) = Gated::new(false);
    let dropped = Counter::<u64>::default();
    let queued = Queued::spawn(
        writer.clone(),
        4,
        dropped.clone(),
        Duration::from_millis(50),
    )?;
    queued.record("first");
    entered.recv_timeout(WAIT)?;
    queued.record("second");
    queued.record("third");
    let started = Instant::now();
    queued.close();
    assert!(started.elapsed() < WAIT, "shutdown waited too long");
    assert_eq!(dropped.get(), 2, "the queued lines, not the one mid-write");
    queued.record("late");
    assert_eq!(dropped.get(), 3, "a line after closing is dropped");

    // Unstuck, the writer finishes its write but nothing counted as dropped.
    writer.open();
    let deadline = Instant::now() + WAIT;
    while writer.lines()?.is_empty() && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(5));
    }
    std::thread::sleep(Duration::from_millis(50));
    assert_eq!(writer.lines()?, ["first"]);
    drop(queued);
    assert_eq!(dropped.get(), 3);
    Ok(())
}

/// A writer whose every write fails, as a closed stdout's does.
struct Broken;

impl Write for Broken {
    fn write(&mut self, _: &[u8]) -> std::io::Result<usize> {
        Err(std::io::ErrorKind::BrokenPipe.into())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Err(std::io::ErrorKind::BrokenPipe.into())
    }
}

#[test]
fn lines_whose_write_fails_are_counted_once() -> TestResult {
    let dropped = Counter::<u64>::default();
    let queued = Queued::spawn(Broken, 16, dropped.clone(), WAIT)?;
    queued.record("one");
    queued.record("two");
    queued.record("three");
    queued.close();
    assert_eq!(dropped.get(), 3);
    Ok(())
}
