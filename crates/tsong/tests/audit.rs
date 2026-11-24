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
        queued.record(format!("{n}"));
    }
    queued.close();
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
    queued.record("first".into());
    entered.recv_timeout(WAIT)?;
    for n in 0..5 {
        queued.record(format!("{n}"));
    }
    assert_eq!(dropped.get(), 3);
    writer.open();
    queued.close();
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
    queued.record("first".into());
    entered.recv_timeout(WAIT)?;
    queued.record("second".into());
    queued.record("third".into());
    let started = Instant::now();
    queued.close();
    assert!(started.elapsed() < WAIT, "shutdown waited too long");
    assert_eq!(dropped.get(), 2, "the queued lines, not the one mid-write");
    queued.record("late".into());
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
    queued.record("one".into());
    queued.record("two".into());
    queued.record("three".into());
    queued.close();
    assert_eq!(dropped.get(), 3);
    Ok(())
}

#[test]
fn dropping_never_waits_for_a_stuck_writer() -> TestResult {
    let (writer, entered) = Gated::new(false);
    let dropped = Counter::<u64>::default();
    let queued = Queued::spawn(writer, 4, dropped.clone(), WAIT)?;
    queued.record("first".into());
    entered.recv_timeout(WAIT)?;
    let started = Instant::now();
    drop(queued);
    assert!(started.elapsed() < WAIT, "dropping waited for the writer");
    assert_eq!(dropped.get(), 0);
    Ok(())
}

/// A writer that waits for its gate on the first write, takes only the
/// first `partial` bytes of the second, fails the third, and takes
/// everything after that.
struct Flaky {
    gated: Gated,
    partial: usize,
    calls: usize,
}

impl Write for Flaky {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        self.calls += 1;
        match self.calls {
            2 => {
                let taken = bytes.get(..self.partial).unwrap_or(bytes);
                self.gated.write(taken)
            }
            3 => Err(std::io::ErrorKind::BrokenPipe.into()),
            _ => self.gated.write(bytes),
        }
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

#[test]
fn a_failed_write_drops_only_unfinished_lines_and_never_runs_lines_together() -> TestResult {
    let (gated, entered) = Gated::new(false);
    let dropped = Counter::<u64>::default();
    let flaky = Flaky {
        gated: gated.clone(),
        partial: "aaaa\nbb".len(),
        calls: 0,
    };
    let queued = Queued::spawn(flaky, 16, dropped.clone(), WAIT)?;
    queued.record("first".into());
    entered.recv_timeout(WAIT)?;
    // These wait together while the first write is held, so they go as one
    // batch, which the writer cuts off inside "bbbb".
    for line in ["aaaa", "bbbb", "cccc"] {
        queued.record(line.into());
    }
    gated.open();
    let deadline = Instant::now() + WAIT;
    while dropped.get() < 2 && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(5));
    }
    queued.record("dddd".into());
    queued.close();
    assert_eq!(dropped.get(), 2, "bbbb and cccc");
    assert_eq!(gated.lines()?, ["first", "aaaa", "bb", "dddd"]);
    Ok(())
}

/// A writer that reports its first write, waits for its gate, then panics
/// on the audit thread. `alive` is dropped as the thread unwinds.
struct Dying {
    gated: Gated,
    alive: Sender<()>,
}

impl Write for Dying {
    #[expect(clippy::panic, reason = "simulates a writer thread that dies")]
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        self.gated.write(bytes)?;
        let _ = self.alive.send(());
        panic!("the audit writer died");
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

#[test]
fn a_writer_that_dies_drops_later_lines_and_close_counts_the_rest() -> TestResult {
    let (gated, entered) = Gated::new(false);
    let (alive, died) = mpsc::channel();
    let dying = Dying {
        gated: gated.clone(),
        alive,
    };
    let dropped = Counter::<u64>::default();
    let queued = Queued::spawn(dying, 16, dropped.clone(), WAIT)?;
    queued.record("first".into());
    entered.recv_timeout(WAIT)?;
    // Queued while the writer is held, so they are left when it dies.
    queued.record("left 1".into());
    queued.record("left 2".into());
    assert_eq!(dropped.get(), 0);
    gated.open();
    // The write's one message, then the disconnect as the thread unwinds.
    died.recv_timeout(WAIT)?;
    let deadline = Instant::now() + WAIT;
    while died.recv_timeout(WAIT).is_ok() && Instant::now() < deadline {}
    // The thread marks itself done just after the writer drops.
    std::thread::sleep(Duration::from_millis(50));
    queued.record("late".into());
    assert_eq!(dropped.get(), 1, "a line after the writer died");
    let started = Instant::now();
    queued.close();
    assert!(started.elapsed() < WAIT, "close waited for a dead writer");
    assert_eq!(dropped.get(), 3, "and the two it left queued");
    assert_eq!(gated.lines()?, ["first"]);
    Ok(())
}
