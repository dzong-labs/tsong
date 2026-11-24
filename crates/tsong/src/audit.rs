//! Where audit lines go: stdout in production, collected by the platform,
//! written by a thread of its own so recording one never blocks a
//! request. The writer's behaviour is described in
//! docs/notes/observability.md.

use std::collections::VecDeque;
use std::io::Write;
use std::sync::{Arc, Condvar, Mutex, MutexGuard, PoisonError};
use std::thread::JoinHandle;
use std::time::Duration;

use prometheus_client::metrics::counter::Counter;

/// Where audit lines go. A line is taken whole, so a queue keeps it
/// without copying it.
pub trait Audit: Send + Sync {
    fn record(&self, line: String);
}

/// Writes each audit line, and a newline, to a writer as it is recorded.
/// A line that can't be written is dropped; auditing never stops a
/// reload. For tests and quiet states; production writes through
/// [`Queued`].
pub struct Lines<W>(Mutex<W>);

impl<W> Lines<W> {
    pub fn new(writer: W) -> Self {
        Self(Mutex::new(writer))
    }

    /// The writer, with everything written to it.
    pub fn into_inner(self) -> W {
        self.0.into_inner().unwrap_or_else(PoisonError::into_inner)
    }
}

impl<W: Write + Send> Audit for Lines<W> {
    fn record(&self, line: String) {
        let mut writer = self.0.lock().unwrap_or_else(PoisonError::into_inner);
        let _ = writeln!(writer, "{line}").and_then(|()| writer.flush());
    }
}

/// What the callers, the writer thread and `close` share, under one lock.
#[derive(Default)]
struct Queue {
    lines: VecDeque<String>,
    /// The lines of the batch being written, taken off `lines` but not yet
    /// written. They count against the capacity.
    writing: usize,
    /// Set when `close` gave up on a stuck writer and counted its lines,
    /// so the writer counts no more.
    abandoned: bool,
    /// Set by `close`: no more lines are taken.
    closed: bool,
    /// Set when the writer thread ends.
    done: bool,
    /// The writer thread, until `close` takes it.
    writer: Option<JoinHandle<()>>,
}

#[derive(Default)]
struct Shared {
    queue: Mutex<Queue>,
    /// Signalled when the queue gains a line or closes.
    ready: Condvar,
    /// Signalled when the writer thread ends.
    finished: Condvar,
}

impl Shared {
    fn queue(&self) -> MutexGuard<'_, Queue> {
        self.queue.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

/// Marks the writer done when its thread ends, however it ends.
struct Done<'a>(&'a Shared);

impl Drop for Done<'_> {
    fn drop(&mut self) {
        self.0.queue().done = true;
        self.0.finished.notify_all();
    }
}

/// Audit lines written by a thread of their own through a bounded queue.
/// A line is dropped and counted when the queue is full, when its write
/// fails, or when it is recorded after closing or after the writer ended.
pub struct Queued {
    shared: Arc<Shared>,
    capacity: usize,
    dropped: Counter,
    shutdown: Duration,
}

impl Queued {
    /// Starts the thread that writes to `writer`, one batch at a time:
    /// whatever was queued when it last looked, written as one buffer and
    /// flushed once.
    pub fn spawn<W: Write + Send + 'static>(
        writer: W,
        capacity: usize,
        dropped: Counter,
        shutdown: Duration,
    ) -> std::io::Result<Self> {
        let shared = Arc::new(Shared::default());
        let thread_shared = shared.clone();
        let thread_dropped = dropped.clone();
        let handle = std::thread::Builder::new()
            .name("audit".into())
            .spawn(move || {
                let _done = Done(&thread_shared);
                write_lines(&thread_shared, writer, &thread_dropped);
            })?;
        shared.queue().writer = Some(handle);
        Ok(Self {
            shared,
            capacity,
            dropped,
            shutdown,
        })
    }

    /// Writes what is queued and stops the writer, waiting at most the
    /// shutdown deadline. A writer still stuck then is left behind. Either
    /// way, lines still queued or being written, such as those a stuck
    /// writer holds or one that ended early lost, are discarded and counted
    /// as dropped. It blocks, so call it
    /// outside async code.
    pub fn close(&self) {
        let mut queue = self.signal_close();
        let Some(writer) = queue.writer.take() else {
            return;
        };
        let waited;
        (queue, waited) = self
            .shared
            .finished
            .wait_timeout_while(queue, self.shutdown, |queue| !queue.done)
            .unwrap_or_else(PoisonError::into_inner);
        // Cleared under the lock, so a writer that comes unstuck can't write
        // lines counted here.
        // A batch still being written counts too: a stuck writer holds it,
        // and a writer that ended early lost it. A stuck writer counts
        // nothing more if it ever finishes.
        let unwritten = queue.lines.len().saturating_add(queue.writing);
        queue.lines.clear();
        queue.writing = 0;
        queue.abandoned = true;
        count(&self.dropped, unwritten);
        drop(queue);
        if !waited.timed_out() {
            let _ = writer.join();
        }
    }

    /// Stops taking lines and tells the writer to finish, without waiting.
    fn signal_close(&self) -> MutexGuard<'_, Queue> {
        let mut queue = self.shared.queue();
        queue.closed = true;
        self.shared.ready.notify_all();
        queue
    }
}

/// Adds `lines` to `counter`.
fn count(counter: &Counter, lines: usize) {
    counter.inc_by(u64::try_from(lines).unwrap_or(u64::MAX));
}

/// Writes batches as they arrive until the queue is closed and empty.
///
/// Each line is atomic on the stream: a write that fails, such as on a
/// closed stdout or a full disk, counts as dropped only the lines it
/// didn't finish, and if it stopped mid-line, the next batch starts with a
/// newline, so a reader sees a broken line rather than two lines run
/// together. A flush that fails drops nothing more: the writer took every
/// line.
fn write_lines<W: Write>(shared: &Shared, mut writer: W, dropped: &Counter) {
    let mut batch = VecDeque::new();
    let mut bytes = Vec::new();
    let mut ends = Vec::new();
    let mut mid_line = false;
    loop {
        {
            let mut queue = shared.queue();
            while queue.lines.is_empty() && !queue.closed {
                queue = shared
                    .ready
                    .wait(queue)
                    .unwrap_or_else(PoisonError::into_inner);
            }
            if queue.lines.is_empty() {
                return;
            }
            std::mem::swap(&mut queue.lines, &mut batch);
            queue.writing = batch.len();
        }
        bytes.clear();
        ends.clear();
        if mid_line {
            bytes.push(b'\n');
        }
        let start = bytes.len();
        for line in batch.drain(..) {
            bytes.extend_from_slice(line.as_bytes());
            bytes.push(b'\n');
            ends.push(bytes.len());
        }
        let (written, failed) = write_some(&mut writer, &bytes);
        let abandoned = {
            let mut queue = shared.queue();
            queue.writing = 0;
            queue.abandoned
        };
        if failed {
            if !abandoned {
                let finished = ends.iter().filter(|&&end| end <= written).count();
                count(dropped, ends.len().saturating_sub(finished));
            }
            if written >= start {
                mid_line = !ends.contains(&written) && written != start;
            }
        } else {
            mid_line = false;
            let _ = writer.flush();
        }
    }
}

/// Writes as much of `bytes` as `writer` takes, and returns how many bytes
/// it took and whether a write failed before the end.
fn write_some<W: Write>(writer: &mut W, bytes: &[u8]) -> (usize, bool) {
    let mut written = 0;
    while let Some(rest) = bytes.get(written..).filter(|rest| !rest.is_empty()) {
        match writer.write(rest) {
            Ok(0) => return (written, true),
            Ok(taken) => written += taken,
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => {}
            Err(_) => return (written, true),
        }
    }
    (written, false)
}

impl Audit for Queued {
    fn record(&self, line: String) {
        let mut queue = self.shared.queue();
        let held = queue.lines.len().saturating_add(queue.writing);
        if queue.closed || queue.done || held >= self.capacity {
            drop(queue);
            self.dropped.inc();
            return;
        }
        let was_empty = queue.lines.is_empty();
        queue.lines.push_back(line);
        drop(queue);
        if was_empty {
            self.shared.ready.notify_one();
        }
    }
}

impl Drop for Queued {
    /// Signals the writer to finish what is queued, without waiting for
    /// it: dropping must never block. Call [`Queued::close`] off the async
    /// workers to wait and count what a stuck writer left.
    fn drop(&mut self) {
        drop(self.signal_close());
    }
}
