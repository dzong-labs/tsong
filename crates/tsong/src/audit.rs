//! Where audit lines go: stdout in production, collected by the platform,
//! written by a thread of its own so recording one never blocks a
//! request. The writer's behaviour is described in
//! docs/notes/observability.md.

use std::collections::VecDeque;
use std::io::{BufWriter, Write};
use std::sync::{Arc, Condvar, Mutex, MutexGuard, PoisonError};
use std::thread::JoinHandle;
use std::time::Duration;

use prometheus_client::metrics::counter::Counter;

/// Where audit lines go.
pub trait Audit: Send + Sync {
    fn record(&self, line: &str);
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
    fn record(&self, line: &str) {
        let mut writer = self.0.lock().unwrap_or_else(PoisonError::into_inner);
        let _ = writeln!(writer, "{line}").and_then(|()| writer.flush());
    }
}

/// What the callers, the writer thread and `close` share, under one lock.
#[derive(Default)]
struct Queue {
    lines: VecDeque<String>,
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
/// fails, or when it is recorded after `close`.
pub struct Queued {
    shared: Arc<Shared>,
    capacity: usize,
    dropped: Counter,
    shutdown: Duration,
}

impl Queued {
    /// Starts the thread that writes to `writer` through a buffer, flushing
    /// once per batch: whatever was queued when it last looked.
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
    /// shutdown deadline. A writer still stuck then is left behind, and
    /// the lines still queued are discarded and counted as dropped. It
    /// blocks, so call it outside async code.
    pub fn close(&self) {
        let mut queue = self.shared.queue();
        queue.closed = true;
        let Some(writer) = queue.writer.take() else {
            return;
        };
        self.shared.ready.notify_all();
        let (mut queue, waited) = self
            .shared
            .finished
            .wait_timeout_while(queue, self.shutdown, |queue| !queue.done)
            .unwrap_or_else(PoisonError::into_inner);
        if waited.timed_out() {
            // Cleared under the lock, so a writer that comes unstuck can't
            // write lines counted here.
            count(&self.dropped, queue.lines.len());
            queue.lines.clear();
        } else {
            drop(queue);
            let _ = writer.join();
        }
    }
}

/// Adds `lines` to `counter`.
fn count(counter: &Counter, lines: usize) {
    counter.inc_by(u64::try_from(lines).unwrap_or(u64::MAX));
}

/// Writes batches as they arrive until the queue is closed and empty. A
/// batch whose write or flush fails, such as on a closed stdout or a full
/// disk, is counted as dropped, and the buffer is discarded so it isn't
/// counted twice.
fn write_lines<W: Write>(shared: &Shared, writer: W, dropped: &Counter) {
    let mut writer = BufWriter::new(writer);
    let mut batch = VecDeque::new();
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
        }
        let written = batch
            .iter()
            .try_for_each(|line| {
                writer.write_all(line.as_bytes())?;
                writer.write_all(b"\n")
            })
            .and_then(|()| writer.flush());
        if written.is_err() {
            count(dropped, batch.len());
            let (inner, _unwritten) = writer.into_parts();
            writer = BufWriter::new(inner);
        }
        batch.clear();
    }
}

impl Audit for Queued {
    fn record(&self, line: &str) {
        let mut queue = self.shared.queue();
        if queue.closed || queue.lines.len() >= self.capacity {
            drop(queue);
            self.dropped.inc();
            return;
        }
        let was_empty = queue.lines.is_empty();
        queue.lines.push_back(line.to_owned());
        drop(queue);
        if was_empty {
            self.shared.ready.notify_one();
        }
    }
}

impl Drop for Queued {
    fn drop(&mut self) {
        self.close();
    }
}
