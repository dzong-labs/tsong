//! The audit writer: a thread of its own that writes audit lines to stdout,
//! so recording one never blocks a request.

use std::collections::VecDeque;
use std::io::{BufWriter, Write};
use std::sync::mpsc::{self, RecvTimeoutError};
use std::sync::{Arc, Condvar, Mutex, MutexGuard, PoisonError};
use std::thread::JoinHandle;
use std::time::Duration;

use prometheus_client::metrics::counter::Counter;

use crate::reload::Audit;

/// The lines waiting for the writer.
#[derive(Default)]
struct Queue {
    lines: VecDeque<String>,
    closed: bool,
}

/// What the callers and the writer thread share.
#[derive(Default)]
struct Shared {
    queue: Mutex<Queue>,
    ready: Condvar,
}

impl Shared {
    fn queue(&self) -> MutexGuard<'_, Queue> {
        self.queue.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

/// Audit lines written by a thread of their own. The queue holds up to
/// `capacity` lines. A line is dropped and counted when the queue is full,
/// when its write fails, or when it is recorded after closing. Lines keep
/// the order they were recorded in.
pub struct Queued {
    shared: Arc<Shared>,
    capacity: usize,
    dropped: Counter,
    shutdown: Duration,
    /// Disconnected when the writer thread ends.
    finished: Mutex<mpsc::Receiver<()>>,
    writer: Mutex<Option<JoinHandle<()>>>,
}

impl Queued {
    /// Starts the thread that writes to `writer` through a buffer, flushing
    /// whenever the queue runs empty.
    pub fn spawn<W: Write + Send + 'static>(
        writer: W,
        capacity: usize,
        dropped: Counter,
        shutdown: Duration,
    ) -> std::io::Result<Self> {
        let shared = Arc::new(Shared::default());
        let (finished_sender, finished) = mpsc::channel::<()>();
        let thread_shared = shared.clone();
        let thread_dropped = dropped.clone();
        let handle = std::thread::Builder::new()
            .name("audit".into())
            .spawn(move || {
                // Dropped when the thread ends, which is what `close` waits for.
                let _finished = finished_sender;
                write_lines(&thread_shared, writer, &thread_dropped);
            })?;
        Ok(Self {
            shared,
            capacity,
            dropped,
            shutdown,
            finished: Mutex::new(finished),
            writer: Mutex::new(Some(handle)),
        })
    }

    /// Writes what is queued and stops the writer, waiting at most the
    /// shutdown deadline. A writer still stuck then, such as on a stalled
    /// stdout, is left behind, and the lines still queued are discarded and
    /// counted as dropped. It blocks, so call it outside async code. Later
    /// lines are dropped and counted.
    pub fn close(&self) {
        self.shared.queue().closed = true;
        self.shared.ready.notify_all();
        let Some(writer) = self
            .writer
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .take()
        else {
            return;
        };
        let finished = self
            .finished
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .recv_timeout(self.shutdown);
        match finished {
            Err(RecvTimeoutError::Disconnected) | Ok(()) => {
                let _ = writer.join();
            }
            Err(RecvTimeoutError::Timeout) => {
                // Clear the queue under the lock, so a writer that comes
                // unstuck can't write lines counted here.
                let unwritten: Vec<String> = self.shared.queue().lines.drain(..).collect();
                self.count_dropped(unwritten.len());
            }
        }
    }

    fn count_dropped(&self, lines: usize) {
        self.dropped
            .inc_by(u64::try_from(lines).unwrap_or(u64::MAX));
    }
}

/// Writes lines as they arrive until the queue is closed and empty. The
/// lines of a batch whose write or flush fails, such as on a closed
/// stdout or a full disk, are counted as dropped, and the buffer is
/// discarded so they aren't counted twice.
fn write_lines<W: Write>(shared: &Shared, writer: W, dropped: &Counter) {
    let mut writer = BufWriter::new(writer);
    loop {
        let batch: Vec<String> = {
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
            queue.lines.drain(..).collect()
        };
        let written = batch
            .iter()
            .try_for_each(|line| writeln!(writer, "{line}"))
            .and_then(|()| writer.flush());
        if written.is_err() {
            dropped.inc_by(u64::try_from(batch.len()).unwrap_or(u64::MAX));
            let (inner, _unwritten) = writer.into_parts();
            writer = BufWriter::new(inner);
        }
    }
}

impl Audit for Queued {
    fn record(&self, line: &str) {
        let mut queue = self.shared.queue();
        if !queue.closed && queue.lines.len() < self.capacity {
            queue.lines.push_back(line.to_owned());
            drop(queue);
            self.shared.ready.notify_one();
        } else {
            drop(queue);
            self.dropped.inc();
        }
    }
}

impl Drop for Queued {
    fn drop(&mut self) {
        self.close();
    }
}
