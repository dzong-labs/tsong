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
    /// Lines taken off the queue but not yet flushed.
    writing: usize,
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
/// `capacity` lines; a line recorded into a full queue is dropped and
/// counted. Lines keep the order they were recorded in. Dropping it
/// writes what is queued, waiting at most the shutdown deadline for a
/// stalled writer before leaving it behind and counting the lines it never
/// wrote as dropped.
pub struct Queued {
    shared: Arc<Shared>,
    capacity: usize,
    dropped: Counter,
    shutdown: Duration,
    /// Disconnected when the writer thread ends.
    finished: Mutex<mpsc::Receiver<()>>,
    writer: Option<JoinHandle<()>>,
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
        let handle = std::thread::Builder::new()
            .name("audit".into())
            .spawn(move || {
                // Dropped when the thread ends, which is what `Drop` waits for.
                let _finished = finished_sender;
                write_lines(&thread_shared, BufWriter::new(writer));
            })?;
        Ok(Self {
            shared,
            capacity,
            dropped,
            shutdown,
            finished: Mutex::new(finished),
            writer: Some(handle),
        })
    }
}

/// Writes lines as they arrive until the queue is closed and empty.
fn write_lines<W: Write>(shared: &Shared, mut writer: BufWriter<W>) {
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
            let batch: Vec<String> = queue.lines.drain(..).collect();
            queue.writing = batch.len();
            batch
        };
        for line in &batch {
            let _ = writeln!(writer, "{line}");
        }
        let _ = writer.flush();
        shared.queue().writing = 0;
    }
}

impl Audit for Queued {
    fn record(&self, line: &str) {
        let mut queue = self.shared.queue();
        if queue.lines.len() < self.capacity {
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
        self.shared.queue().closed = true;
        self.shared.ready.notify_all();
        let finished = self
            .finished
            .get_mut()
            .unwrap_or_else(PoisonError::into_inner)
            .recv_timeout(self.shutdown);
        match finished {
            Err(RecvTimeoutError::Disconnected) | Ok(()) => {
                if let Some(writer) = self.writer.take() {
                    let _ = writer.join();
                }
            }
            Err(RecvTimeoutError::Timeout) => {
                // The writer is stuck, such as on a stalled stdout. Leave it
                // and count what it never wrote.
                drop(self.writer.take());
                let queue = self.shared.queue();
                let unwritten = queue.lines.len().saturating_add(queue.writing);
                drop(queue);
                self.dropped
                    .inc_by(u64::try_from(unwritten).unwrap_or(u64::MAX));
            }
        }
    }
}
