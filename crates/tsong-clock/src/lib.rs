//! The time Tsong reads, injected so tests can set it.
//!
//! [`SystemClock`] reads the system's clock. `ManualClock`, behind the
//! `test-util` feature, is set by hand.

use std::time::{Duration, SystemTime, UNIX_EPOCH};

/// A source of the current time.
pub trait Clock: Send + Sync {
    /// Now.
    fn now(&self) -> SystemTime;

    /// Now, in whole seconds since the Unix epoch: the unit of JWT time
    /// claims. Zero before the epoch.
    fn unix_seconds(&self) -> u64 {
        self.now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or(Duration::ZERO)
            .as_secs()
    }
}

/// The system's clock.
#[derive(Debug, Clone, Copy, Default)]
pub struct SystemClock;

impl Clock for SystemClock {
    fn now(&self) -> SystemTime {
        SystemTime::now()
    }
}

#[cfg(feature = "test-util")]
mod manual {
    use std::sync::Mutex;
    use std::time::{Duration, SystemTime, UNIX_EPOCH};

    use crate::Clock;

    /// A clock a test sets by hand. Starts at the given Unix second.
    #[derive(Debug)]
    pub struct ManualClock(Mutex<SystemTime>);

    impl ManualClock {
        pub fn at(unix_seconds: u64) -> Self {
            Self(Mutex::new(UNIX_EPOCH + Duration::from_secs(unix_seconds)))
        }

        /// Moves the clock forward.
        pub fn advance(&self, by: Duration) {
            let mut now = self
                .0
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            *now += by;
        }
    }

    impl Clock for ManualClock {
        fn now(&self) -> SystemTime {
            *self
                .0
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
        }
    }
}

#[cfg(feature = "test-util")]
pub use manual::ManualClock;
