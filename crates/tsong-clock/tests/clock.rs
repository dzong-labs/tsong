use std::error::Error;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use tsong_clock::{Clock, ManualClock, SystemClock};

type TestResult = Result<(), Box<dyn Error>>;

#[test]
fn the_system_clock_reads_the_system_time() -> TestResult {
    let before = SystemTime::now();
    let now = SystemClock.now();
    assert!(now >= before);
    assert!(now <= SystemTime::now());
    let seconds = SystemClock.unix_seconds();
    let expected = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
    assert!(seconds + 1 >= expected && seconds <= expected);
    Ok(())
}

#[test]
fn a_manual_clock_moves_only_when_told() {
    let clock = ManualClock::at(1_000);
    assert_eq!(clock.unix_seconds(), 1_000);
    clock.advance(Duration::from_secs(90));
    assert_eq!(clock.unix_seconds(), 1_090);
    assert_eq!(clock.now(), UNIX_EPOCH + Duration::from_secs(1_090));
}

struct BeforeEpoch;

impl Clock for BeforeEpoch {
    fn now(&self) -> SystemTime {
        UNIX_EPOCH - Duration::from_secs(5)
    }
}

#[test]
fn before_the_epoch_is_zero_seconds() {
    assert_eq!(BeforeEpoch.unix_seconds(), 0);
}
