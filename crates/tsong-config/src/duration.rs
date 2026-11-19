//! Durations in .NET's `TimeSpan` constant format, `[d.]hh:mm:ss[.fffffff]`:
//! `"00:15:00"` is 15 minutes, `"1.01:00:00"` 25 hours, `"00:00:00.05"`
//! 50 milliseconds.

use std::time::Duration;

use serde::{Deserialize, Deserializer, de::Error};

/// Why text isn't a duration.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error(
    "a duration must be [d.]hh:mm:ss[.fffffff], such as \"00:15:00\", with hours under 24 and minutes and seconds under 60"
)]
pub struct DurationError;

const SECONDS_PER_DAY: u64 = 24 * 60 * 60;

/// Parses `[d.]hh:mm:ss[.fffffff]`: optional whole days and a dot, then
/// two-digit hours under 24, minutes and seconds under 60, then an
/// optional fraction of a second of one to seven digits.
pub fn parse_duration(text: &str) -> Result<Duration, DurationError> {
    let (head, rest) = text.split_once(':').ok_or(DurationError)?;
    let (days, hours) = match head.split_once('.') {
        Some((days, hours)) => (number(days, 1..=20)?, hours),
        None => (0, head),
    };
    let (minutes, rest) = rest.split_once(':').ok_or(DurationError)?;
    let (seconds, fraction) = match rest.split_once('.') {
        Some((seconds, fraction)) => (seconds, Some(fraction)),
        None => (rest, None),
    };
    let hours = below(number(hours, 2..=2)?, 24)?;
    let minutes = below(number(minutes, 2..=2)?, 60)?;
    let seconds = below(number(seconds, 2..=2)?, 60)?;
    let nanos = match fraction {
        None => 0,
        Some(fraction) => {
            let digits = u32::try_from(fraction.len()).map_err(|_| DurationError)?;
            let value = number(fraction, 1..=7)?;
            let scale = 10u64.pow(9u32.saturating_sub(digits));
            u32::try_from(value * scale).map_err(|_| DurationError)?
        }
    };
    let whole = days
        .checked_mul(SECONDS_PER_DAY)
        .and_then(|days| days.checked_add(hours * 3600 + minutes * 60 + seconds))
        .ok_or(DurationError)?;
    Ok(Duration::new(whole, nanos))
}

/// `text` as a number, when it is only ASCII digits and its length is in
/// `lengths`.
fn number(text: &str, lengths: std::ops::RangeInclusive<usize>) -> Result<u64, DurationError> {
    if !lengths.contains(&text.len()) || !text.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(DurationError);
    }
    text.parse().map_err(|_| DurationError)
}

fn below(value: u64, limit: u64) -> Result<u64, DurationError> {
    if value < limit {
        Ok(value)
    } else {
        Err(DurationError)
    }
}

pub fn deserialize<'de, D: Deserializer<'de>>(deserializer: D) -> Result<Duration, D::Error> {
    let text = String::deserialize(deserializer)?;
    parse_duration(&text).map_err(D::Error::custom)
}

/// An optional duration: absent is `None`.
pub mod option {
    use super::*;

    pub fn deserialize<'de, D: Deserializer<'de>>(
        deserializer: D,
    ) -> Result<Option<Duration>, D::Error> {
        super::deserialize(deserializer).map(Some)
    }
}
