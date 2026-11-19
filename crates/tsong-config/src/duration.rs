//! Durations in .NET's `TimeSpan` constant format, `[d.]hh:mm:ss[.fffffff]`,
//! written as a quoted string: `"00:15:00"` is 15 minutes, `"1.01:00:00"`
//! 25 hours, `"00:00:00.05"` 50 milliseconds.

use std::ops::RangeInclusive;
use std::time::Duration;

use serde::{Deserialize, Deserializer, de::Error};
use toml::Value;

/// Why text isn't a duration.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error(
    "a duration must be [d.]hh:mm:ss[.fffffff], such as \"00:15:00\", with hours under 24 and minutes and seconds under 60"
)]
pub struct DurationError;

/// Why a duration isn't a string. Unquoted, `00:15:00` is a TOML time of
/// day.
const NOT_A_STRING: &str =
    "a duration is a quoted string, such as \"00:15:00\", in the form [d.]hh:mm:ss[.fffffff]";

const SECONDS_PER_DAY: u64 = 24 * 60 * 60;

/// Parses `[d.]hh:mm:ss[.fffffff]`: optional whole days and a dot, then
/// two-digit hours under 24, minutes and seconds under 60, then an
/// optional fraction of a second of one to seven digits.
fn parse_duration(text: &str) -> Result<Duration, DurationError> {
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
    // Seven digits at most, so the nanoseconds stay under a billion.
    let nanos = match fraction {
        None => 0,
        Some(fraction) => number(fraction, 1..=7)? * 10u64.pow(9 - fraction.len() as u32),
    };
    let whole = days
        .checked_mul(SECONDS_PER_DAY)
        .and_then(|days| days.checked_add(hours * 3600 + minutes * 60 + seconds))
        .ok_or(DurationError)?;
    Duration::from_secs(whole)
        .checked_add(Duration::from_nanos(nanos))
        .ok_or(DurationError)
}

/// `text` as a number, when it is only ASCII digits and its length is in
/// `lengths`.
fn number(text: &str, lengths: RangeInclusive<usize>) -> Result<u64, DurationError> {
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
    match Value::deserialize(deserializer) {
        Ok(Value::String(text)) => parse_duration(&text).map_err(D::Error::custom),
        _ => Err(D::Error::custom(NOT_A_STRING)),
    }
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_duration_is_days_hours_minutes_seconds_and_a_fraction() {
        for (text, expected) in [
            ("00:00:00", Duration::ZERO),
            ("00:00:30", Duration::from_secs(30)),
            ("00:15:00", Duration::from_secs(15 * 60)),
            ("01:00:00", Duration::from_secs(3600)),
            ("23:59:59", Duration::from_secs(86_399)),
            ("1.00:00:00", Duration::from_secs(86_400)),
            ("1.01:00:00", Duration::from_secs(25 * 3600)),
            ("365.00:00:00", Duration::from_secs(365 * 86_400)),
            ("00:00:00.5", Duration::from_millis(500)),
            ("00:00:00.05", Duration::from_millis(50)),
            ("00:00:01.250", Duration::from_millis(1250)),
            ("00:00:00.0000001", Duration::from_nanos(100)),
            ("00:00:00.1234567", Duration::from_nanos(123_456_700)),
            ("00:00:00.9999999", Duration::from_nanos(999_999_900)),
            // The longest: u64::MAX seconds and the largest fraction.
            (
                "213503982334601.07:00:15.9999999",
                Duration::new(u64::MAX, 999_999_900),
            ),
            (
                "2.03:04:05.6",
                Duration::new(2 * 86_400 + 3 * 3600 + 4 * 60 + 5, 600_000_000),
            ),
        ] {
            assert_eq!(parse_duration(text), Ok(expected), "{text}");
        }
    }

    #[test]
    fn anything_else_is_refused() {
        for text in [
            "",
            "15m",
            "30s",
            "PT15M",
            "15:00",
            "0:15:00",
            "00:15:0",
            "000:15:00",
            "24:00:00",
            "1.24:00:00",
            "00:60:00",
            "00:00:60",
            "-00:15:00",
            "+00:15:00",
            " 00:15:00",
            "00:15:00 ",
            ".00:15:00",
            "1.:00:00",
            "1..00:00:00",
            "00:15:00.",
            "00:00:00.12345678",
            "00:00:00.-1",
            "00:00:00.1.2",
            "00:00:00:00",
            "1.2.00:00:00",
            "a.00:00:00",
            "00:aa:00",
            "99999999999999999999.00:00:00",
            "999999999999999999999.00:00:00",
            // One second past u64::MAX seconds.
            "213503982334601.07:00:16",
            "١٢:٠٠:٠٠",
        ] {
            assert_eq!(parse_duration(text), Err(DurationError), "{text:?}");
        }
    }
}
