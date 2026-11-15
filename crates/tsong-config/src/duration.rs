//! Durations written the way people write them: `"15m"`, `"30s"`.

use std::time::Duration;

use serde::{Deserialize, Deserializer, de::Error};

pub fn deserialize<'de, D: Deserializer<'de>>(deserializer: D) -> Result<Duration, D::Error> {
    let text = String::deserialize(deserializer)?;
    humantime::parse_duration(&text).map_err(D::Error::custom)
}
