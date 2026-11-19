//! Parses arbitrary text as a config and as a bootstrap file: neither may
//! panic.

#![no_main]

use libfuzzer_sys::fuzz_target;
use tsong_config::{Bootstrap, Config};

fuzz_target!(|data: &[u8]| {
    let Ok(text) = std::str::from_utf8(data) else {
        return;
    };
    let _ = Config::from_toml(text);
    let _ = Bootstrap::from_toml(text);
});
