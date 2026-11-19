//! Reads an arbitrary token endpoint body as a token request: it must
//! never panic.

#![no_main]

use libfuzzer_sys::fuzz_target;
use tsong_issuer::TokenRequest;

fuzz_target!(|data: &[u8]| {
    let _ = serde_urlencoded::from_bytes::<TokenRequest>(data);
});
