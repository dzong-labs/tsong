use std::error::Error;
use std::time::Duration;

use tsong_config::{DurationError, parse_duration};

type TestResult<T = ()> = Result<T, Box<dyn Error>>;

#[test]
fn a_duration_is_days_hours_minutes_seconds_and_a_fraction() -> TestResult {
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
        (
            "2.03:04:05.6",
            Duration::new(2 * 86_400 + 3 * 3600 + 4 * 60 + 5, 600_000_000),
        ),
    ] {
        assert_eq!(parse_duration(text), Ok(expected), "{text}");
    }
    Ok(())
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
        "١٢:٠٠:٠٠",
    ] {
        assert_eq!(parse_duration(text), Err(DurationError), "{text:?}");
    }
}

#[test]
fn a_bad_duration_in_a_config_says_what_form_it_takes() -> TestResult {
    let text = include_str!("../../../examples/tsong.toml").replace("\"00:15:00\"", "\"15m\"");
    let error = tsong_config::Config::from_toml(&text)
        .err()
        .ok_or("15m was accepted")?
        .to_string();
    assert!(
        error.contains(r#"a duration must be [d.]hh:mm:ss[.fffffff], such as "00:15:00""#),
        "{error}"
    );
    Ok(())
}
