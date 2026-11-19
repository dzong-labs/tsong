use std::error::Error;

type TestResult<T = ()> = Result<T, Box<dyn Error>>;

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

#[test]
fn an_unquoted_duration_is_told_to_be_quoted() -> TestResult {
    let sample = include_str!("../../../examples/tsong.toml");
    for unquoted in ["00:15:00", "00:15:00.5"] {
        let text = sample.replace("\"00:15:00\"", unquoted);
        let error = tsong_config::Config::from_toml(&text)
            .err()
            .ok_or("an unquoted duration was accepted")?
            .to_string();
        assert!(
            error.contains(r#"a duration is a quoted string, such as "00:15:00""#),
            "{unquoted}: {error}"
        );
    }
    Ok(())
}
