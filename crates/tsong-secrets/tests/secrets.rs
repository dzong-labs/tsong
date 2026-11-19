use std::error::Error;
use std::sync::Arc;

use tsong_secrets::{
    Env, File, ResolveFuture, Scheme, Secret, SecretError, SecretRef, SecretSource, Secrets,
};

type TestResult<T = ()> = Result<T, Box<dyn Error>>;

/// The error `result` holds, or a test failure when it holds a value.
fn failure<T, E>(result: Result<T, E>) -> TestResult<E> {
    match result {
        Ok(_) => Err("expected an error, got a value".into()),
        Err(error) => Ok(error),
    }
}

/// A source that answers every reference with the same bytes.
struct Fixed(&'static [u8]);

impl SecretSource for Fixed {
    fn resolve<'a>(&'a self, _: &'a SecretRef) -> ResolveFuture<'a> {
        let secret = Secret::new(self.0.to_vec());
        Box::pin(async move { Ok(secret) })
    }
}

#[tokio::test]
async fn an_env_secret_is_its_variable() -> TestResult {
    // PATH is always set and never empty.
    let reference: SecretRef = "env:PATH".parse()?;
    let secret = Secrets::default().resolve(&reference).await?;
    assert_eq!(secret.expose(), std::env::var("PATH")?.as_bytes());
    Ok(())
}

#[tokio::test]
async fn an_unset_variable_is_reported() -> TestResult {
    let reference = "env:TSONG_TEST_SECRET_THAT_IS_NEVER_SET".parse()?;
    let error = failure(Env.resolve(&reference).await)?;
    assert!(matches!(error, SecretError::NotSet(_)));
    assert_eq!(
        error.to_string(),
        "secret env:TSONG_TEST_SECRET_THAT_IS_NEVER_SET is not set"
    );
    Ok(())
}

#[tokio::test]
async fn a_file_secret_is_its_bytes() -> TestResult {
    let dir = tempfile::tempdir()?;
    let path = dir.path().join("secret");
    std::fs::write(&path, b"s3cret\n")?;
    let reference = format!("file:{}", path.display()).parse()?;
    let secret = Secrets::default().resolve(&reference).await?;
    assert_eq!(secret.expose(), b"s3cret\n");
    Ok(())
}

#[tokio::test]
async fn a_missing_file_is_reported() -> TestResult {
    let dir = tempfile::tempdir()?;
    let path = dir.path().join("missing");
    let reference = format!("file:{}", path.display()).parse()?;
    let error = failure(File.resolve(&reference).await)?;
    assert!(matches!(error, SecretError::Read { .. }));
    let prefix = format!("reading secret file:{}: ", path.display());
    assert!(error.to_string().starts_with(&prefix), "{error}");
    Ok(())
}

#[tokio::test]
async fn an_empty_secret_is_refused() -> TestResult {
    let dir = tempfile::tempdir()?;
    let path = dir.path().join("empty");
    std::fs::write(&path, b"")?;
    let reference = format!("file:{}", path.display()).parse()?;
    let error = failure(Secrets::default().resolve(&reference).await)?;
    assert_eq!(
        error.to_string(),
        format!("secret file:{} is empty", path.display())
    );
    Ok(())
}

#[tokio::test]
async fn each_scheme_goes_to_its_own_source() -> TestResult {
    let secrets = Secrets::empty()
        .with(Scheme::Env, Arc::new(Fixed(b"from env")))
        .with(Scheme::File, Arc::new(Fixed(b"from file")));
    let env = secrets.resolve(&"env:A".parse()?).await?;
    let file = secrets.resolve(&"file:/a".parse()?).await?;
    assert_eq!(env.expose(), b"from env");
    assert_eq!(file.expose(), b"from file");
    Ok(())
}

#[tokio::test]
async fn a_scheme_without_a_source_is_refused() -> TestResult {
    let secrets = Secrets::empty().with(Scheme::File, Arc::new(Fixed(b"x")));
    let error = failure(secrets.resolve(&"env:A".parse()?).await)?;
    assert_eq!(error.to_string(), "no source reads env secrets");
    Ok(())
}

#[test]
fn debug_never_shows_a_secret() {
    let secret = Secret::new(b"s3cret".to_vec());
    assert_eq!(format!("{secret:?}"), "Secret(..)");
    assert_eq!(format!("{:?}", Secrets::default()), "{Env, File}");
}
