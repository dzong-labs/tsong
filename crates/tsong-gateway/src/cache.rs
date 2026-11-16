//! The read-through cache of exchanged tokens.

use std::sync::Arc;
use std::time::{Duration, Instant};

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use moka::Expiry;
use moka::future::Cache;
use serde_json::Value;
use sha2::{Digest, Sha256};
use tsong_clock::Clock;
use tsong_issuer::{ExchangeError, TokenResponse};

use crate::Exchanger;

/// An inbound token's SHA-256 and the route host it was exchanged for.
/// The cache never holds an inbound token in the clear.
type Key = ([u8; 32], String);

/// An exchanged token and how long the cache keeps it.
#[derive(Clone)]
struct Minted {
    token: Arc<str>,
    lifetime: Duration,
}

/// Expires each entry after its own lifetime.
struct PerEntry;

impl Expiry<Key, Minted> for PerEntry {
    fn expire_after_create(&self, _: &Key, minted: &Minted, _: Instant) -> Option<Duration> {
        Some(minted.lifetime)
    }
}

/// Exchanged tokens, keyed by inbound token and route host. A miss
/// exchanges the token; concurrent misses on one key share one exchange.
/// Failed exchanges are not kept.
pub struct ExchangeCache {
    cache: Cache<Key, Minted>,
    exchanger: Arc<dyn Exchanger>,
    clock: Arc<dyn Clock>,
    clock_skew: Duration,
}

impl ExchangeCache {
    pub fn new(
        exchanger: Arc<dyn Exchanger>,
        clock: Arc<dyn Clock>,
        max_entries: u64,
        clock_skew: Duration,
    ) -> Self {
        Self {
            cache: Cache::builder()
                .max_capacity(max_entries)
                .expire_after(PerEntry)
                .build(),
            exchanger,
            clock,
            clock_skew,
        }
    }

    /// The token `inbound` exchanges for at `host`, from the cache or a
    /// new exchange.
    pub async fn token(&self, inbound: &str, host: &str) -> Result<Arc<str>, Arc<ExchangeError>> {
        let key = (Sha256::digest(inbound.as_bytes()).into(), host.to_owned());
        let minted = self
            .cache
            .try_get_with(key, async {
                let response = self.exchanger.exchange(inbound, host).await?;
                let lifetime = lifetime(&response, self.clock.unix_seconds(), self.clock_skew);
                Ok::<_, ExchangeError>(Minted {
                    token: response.access_token.into(),
                    lifetime,
                })
            })
            .await?;
        Ok(minted.token)
    }
}

/// How long an exchanged token stays cached: until its `exp`, read from
/// its payload, less the clock skew. `expires_in` stands in for `exp` when
/// the payload can't be read.
pub fn lifetime(response: &TokenResponse, now: u64, clock_skew: Duration) -> Duration {
    let seconds = expires_at(&response.access_token)
        .map_or(response.expires_in, |exp| exp.saturating_sub(now));
    Duration::from_secs(seconds).saturating_sub(clock_skew)
}

/// The `exp` claim of a JWT, without verifying it: Tsong signed it.
fn expires_at(token: &str) -> Option<u64> {
    let payload = token.split('.').nth(1)?;
    let bytes = URL_SAFE_NO_PAD.decode(payload).ok()?;
    let claims: Value = serde_json::from_slice(&bytes).ok()?;
    claims.get("exp")?.as_u64()
}
