//! Keychain-aware credential health for the `claudecode` channel.
//!
//! The default `ModelCooldownHealth::dead` bit is sticky: once a credential
//! returns 401/403 and `refresh_credential` declines to refresh (because
//! gproxy's strict-keychain mode refuses to rotate the shared OAuth session),
//! `dead` stays `true` forever and the credential is permanently filtered out
//! of the engine's eligibility list. From the user's perspective, even after
//! Claude Code refreshes the keychain in the background, gproxy never tries
//! the credential again until the process is restarted.
//!
//! This health type wraps `ModelCooldownHealth` and grants a credential a
//! second chance whenever the local Claude Code keychain looks fresh again.
//! When the engine schedules a candidate, it will re-enter the retry loop;
//! the channel's `needs_refresh` then sees the stale `expires_at_ms` and
//! triggers `refresh_credential`, which adopts the keychain snapshot via
//! Path 0 and returns the credential to service.
//!
//! The keychain read is short-lived (a `Once`-style cache) so a flurry of
//! requests doesn't shell out to `/usr/bin/security` repeatedly.

use std::sync::Mutex;
use std::time::{Duration, Instant};

use crate::health::{CredentialHealth, ModelCooldownHealth};

/// Cache window for the keychain freshness check. Short enough that a token
/// rotation by Claude Code is reflected within seconds, long enough to cover
/// a burst of concurrent requests without hammering the keychain API.
const KEYCHAIN_CACHE_TTL: Duration = Duration::from_millis(2_000);

#[derive(Debug, Default)]
struct KeychainFreshCache {
    checked_at: Option<Instant>,
    is_fresh: bool,
}

#[derive(Debug, Default)]
pub struct ClaudeCodeKeychainAwareHealth {
    inner: ModelCooldownHealth,
    cache: Mutex<KeychainFreshCache>,
}

impl Clone for ClaudeCodeKeychainAwareHealth {
    fn clone(&self) -> Self {
        // The cache is a transient performance optimisation. Cloned health
        // structures get a fresh cache rather than copying the lock state.
        Self {
            inner: self.inner.clone(),
            cache: Mutex::new(KeychainFreshCache::default()),
        }
    }
}

impl ClaudeCodeKeychainAwareHealth {
    fn keychain_looks_fresh(&self) -> bool {
        let now = Instant::now();
        if let Ok(mut cache) = self.cache.lock() {
            if let Some(checked_at) = cache.checked_at {
                if now.duration_since(checked_at) < KEYCHAIN_CACHE_TTL {
                    return cache.is_fresh;
                }
            }
            let is_fresh = match crate::utils::claudecode_local_keychain::read_claudecode_local_credentials() {
                Some(snapshot) => {
                    let now_ms = crate::utils::oauth::current_unix_ms();
                    snapshot.expires_at_ms > now_ms.saturating_add(60_000)
                }
                None => false,
            };
            cache.checked_at = Some(now);
            cache.is_fresh = is_fresh;
            is_fresh
        } else {
            // Lock poisoned — fall back to a direct read without caching.
            match crate::utils::claudecode_local_keychain::read_claudecode_local_credentials() {
                Some(snapshot) => {
                    let now_ms = crate::utils::oauth::current_unix_ms();
                    snapshot.expires_at_ms > now_ms.saturating_add(60_000)
                }
                None => false,
            }
        }
    }
}

impl CredentialHealth for ClaudeCodeKeychainAwareHealth {
    fn is_available(&self, model: Option<&str>) -> bool {
        if self.inner.is_available(model) {
            return true;
        }
        // The inner health filtered us out. If the only reason is the sticky
        // `dead` bit (no active cooldown), peek at the local Claude Code
        // keychain: if it looks fresh, give the credential another shot —
        // the next retry will see `needs_refresh == true`, call
        // `refresh_credential`, and Path 0 will adopt the live keychain
        // tokens, returning the credential to service.
        if !self.inner.dead {
            return false;
        }
        self.keychain_looks_fresh()
    }

    fn status(&self, model: Option<&str>) -> &'static str {
        // When the inner status is "unavailable" only because of the sticky
        // dead bit AND the keychain looks fresh, surface "cooldown" instead
        // — operators reading the admin API see "this credential will heal
        // itself" rather than a permanent failure marker.
        let inner_status = self.inner.status(model);
        if inner_status == "unavailable" && self.inner.dead && self.keychain_looks_fresh() {
            return "cooldown";
        }
        inner_status
    }

    fn record_error(&mut self, status: u16, model: Option<&str>, retry_after_ms: Option<u64>) {
        self.inner.record_error(status, model, retry_after_ms);
        // Force the next is_available() call to re-check the keychain
        // instead of using a possibly-stale cached "fresh=true" entry from
        // before the error.
        if let Ok(mut cache) = self.cache.lock() {
            cache.checked_at = None;
        }
    }

    fn record_success(&mut self, model: Option<&str>) {
        self.inner.record_success(model);
        if let Ok(mut cache) = self.cache.lock() {
            cache.checked_at = None;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_to_inner_when_alive() {
        let health = ClaudeCodeKeychainAwareHealth::default();
        // Empty keychain on test runners → keychain_looks_fresh = false.
        // Inner is_available is true (no dead bit), so the wrapper returns
        // true regardless of keychain state.
        assert!(health.is_available(None));
    }

    #[test]
    fn dead_with_no_keychain_stays_dead() {
        let mut health = ClaudeCodeKeychainAwareHealth::default();
        health.record_error(401, None, None);
        // No keychain entry on the test runner, so no resurrection.
        assert!(!health.is_available(None));
    }

    #[test]
    fn record_success_clears_dead_and_cache() {
        let mut health = ClaudeCodeKeychainAwareHealth::default();
        health.record_error(401, None, None);
        assert!(!health.is_available(None));
        health.record_success(None);
        assert!(health.is_available(None));
    }
}
