//! Read-only access to the Claude Code CLI's local credential store.
//!
//! Claude Code persists its OAuth tokens in the platform keychain (macOS) or
//! the on-disk fallback file `~/.claude/.credentials.json` (Linux, Windows
//! once they ship that path). When a gproxy `claudecode` provider runs on the
//! same machine as Claude Code, both processes target the *same* refresh
//! token. Anthropic rotates `refresh_token` on every successful refresh, so
//! whichever side refreshes second wins, and the loser's stored
//! `refresh_token` is permanently invalidated.
//!
//! This module lets the channel act as a *passive reader* of Claude Code's
//! credential state instead of a competitor: rather than calling Anthropic's
//! `refresh_token` grant on its own, the channel can re-read the keychain
//! and adopt whatever token Claude Code's normal usage has produced.
//!
//! # Trust boundary
//!
//! - The keychain entry is read-only here. We never write back, never refresh
//!   on Claude Code's behalf, and never trigger token rotation.
//! - On macOS we shell out to `/usr/bin/security` rather than linking the
//!   Security framework — it keeps the dependency surface small and matches
//!   exactly what `claude` itself does.
//! - On other platforms we read `~/.claude/.credentials.json` directly when
//!   present.

use serde::Deserialize;

/// Snapshot of the OAuth state we care about.
#[derive(Debug, Clone)]
pub struct ClaudecodeKeychainSnapshot {
    pub access_token: String,
    pub refresh_token: String,
    /// Milliseconds since the Unix epoch.
    pub expires_at_ms: u64,
}

#[derive(Debug, Deserialize)]
struct ClaudecodeKeychainEnvelope {
    #[serde(rename = "claudeAiOauth")]
    claude_ai_oauth: ClaudecodeKeychainBody,
}

#[derive(Debug, Deserialize)]
struct ClaudecodeKeychainBody {
    #[serde(rename = "accessToken")]
    access_token: String,
    #[serde(rename = "refreshToken")]
    refresh_token: String,
    #[serde(rename = "expiresAt")]
    expires_at: u64,
}

/// Try to read Claude Code's credential store. Returns `None` when the entry
/// is missing, malformed, or the platform isn't supported. Errors are logged
/// at debug level — a missing keychain entry is the normal case for users who
/// don't run Claude Code on this machine.
pub fn read_claudecode_local_credentials() -> Option<ClaudecodeKeychainSnapshot> {
    let raw = read_raw()?;
    match serde_json::from_str::<ClaudecodeKeychainEnvelope>(&raw) {
        Ok(envelope) => {
            let body = envelope.claude_ai_oauth;
            if body.access_token.is_empty() || body.refresh_token.is_empty() {
                tracing::debug!(
                    "claudecode local credential store has empty access or refresh token"
                );
                return None;
            }
            Some(ClaudecodeKeychainSnapshot {
                access_token: body.access_token,
                refresh_token: body.refresh_token,
                expires_at_ms: body.expires_at,
            })
        }
        Err(e) => {
            tracing::debug!(error = %e, "claudecode local credential store JSON parse failed");
            None
        }
    }
}

#[cfg(target_os = "macos")]
fn read_raw() -> Option<String> {
    use std::process::Command;
    let output = Command::new("/usr/bin/security")
        .args([
            "find-generic-password",
            "-s",
            "Claude Code-credentials",
            "-w",
        ])
        .output()
        .ok()?;
    if !output.status.success() {
        tracing::debug!(
            status = output.status.code().unwrap_or(-1),
            "macos keychain lookup for Claude Code-credentials failed"
        );
        return None;
    }
    let raw = String::from_utf8(output.stdout).ok()?;
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return None;
    }
    Some(trimmed.to_string())
}

#[cfg(not(target_os = "macos"))]
fn read_raw() -> Option<String> {
    use std::path::PathBuf;
    let home = std::env::var_os("HOME")?;
    let path = PathBuf::from(home).join(".claude").join(".credentials.json");
    match std::fs::read_to_string(&path) {
        Ok(s) => Some(s),
        Err(e) => {
            tracing::debug!(
                path = %path.display(),
                error = %e,
                "claudecode local credentials file not readable"
            );
            None
        }
    }
}
