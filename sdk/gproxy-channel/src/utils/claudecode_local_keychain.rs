//! Read/write access to the Claude Code CLI's local credential store.
//!
//! Claude Code persists its OAuth tokens in the platform keychain (macOS) or
//! the on-disk fallback file `~/.claude/.credentials.json` (Linux, Windows
//! once they ship that path). When a gproxy `claudecode` provider runs on the
//! same machine as Claude Code, both processes target the *same* refresh
//! token. Anthropic rotates `refresh_token` on every successful refresh, so
//! whichever side refreshes second leaves the loser's stored `refresh_token`
//! permanently invalidated.
//!
//! This module exposes both directions:
//!
//! - `read_claudecode_local_credentials` — passively read whatever Claude
//!   Code's normal usage has produced. The channel uses this in Path 0 to
//!   adopt fresh tokens without calling the refresh_token grant ourselves.
//! - `write_claudecode_local_credentials` — write a snapshot back into the
//!   same store. The channel uses this after Path 1 (its own refresh_token
//!   grant) so Claude Code, on its next launch, reads the rotated tokens
//!   gproxy just produced and remains functional. Without this, Claude Code
//!   would 401 on its next refresh attempt and force the user to /login.
//!
//! The shared store thus becomes a *coordination channel* between gproxy and
//! Claude Code rather than a contended resource. Either side can rotate, the
//! other side reads the result.

use serde::{Deserialize, Serialize};

/// Snapshot of the OAuth state we care about.
#[derive(Debug, Clone)]
pub struct ClaudecodeKeychainSnapshot {
    pub access_token: String,
    pub refresh_token: String,
    /// Milliseconds since the Unix epoch.
    pub expires_at_ms: u64,
}

#[derive(Debug, Deserialize, Serialize)]
struct ClaudecodeKeychainEnvelope {
    #[serde(rename = "claudeAiOauth")]
    claude_ai_oauth: ClaudecodeKeychainBody,
}

#[derive(Debug, Deserialize, Serialize)]
struct ClaudecodeKeychainBody {
    #[serde(rename = "accessToken")]
    access_token: String,
    #[serde(rename = "refreshToken")]
    refresh_token: String,
    #[serde(rename = "expiresAt")]
    expires_at: u64,
    /// Preserved verbatim when we round-trip the entry. `serde_json::Value`
    /// is used so we don't have to enumerate every field Claude Code might
    /// add in the future (subscriptionType, scopes, rateLimitTier, …).
    #[serde(flatten)]
    extra: serde_json::Map<String, serde_json::Value>,
}

/// Try to read Claude Code's credential store. Returns `None` when the entry
/// is missing, malformed, or the platform isn't supported.
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

/// Write a snapshot back to Claude Code's credential store. Preserves any
/// extra fields the existing entry carried (subscriptionType, scopes,
/// rateLimitTier, …) so the CLI's own consumers keep working.
///
/// Returns `Ok(true)` on a successful write, `Ok(false)` when no existing
/// entry was found (the user might not have Claude Code installed locally —
/// in that case there is nothing for gproxy to coordinate with), and `Err`
/// only on actual I/O failures.
pub fn write_claudecode_local_credentials(
    snapshot: &ClaudecodeKeychainSnapshot,
) -> std::io::Result<bool> {
    // Round-trip through the existing entry so we keep `subscriptionType`,
    // `scopes`, etc. intact. If the entry is missing, do nothing.
    let raw = match read_raw() {
        Some(s) => s,
        None => return Ok(false),
    };
    let mut envelope: ClaudecodeKeychainEnvelope = match serde_json::from_str(&raw) {
        Ok(v) => v,
        Err(e) => {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("existing keychain entry is not valid JSON: {e}"),
            ));
        }
    };
    envelope.claude_ai_oauth.access_token = snapshot.access_token.clone();
    envelope.claude_ai_oauth.refresh_token = snapshot.refresh_token.clone();
    envelope.claude_ai_oauth.expires_at = snapshot.expires_at_ms;
    let serialized = serde_json::to_string(&envelope).map_err(|e| {
        std::io::Error::new(
            std::io::ErrorKind::Other,
            format!("failed to serialize keychain envelope: {e}"),
        )
    })?;
    write_raw(&serialized)?;
    Ok(true)
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

#[cfg(target_os = "macos")]
fn write_raw(serialized: &str) -> std::io::Result<()> {
    use std::process::Command;

    // The current user's short name owns the entry. Read it from the
    // existing record rather than guessing — a gproxy run as root or
    // launchctl-system would otherwise associate the entry with the wrong
    // account and Claude Code would no longer find it.
    let account = current_account_for_entry().unwrap_or_else(default_account);

    let status = Command::new("/usr/bin/security")
        .args([
            "add-generic-password",
            // Update existing entry instead of erroring on duplicate.
            "-U",
            "-s",
            "Claude Code-credentials",
            "-a",
            &account,
            "-w",
            serialized,
        ])
        .status()?;
    if !status.success() {
        return Err(std::io::Error::other(format!(
            "/usr/bin/security exited with status {}",
            status.code().unwrap_or(-1)
        )));
    }
    Ok(())
}

#[cfg(target_os = "macos")]
fn current_account_for_entry() -> Option<String> {
    use std::process::Command;
    let output = Command::new("/usr/bin/security")
        .args([
            "find-generic-password",
            "-s",
            "Claude Code-credentials",
            "-g",
        ])
        .output()
        .ok()?;
    // `-g` writes the metadata to stderr; the secret goes to stdout. We
    // only need the metadata.
    let combined = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    for line in combined.lines() {
        // Lines look like:  "acct"<blob>="magenie33"
        if let Some(rest) = line.split_once("\"acct\"<blob>=") {
            let value = rest.1.trim();
            if let Some(stripped) = value.strip_prefix('"').and_then(|s| s.strip_suffix('"')) {
                if !stripped.is_empty() {
                    return Some(stripped.to_string());
                }
            }
        }
    }
    None
}

#[cfg(target_os = "macos")]
fn default_account() -> String {
    std::env::var("USER").unwrap_or_else(|_| "user".to_string())
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

#[cfg(not(target_os = "macos"))]
fn write_raw(serialized: &str) -> std::io::Result<()> {
    use std::path::PathBuf;
    let home = std::env::var_os("HOME").ok_or_else(|| {
        std::io::Error::new(std::io::ErrorKind::NotFound, "HOME env var unset")
    })?;
    let dir = PathBuf::from(home).join(".claude");
    let path = dir.join(".credentials.json");
    if !dir.exists() {
        std::fs::create_dir_all(&dir)?;
    }
    // Atomic replace so a partial write can't leave Claude Code with a
    // half-written entry.
    let tmp = dir.join(".credentials.json.tmp");
    std::fs::write(&tmp, serialized)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut perms = std::fs::metadata(&tmp)?.permissions();
        perms.set_mode(0o600);
        std::fs::set_permissions(&tmp, perms)?;
    }
    std::fs::rename(&tmp, &path)?;
    Ok(())
}
