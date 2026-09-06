use std::path::PathBuf;
use std::time::Duration;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SshTarget {
    pub host: String,
    pub port: u16,
    pub username: String,
}

impl SshTarget {
    pub fn address(&self) -> (&str, u16) {
        (&self.host, self.port)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AuthMethod {
    Password(String),
    PrivateKey {
        path: PathBuf,
        passphrase: Option<String>,
    },
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum HostKeyPolicy {
    FingerprintSha256(String),
    InsecureAcceptAny,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TerminalSize {
    pub columns: u32,
    pub rows: u32,
    pub pixel_width: u32,
    pub pixel_height: u32,
}

impl Default for TerminalSize {
    fn default() -> Self {
        Self {
            columns: 120,
            rows: 40,
            pixel_width: 0,
            pixel_height: 0,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TmuxSessionConfig {
    pub target: SshTarget,
    pub auth: AuthMethod,
    pub host_key_policy: HostKeyPolicy,
    pub tmux_session: String,
    pub term: String,
    pub size: TerminalSize,
    pub keepalive_interval: Duration,
    pub keepalive_max: usize,
}

impl TmuxSessionConfig {
    pub fn tmux_attach_command(&self) -> String {
        tmux_attach_command(&self.tmux_session)
    }
}

pub fn tmux_attach_command(session_name: &str) -> String {
    format!("tmux new-session -A -s {}", shell_quote(session_name))
}

fn shell_quote(value: &str) -> String {
    if value.is_empty() {
        return "''".to_string();
    }

    let escaped = value.replace('\'', "'\"'\"'");
    format!("'{escaped}'")
}

pub fn reconnect_delay(attempt: u32) -> Duration {
    let exponent = attempt.saturating_sub(1).min(5);
    let seconds = (1_u64 << exponent).min(30);
    Duration::from_secs(seconds)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tmux_attach_command_quotes_session_name() {
        assert_eq!(
            tmux_attach_command("main work"),
            "tmux new-session -A -s 'main work'"
        );
        assert_eq!(
            tmux_attach_command("dev'box"),
            "tmux new-session -A -s 'dev'\"'\"'box'"
        );
    }

    #[test]
    fn reconnect_delay_is_bounded() {
        assert_eq!(reconnect_delay(1), Duration::from_secs(1));
        assert_eq!(reconnect_delay(4), Duration::from_secs(8));
        assert_eq!(reconnect_delay(99), Duration::from_secs(30));
    }
}
