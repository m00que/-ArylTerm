use std::env;
use std::path::PathBuf;
use std::time::Duration;

use anyhow::{Context, Result, bail};
use backend::config::{AuthMethod, HostKeyPolicy, SshTarget, TerminalSize, TmuxSessionConfig};
use backend::manager::{SessionEvent, SessionManager};
use bytes::Bytes;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            env::var("RUST_LOG").unwrap_or_else(|_| "backend=info,russh=warn".to_string()),
        )
        .init();

    let config = CliConfig::parse(env::args().skip(1))?.into_session_config()?;
    let exit_status = run_stdio(config).await?;

    std::process::exit(exit_status as i32);
}

async fn run_stdio(config: TmuxSessionConfig) -> Result<u32> {
    let (manager, mut events) = SessionManager::spawn(config);
    manager.connect().await?;

    let mut stdin = tokio::io::stdin();
    let mut stdout = tokio::io::stdout();
    let mut stdin_buf = [0_u8; 4096];
    let mut exit_status = 0;

    loop {
        tokio::select! {
            read = stdin.read(&mut stdin_buf) => {
                let read = read.context("failed to read local stdin")?;
                if read == 0 {
                    manager.disconnect().await?;
                    break;
                }

                manager
                    .write(Bytes::copy_from_slice(&stdin_buf[..read]))
                    .await?;
            }
            event = events.recv() => {
                let Some(event) = event else {
                    break;
                };

                match event {
                    SessionEvent::Output(data) => {
                        stdout.write_all(&data).await.context("failed to write stdout")?;
                        stdout.flush().await.context("failed to flush stdout")?;
                    }
                    SessionEvent::ExitStatus(status) => {
                        exit_status = status;
                        break;
                    }
                    SessionEvent::StateChanged(state) => {
                        tracing::info!(?state, "session state changed");
                    }
                    SessionEvent::Error(message) => {
                        tracing::warn!(%message, "session manager reported an error");
                    }
                }
            }
            signal = tokio::signal::ctrl_c() => {
                signal.context("failed to listen for Ctrl-C")?;
                manager.shutdown().await?;
                break;
            }
        }
    }

    Ok(exit_status)
}

#[derive(Debug)]
struct CliConfig {
    host: Option<String>,
    host_port: Option<u16>,
    port: Option<u16>,
    username: Option<String>,
    password: Option<String>,
    key: Option<PathBuf>,
    key_passphrase: Option<String>,
    tmux_session: String,
    term: String,
    columns: u32,
    rows: u32,
    host_key_sha256: Option<String>,
    accept_any_host_key: bool,
}

impl Default for CliConfig {
    fn default() -> Self {
        Self {
            host: None,
            host_port: None,
            port: None,
            username: None,
            password: env::var("ARYLTERM_SSH_PASSWORD").ok(),
            key: None,
            key_passphrase: env::var("ARYLTERM_SSH_KEY_PASSPHRASE").ok(),
            tmux_session: "main".to_string(),
            term: "xterm-256color".to_string(),
            columns: 120,
            rows: 40,
            host_key_sha256: None,
            accept_any_host_key: false,
        }
    }
}

impl CliConfig {
    fn parse(args: impl IntoIterator<Item = String>) -> Result<Self> {
        let mut config = Self::default();
        let mut args = args.into_iter();

        while let Some(arg) = args.next() {
            match arg.as_str() {
                "--host" => {
                    let value = next_value(&mut args, "--host")?;
                    let (host, host_port) = parse_host_and_port(&value)?;
                    config.host = Some(host);
                    config.host_port = host_port;
                }
                "--port" => {
                    config.port = Some(
                        next_value(&mut args, "--port")?
                            .parse()
                            .context("--port must be a number")?,
                    )
                }
                "--user" | "--username" => config.username = Some(next_value(&mut args, "--user")?),
                "--password" => config.password = Some(next_value(&mut args, "--password")?),
                "--key" => config.key = Some(PathBuf::from(next_value(&mut args, "--key")?)),
                "--key-passphrase" => {
                    config.key_passphrase = Some(next_value(&mut args, "--key-passphrase")?)
                }
                "--tmux" | "--tmux-session" => {
                    config.tmux_session = next_value(&mut args, "--tmux")?
                }
                "--term" => config.term = next_value(&mut args, "--term")?,
                "--cols" | "--columns" => {
                    config.columns = next_value(&mut args, "--cols")?
                        .parse()
                        .context("--cols must be a number")?
                }
                "--rows" => {
                    config.rows = next_value(&mut args, "--rows")?
                        .parse()
                        .context("--rows must be a number")?
                }
                "--host-key-sha256" => {
                    config.host_key_sha256 = Some(next_value(&mut args, "--host-key-sha256")?)
                }
                "--accept-any-host-key" => config.accept_any_host_key = true,
                "--help" | "-h" => {
                    print_help();
                    std::process::exit(0);
                }
                unknown => bail!("unknown argument: {unknown}"),
            }
        }

        Ok(config)
    }

    fn into_session_config(self) -> Result<TmuxSessionConfig> {
        let host = self.host.context("missing --host")?;
        let username = self.username.context("missing --user")?;
        let port = self.port.or(self.host_port).unwrap_or(22);
        let auth = match (self.key, self.password) {
            (Some(path), _) => AuthMethod::PrivateKey {
                path,
                passphrase: self.key_passphrase,
            },
            (None, Some(password)) => AuthMethod::Password(password),
            (None, None) => {
                bail!("missing auth method: pass --key, --password, or set ARYLTERM_SSH_PASSWORD")
            }
        };
        let host_key_policy = match (self.accept_any_host_key, self.host_key_sha256) {
            (true, _) => HostKeyPolicy::InsecureAcceptAny,
            (false, Some(fingerprint)) => HostKeyPolicy::FingerprintSha256(fingerprint),
            (false, None) => {
                bail!("missing host key policy: pass --host-key-sha256 or --accept-any-host-key")
            }
        };

        Ok(TmuxSessionConfig {
            target: SshTarget {
                host,
                port,
                username,
            },
            auth,
            host_key_policy,
            tmux_session: self.tmux_session,
            term: self.term,
            size: TerminalSize {
                columns: self.columns,
                rows: self.rows,
                pixel_width: 0,
                pixel_height: 0,
            },
            keepalive_interval: Duration::from_secs(15),
            keepalive_max: 3,
        })
    }
}

fn next_value(args: &mut impl Iterator<Item = String>, name: &str) -> Result<String> {
    args.next()
        .with_context(|| format!("{name} requires a value"))
}

fn parse_host_and_port(input: &str) -> Result<(String, Option<u16>)> {
    if let Some(rest) = input.strip_prefix('[') {
        let closing = rest
            .find(']')
            .with_context(|| format!("invalid host value: {input}"))?;
        let host = rest[..closing].to_string();
        let suffix = &rest[closing + 1..];
        if suffix.is_empty() {
            return Ok((host, None));
        }
        let port = suffix
            .strip_prefix(':')
            .with_context(|| format!("invalid host value: {input}"))?
            .parse()
            .context("host port must be a number")?;
        return Ok((host, Some(port)));
    }

    if input.matches(':').count() == 1 {
        let (host, port) = input
            .rsplit_once(':')
            .with_context(|| format!("invalid host value: {input}"))?;
        let port = port.parse().context("host port must be a number")?;
        return Ok((host.to_string(), Some(port)));
    }

    Ok((input.to_string(), None))
}

#[cfg(test)]
mod tests {
    use super::parse_host_and_port;

    #[test]
    fn parses_plain_host() {
        let (host, port) = parse_host_and_port("example.com").unwrap();
        assert_eq!(host, "example.com");
        assert_eq!(port, None);
    }

    #[test]
    fn parses_host_and_port() {
        let (host, port) = parse_host_and_port("49.235.144.5:31022").unwrap();
        assert_eq!(host, "49.235.144.5");
        assert_eq!(port, Some(31022));
    }

    #[test]
    fn parses_bracketed_ipv6_and_port() {
        let (host, port) = parse_host_and_port("[2001:db8::1]:2222").unwrap();
        assert_eq!(host, "2001:db8::1");
        assert_eq!(port, Some(2222));
    }

    #[test]
    fn leaves_unbracketed_ipv6_without_port() {
        let (host, port) = parse_host_and_port("2001:db8::1").unwrap();
        assert_eq!(host, "2001:db8::1");
        assert_eq!(port, None);
    }
}

fn print_help() {
    println!(
        "ArylTerm backend SSH probe\n\
         \n\
         Usage:\n\
           backend --host HOST[:PORT] --user USER (--key PATH | --password PASS) [options]\n\
         \n\
         Options:\n\
           --port PORT                  SSH port, overrides host port suffix\n\
           --tmux SESSION               tmux session name, default main\n\
           --term TERM                  PTY TERM value, default xterm-256color\n\
           --cols N --rows N            initial PTY size, default 120x40\n\
           --host-key-sha256 SHA256:... expected server host key fingerprint\n\
           --accept-any-host-key        development only: skip host key verification\n\
           --key-passphrase PASS        private key passphrase\n\
         \n\
         Environment:\n\
           ARYLTERM_SSH_PASSWORD\n\
           ARYLTERM_SSH_KEY_PASSPHRASE"
    );
}
