use std::sync::Arc;

use anyhow::{Context, Result, bail};
use bytes::Bytes;
use russh::keys::{HashAlg, PrivateKeyWithHashAlg, PublicKeyOrCertificate, load_secret_key};
use russh::{ChannelMsg, Disconnect, client};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use crate::config::{AuthMethod, HostKeyPolicy, TerminalSize, TmuxSessionConfig};

#[derive(Clone, Debug)]
struct ArylClient {
    host_key_policy: HostKeyPolicy,
}

impl client::Handler for ArylClient {
    type Error = russh::Error;

    async fn check_server_key(
        &mut self,
        server_public_key: &PublicKeyOrCertificate,
    ) -> Result<bool, Self::Error> {
        match &self.host_key_policy {
            HostKeyPolicy::InsecureAcceptAny => Ok(true),
            HostKeyPolicy::FingerprintSha256(expected) => {
                let public_key = server_public_key.public_key();
                let actual = public_key.fingerprint(HashAlg::Sha256).to_string();
                Ok(actual == *expected)
            }
        }
    }
}

pub struct SshSession {
    handle: client::Handle<ArylClient>,
}

pub struct RemotePty {
    channel: russh::Channel<client::Msg>,
}

impl SshSession {
    pub async fn connect(config: &TmuxSessionConfig) -> Result<Self> {
        let mut client_config = client::Config {
            keepalive_interval: Some(config.keepalive_interval),
            keepalive_max: config.keepalive_max,
            nodelay: true,
            ..Default::default()
        };
        client_config.inactivity_timeout = None;

        let handler = ArylClient {
            host_key_policy: config.host_key_policy.clone(),
        };
        let mut handle = client::connect(Arc::new(client_config), config.target.address(), handler)
            .await
            .with_context(|| {
                format!(
                    "failed to connect to {}:{}",
                    config.target.host, config.target.port
                )
            })?;

        authenticate(&mut handle, &config.target.username, &config.auth).await?;

        Ok(Self { handle })
    }

    pub async fn open_tmux(&self, config: &TmuxSessionConfig) -> Result<RemotePty> {
        let channel = self
            .handle
            .channel_open_session()
            .await
            .context("failed to open SSH session channel")?;

        request_pty(&channel, &config.term, &config.size).await?;
        channel
            .exec(true, config.tmux_attach_command())
            .await
            .context("failed to execute tmux attach command")?;

        Ok(RemotePty { channel })
    }

    pub async fn send_keepalive(&self) -> Result<()> {
        self.handle
            .send_keepalive(true)
            .await
            .context("SSH keepalive failed")
    }

    pub async fn close(&self) -> Result<()> {
        self.handle
            .disconnect(Disconnect::ByApplication, "ArylTerm closed", "en")
            .await
            .context("failed to disconnect SSH session")
    }
}

impl RemotePty {
    pub async fn write(&self, data: impl Into<Bytes>) -> Result<()> {
        self.channel
            .data_bytes(data)
            .await
            .context("failed to write to remote PTY")
    }

    pub async fn resize(&self, size: TerminalSize) -> Result<()> {
        self.channel
            .window_change(size.columns, size.rows, size.pixel_width, size.pixel_height)
            .await
            .context("failed to resize remote PTY")
    }

    pub async fn run_stdio(mut self) -> Result<u32> {
        let mut stdin = tokio::io::stdin();
        let mut stdout = tokio::io::stdout();
        let mut stdin_buf = [0_u8; 4096];
        let mut stdin_closed = false;
        let mut exit_status = None;

        loop {
            tokio::select! {
                read = stdin.read(&mut stdin_buf), if !stdin_closed => {
                    let read = read.context("failed to read local stdin")?;
                    if read == 0 {
                        stdin_closed = true;
                        self.channel.eof().await.context("failed to send remote EOF")?;
                    } else {
                        self.write(Bytes::copy_from_slice(&stdin_buf[..read])).await?;
                    }
                }
                message = self.channel.wait() => {
                    let Some(message) = message else {
                        break;
                    };

                    match message {
                        ChannelMsg::Data { data } | ChannelMsg::ExtendedData { data, .. } => {
                            stdout.write_all(&data).await.context("failed to write stdout")?;
                            stdout.flush().await.context("failed to flush stdout")?;
                        }
                        ChannelMsg::ExitStatus { exit_status: status } => {
                            exit_status = Some(status);
                        }
                        ChannelMsg::Eof | ChannelMsg::Close => {
                            break;
                        }
                        _ => {}
                    }
                }
            }
        }

        Ok(exit_status.unwrap_or(0))
    }
}

async fn authenticate(
    handle: &mut client::Handle<ArylClient>,
    username: &str,
    auth: &AuthMethod,
) -> Result<()> {
    let result = match auth {
        AuthMethod::Password(password) => handle
            .authenticate_password(username, password)
            .await
            .context("password authentication failed")?,
        AuthMethod::PrivateKey { path, passphrase } => {
            let key = load_secret_key(path, passphrase.as_deref())
                .with_context(|| format!("failed to load private key {}", path.display()))?;
            let hash_algorithm = handle.best_supported_rsa_hash().await?.flatten();
            handle
                .authenticate_publickey(
                    username,
                    PrivateKeyWithHashAlg::new(Arc::new(key), hash_algorithm),
                )
                .await
                .context("public key authentication failed")?
        }
    };

    if !result.success() {
        bail!("SSH authentication rejected by server");
    }

    Ok(())
}

async fn request_pty(
    channel: &russh::Channel<client::Msg>,
    term: &str,
    size: &TerminalSize,
) -> Result<()> {
    channel
        .request_pty(
            true,
            term,
            size.columns,
            size.rows,
            size.pixel_width,
            size.pixel_height,
            &[],
        )
        .await
        .context("failed to request remote PTY")
}
