use std::time::Duration;

use anyhow::{Context, Result};
use bytes::Bytes;
use russh::{ChannelMsg, ChannelReadHalf, ChannelWriteHalf, client};
use tokio::sync::mpsc;
use tokio::task::JoinHandle;
use tokio::time::Instant;

use crate::config::{TerminalSize, TmuxSessionConfig, reconnect_delay};
use crate::session::SshSession;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SessionState {
    Disconnected,
    Connecting,
    Connected,
    Reconnecting { attempt: u32, delay: Duration },
    Failed,
}

#[derive(Debug)]
pub enum SessionEvent {
    StateChanged(SessionState),
    Output(Bytes),
    ExitStatus(u32),
    Error(String),
}

#[derive(Debug)]
pub enum SessionCommand {
    Connect,
    Disconnect,
    Write(Bytes),
    Resize(TerminalSize),
    Retry,
    Shutdown,
}

#[derive(Clone)]
pub struct SessionManagerHandle {
    command_tx: mpsc::Sender<SessionCommand>,
}

pub struct SessionManager;

impl SessionManager {
    pub fn spawn(
        config: TmuxSessionConfig,
    ) -> (SessionManagerHandle, mpsc::Receiver<SessionEvent>) {
        let (command_tx, command_rx) = mpsc::channel(64);
        let (event_tx, event_rx) = mpsc::channel(128);
        let handle = SessionManagerHandle { command_tx };

        tokio::spawn(run_actor(config, command_rx, event_tx));

        (handle, event_rx)
    }
}

impl SessionManagerHandle {
    pub async fn connect(&self) -> Result<()> {
        self.send(SessionCommand::Connect).await
    }

    pub async fn disconnect(&self) -> Result<()> {
        self.send(SessionCommand::Disconnect).await
    }

    pub async fn write(&self, data: impl Into<Bytes>) -> Result<()> {
        self.send(SessionCommand::Write(data.into())).await
    }

    pub async fn resize(&self, size: TerminalSize) -> Result<()> {
        self.send(SessionCommand::Resize(size)).await
    }

    pub async fn retry(&self) -> Result<()> {
        self.send(SessionCommand::Retry).await
    }

    pub async fn shutdown(&self) -> Result<()> {
        self.send(SessionCommand::Shutdown).await
    }

    async fn send(&self, command: SessionCommand) -> Result<()> {
        self.command_tx
            .send(command)
            .await
            .context("session manager actor is no longer running")
    }
}

struct ActiveConnection {
    ssh: SshSession,
    writer: ChannelWriteHalf<client::Msg>,
    events: mpsc::Receiver<ConnectionEvent>,
    reader_task: JoinHandle<()>,
}

enum ConnectionEvent {
    Output(Bytes),
    Closed { exit_status: Option<u32> },
}

async fn run_actor(
    config: TmuxSessionConfig,
    mut command_rx: mpsc::Receiver<SessionCommand>,
    event_tx: mpsc::Sender<SessionEvent>,
) {
    let mut state = SessionState::Disconnected;
    let mut desired_connection = false;
    let mut active: Option<ActiveConnection> = None;
    let mut retry_deadline = None;
    let mut retry_attempt = 0;
    let mut pending_size = config.size.clone();

    emit_state(&event_tx, &state).await;

    loop {
        let connection_events_open = active.is_some();
        let retry_at = retry_deadline;

        tokio::select! {
            command = command_rx.recv() => {
                let Some(command) = command else {
                    close_active(&mut active).await;
                    break;
                };

                match command {
                    SessionCommand::Connect => {
                        desired_connection = true;
                        retry_deadline = None;

                        if active.is_none() {
                            match connect_once(&config, &pending_size, &event_tx).await {
                                Ok(connection) => {
                                    active = Some(connection);
                                    retry_attempt = 0;
                                }
                                Err(error) => {
                                    schedule_retry(
                                        &event_tx,
                                        &mut state,
                                        &mut retry_deadline,
                                        &mut retry_attempt,
                                        error,
                                    ).await;
                                }
                            }
                        }
                    }
                    SessionCommand::Disconnect => {
                        desired_connection = false;
                        retry_deadline = None;
                        retry_attempt = 0;
                        close_active(&mut active).await;
                        set_state(&event_tx, &mut state, SessionState::Disconnected).await;
                    }
                    SessionCommand::Write(data) => {
                        let Some(connection) = active.as_mut() else {
                            emit_error(&event_tx, "cannot write while session is disconnected").await;
                            continue;
                        };

                        if let Err(error) = connection.writer.data_bytes(data).await {
                            emit_error(&event_tx, format!("failed to write remote input: {error}")).await;
                            close_active(&mut active).await;
                            if desired_connection {
                                schedule_retry(
                                    &event_tx,
                                    &mut state,
                                    &mut retry_deadline,
                                    &mut retry_attempt,
                                    error.into(),
                                ).await;
                            } else {
                                set_state(&event_tx, &mut state, SessionState::Disconnected).await;
                            }
                        }
                    }
                    SessionCommand::Resize(size) => {
                        pending_size = size;

                        let Some(connection) = active.as_mut() else {
                            continue;
                        };

                        if let Err(error) = connection.writer.window_change(
                            pending_size.columns,
                            pending_size.rows,
                            pending_size.pixel_width,
                            pending_size.pixel_height,
                        ).await {
                            emit_error(&event_tx, format!("failed to resize remote PTY: {error}")).await;
                            close_active(&mut active).await;
                            if desired_connection {
                                schedule_retry(
                                    &event_tx,
                                    &mut state,
                                    &mut retry_deadline,
                                    &mut retry_attempt,
                                    error.into(),
                                ).await;
                            } else {
                                set_state(&event_tx, &mut state, SessionState::Disconnected).await;
                            }
                        }
                    }
                    SessionCommand::Retry => {
                        retry_deadline = None;
                        if desired_connection && active.is_none() {
                            match connect_once(&config, &pending_size, &event_tx).await {
                                Ok(connection) => {
                                    active = Some(connection);
                                    retry_attempt = 0;
                                }
                                Err(error) => {
                                    schedule_retry(
                                        &event_tx,
                                        &mut state,
                                        &mut retry_deadline,
                                        &mut retry_attempt,
                                        error,
                                    ).await;
                                }
                            }
                        }
                    }
                    SessionCommand::Shutdown => {
                        close_active(&mut active).await;
                        break;
                    }
                }
            }
            connection_event = async {
                active
                    .as_mut()
                    .expect("connection event branch requires an active connection")
                    .events
                    .recv()
                    .await
            }, if connection_events_open => {
                match connection_event {
                    Some(ConnectionEvent::Output(data)) => {
                        let _ = event_tx.send(SessionEvent::Output(data)).await;
                    }
                    Some(ConnectionEvent::Closed { exit_status: Some(status) }) => {
                        desired_connection = false;
                        retry_deadline = None;
                        retry_attempt = 0;
                        close_active(&mut active).await;
                        let _ = event_tx.send(SessionEvent::ExitStatus(status)).await;
                        set_state(&event_tx, &mut state, SessionState::Disconnected).await;
                    }
                    Some(ConnectionEvent::Closed { exit_status: None }) | None => {
                        close_active(&mut active).await;
                        if desired_connection {
                            schedule_retry(
                                &event_tx,
                                &mut state,
                                &mut retry_deadline,
                                &mut retry_attempt,
                                anyhow::anyhow!("remote SSH channel closed"),
                            ).await;
                        } else {
                            set_state(&event_tx, &mut state, SessionState::Disconnected).await;
                        }
                    }
                }
            }
            _ = async {
                tokio::time::sleep_until(retry_at.expect("retry branch requires a deadline")).await
            }, if retry_at.is_some() => {
                retry_deadline = None;

                if desired_connection && active.is_none() {
                    match connect_once(&config, &pending_size, &event_tx).await {
                        Ok(connection) => {
                            active = Some(connection);
                            retry_attempt = 0;
                        }
                        Err(error) => {
                            schedule_retry(
                                &event_tx,
                                &mut state,
                                &mut retry_deadline,
                                &mut retry_attempt,
                                error,
                            ).await;
                        }
                    }
                }
            }
        }
    }
}

async fn connect_once(
    config: &TmuxSessionConfig,
    size: &TerminalSize,
    event_tx: &mpsc::Sender<SessionEvent>,
) -> Result<ActiveConnection> {
    emit_state(event_tx, &SessionState::Connecting).await;

    let ssh = SshSession::connect(config).await?;
    let pty = match ssh.open_tmux(config).await {
        Ok(pty) => pty,
        Err(error) => {
            let _ = ssh.close().await;
            return Err(error);
        }
    };

    let (reader, writer) = pty.into_parts();
    writer
        .window_change(size.columns, size.rows, size.pixel_width, size.pixel_height)
        .await
        .context("failed to apply PTY size after connection")?;

    let (connection_tx, connection_rx) = mpsc::channel(64);
    let reader_task = tokio::spawn(read_channel(reader, connection_tx));

    emit_state(event_tx, &SessionState::Connected).await;

    Ok(ActiveConnection {
        ssh,
        writer,
        events: connection_rx,
        reader_task,
    })
}

async fn read_channel(mut reader: ChannelReadHalf, event_tx: mpsc::Sender<ConnectionEvent>) {
    let mut exit_status = None;

    loop {
        let Some(message) = reader.wait().await else {
            break;
        };

        match message {
            ChannelMsg::Data { data } | ChannelMsg::ExtendedData { data, .. } => {
                if event_tx.send(ConnectionEvent::Output(data)).await.is_err() {
                    return;
                }
            }
            ChannelMsg::ExitStatus {
                exit_status: status,
            } => {
                exit_status = Some(status);
            }
            ChannelMsg::Eof | ChannelMsg::Close => break,
            _ => {}
        }
    }

    let _ = event_tx.send(ConnectionEvent::Closed { exit_status }).await;
}

async fn close_active(active: &mut Option<ActiveConnection>) {
    let Some(connection) = active.take() else {
        return;
    };

    connection.reader_task.abort();
    let _ = connection.ssh.close().await;
}

async fn schedule_retry(
    event_tx: &mpsc::Sender<SessionEvent>,
    state: &mut SessionState,
    retry_deadline: &mut Option<Instant>,
    retry_attempt: &mut u32,
    error: anyhow::Error,
) {
    emit_error(event_tx, error.to_string()).await;
    *retry_attempt = retry_attempt.saturating_add(1);
    let delay = reconnect_delay(*retry_attempt);
    *retry_deadline = Some(Instant::now() + delay);
    set_state(
        event_tx,
        state,
        SessionState::Reconnecting {
            attempt: *retry_attempt,
            delay,
        },
    )
    .await;
}

async fn set_state(
    event_tx: &mpsc::Sender<SessionEvent>,
    state: &mut SessionState,
    next: SessionState,
) {
    if *state == next {
        return;
    }
    *state = next.clone();
    emit_state(event_tx, &next).await;
}

async fn emit_state(event_tx: &mpsc::Sender<SessionEvent>, state: &SessionState) {
    let _ = event_tx
        .send(SessionEvent::StateChanged(state.clone()))
        .await;
}

async fn emit_error(event_tx: &mpsc::Sender<SessionEvent>, message: impl Into<String>) {
    let _ = event_tx.send(SessionEvent::Error(message.into())).await;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{AuthMethod, HostKeyPolicy, SshTarget};

    fn test_config() -> TmuxSessionConfig {
        TmuxSessionConfig {
            target: SshTarget {
                host: "127.0.0.1".to_string(),
                port: 22,
                username: "tester".to_string(),
            },
            auth: AuthMethod::Password("secret".to_string()),
            host_key_policy: HostKeyPolicy::InsecureAcceptAny,
            tmux_session: "main".to_string(),
            term: "xterm-256color".to_string(),
            size: TerminalSize::default(),
            keepalive_interval: Duration::from_secs(15),
            keepalive_max: 3,
        }
    }

    #[tokio::test]
    async fn write_is_rejected_without_replaying_input() {
        let (handle, mut events) = SessionManager::spawn(test_config());

        assert!(matches!(
            events.recv().await,
            Some(SessionEvent::StateChanged(SessionState::Disconnected))
        ));

        handle
            .write(Bytes::from_static(b"echo should not be queued"))
            .await
            .unwrap();

        assert!(matches!(
            events.recv().await,
            Some(SessionEvent::Error(message))
                if message == "cannot write while session is disconnected"
        ));

        handle.shutdown().await.unwrap();
    }

    #[tokio::test]
    async fn resize_is_accepted_while_disconnected() {
        let (handle, mut events) = SessionManager::spawn(test_config());
        let _ = events.recv().await;

        handle
            .resize(TerminalSize {
                columns: 160,
                rows: 48,
                pixel_width: 0,
                pixel_height: 0,
            })
            .await
            .unwrap();

        assert!(events.try_recv().is_err());
        handle.shutdown().await.unwrap();
    }
}
