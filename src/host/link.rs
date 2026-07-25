//! The local end of a `herdr pty-host` connection.
//!
//! Turns one framed stdio link into per-pane byte pipes. The trick that keeps
//! this small: each channel gets a `socketpair`, one end of which is handed to
//! the ordinary PTY actor as its "master". The actor already reads and writes an
//! `OwnedFd` and its own tests drive it from a socket pair, so a remote pane
//! needs no changes to the byte path at all.
//!
//! What cannot travel that way is the window size, because resizing a PTY is an
//! `ioctl` on the real master — which lives on the other machine. So `resize`
//! becomes a protocol message instead. This is the one asymmetry between a local
//! and a remote pane, and it is why a remote pane must never reach
//! `resize_pty_fd`: that call returns `ENOTTY` on a socket and herdr logs the
//! failure at `debug!`, so getting this wrong produces a pane that silently
//! never resizes.

use std::collections::HashMap;
use std::io::{Read, Write};
use std::os::fd::{FromRawFd, IntoRawFd, OwnedFd};
use std::os::unix::net::UnixStream;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use super::protocol::{
    negotiate, read_frame, write_frame, ChannelId, FromHost, Negotiation, SpawnSpec, ToHost,
    HOST_PROTOCOL_VERSION,
};

/// Per-channel state the link retains after handing the actor its end.
struct ChannelEnd {
    /// Our side of the socket pair: host output is written here for the actor to
    /// read, and user input written by the actor is read from here.
    local: UnixStream,
}

type Channels = Arc<Mutex<HashMap<ChannelId, ChannelEnd>>>;

/// A connected pty-host link.
pub struct HostLink {
    writer: Arc<Mutex<Box<dyn Write + Send>>>,
    channels: Channels,
    next_channel: AtomicU64,
    /// Version the peer advertised, for diagnostics.
    peer_version: u32,
}

/// How long to wait for a host to answer a handshake.
///
/// Bounded because this can run where a keypress is waiting: an unreachable or
/// wedged host must fail rather than freeze the interface.
const HANDSHAKE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(20);

/// Script that starts the daemon on a host.
///
/// A bare `herdr` is not enough: a non-interactive ssh command gets a minimal
/// PATH that excludes `~/.local/bin`, which is where herdr installs itself on a
/// host. So try PATH first, then that location.
///
/// Run through `sh -c`, never a login shell: anything a profile echoes to stdout
/// would land in front of the handshake and corrupt the framed stream. Must
/// contain no single quotes, since it is single-quoted for the remote shell.
///
/// `attach`, not the daemon itself: attach bridges stdio to a detached daemon that
/// already holds the PTYs, so the processes are not children of this ssh invocation
/// and survive it being torn down.
const REMOTE_LAUNCH: &str = concat!(
    "if command -v herdr >/dev/null 2>&1; then exec herdr pty-host attach; ",
    "else exec \"$HOME/.local/bin/herdr\" pty-host attach; fi"
);

impl HostLink {
    /// Connect to a host by running `herdr pty-host` there over ssh.
    ///
    /// ssh is only a way to carry stdio, so it is confined to this one function;
    /// everything else works on streams and is exercised over pipes in tests.
    /// Keepalives are set so a dead link surfaces rather than hanging forever.
    pub fn connect_over_ssh(target: &str) -> std::io::Result<(Self, std::process::Child)> {
        let mut child = std::process::Command::new("ssh")
            .arg("-o")
            .arg("BatchMode=yes")
            // Fail fast on an unreachable host instead of sitting in ssh's
            // default connect timeout.
            .arg("-o")
            .arg("ConnectTimeout=10")
            .arg("-o")
            .arg("ServerAliveInterval=30")
            .arg("-o")
            .arg("ServerAliveCountMax=6")
            // No tty: this is a framed byte protocol, and a pty would mangle it.
            .arg("-T")
            .arg(target)
            // ONE argument, single-quoted for the remote shell. ssh joins its
            // command arguments into a single string and hands that to the
            // remote login shell, so passing `sh`, `-c`, `<script>` separately
            // loses the boundaries and the shell tries to parse the script
            // itself — zsh reports `parse error near then`.
            .arg(format!("sh -c '{REMOTE_LAUNCH}'"))
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            // Captured, not discarded: when a host fails to start, ssh's own
            // message is usually the only thing that explains why.
            .stderr(std::process::Stdio::piped())
            .spawn()?;

        let stdout = child
            .stdout
            .take()
            .ok_or_else(|| std::io::Error::other("ssh produced no stdout"))?;
        let stdin = child
            .stdin
            .take()
            .ok_or_else(|| std::io::Error::other("ssh produced no stdin"))?;

        match Self::connect(stdout, Box::new(stdin)) {
            Ok(link) => Ok((link, child)),
            Err(err) => {
                // Surface what the far side said before tearing it down.
                let mut stderr = String::new();
                if let Some(mut pipe) = child.stderr.take() {
                    use std::io::Read;
                    let mut raw = Vec::new();
                    let _ = pipe.read_to_end(&mut raw);
                    stderr = String::from_utf8_lossy(&raw).trim().to_string();
                }
                let _ = child.kill();
                let _ = child.wait();

                let detail = if stderr.is_empty() {
                    // The most common cause by far is no herdr on the host.
                    "Check that herdr is installed there, or run `herdr host probe` for detail."
                        .to_string()
                } else {
                    format!("host said: {stderr}")
                };
                Err(std::io::Error::other(format!(
                    "could not start herdr pty-host on {target}: {err}. {detail}"
                )))
            }
        }
    }

    /// Handshake over an already-established byte stream.
    ///
    /// Taking streams rather than spawning ssh keeps the transport out of this
    /// layer: the same code is driven over pipes in tests and over ssh in
    /// production, so the interesting logic is exercised without a network.
    pub fn connect<R: Read + Send + 'static>(
        reader: R,
        writer: Box<dyn Write + Send>,
    ) -> std::io::Result<Self> {
        let writer = Arc::new(Mutex::new(writer));
        {
            let mut guard = writer.lock().map_err(|_| poisoned())?;
            write_frame(
                &mut *guard,
                &ToHost::Hello {
                    version: HOST_PROTOCOL_VERSION,
                },
            )
            .map_err(std::io::Error::other)?;
            guard.flush()?;
        }

        // The dispatcher reads every frame including the first, and reports the
        // welcome through a channel. That lets the handshake have a DEADLINE: a
        // plain blocking read on a wedged host would hang the caller forever, and
        // this runs where a keypress is waiting.
        let channels: Channels = Arc::new(Mutex::new(HashMap::new()));
        let (welcome_tx, welcome_rx) = std::sync::mpsc::channel();
        {
            let channels = Arc::clone(&channels);
            std::thread::spawn(move || dispatch_from_host(reader, channels, welcome_tx));
        }

        let peer_version = match welcome_rx.recv_timeout(HANDSHAKE_TIMEOUT) {
            Ok(Ok(version)) => version,
            Ok(Err(message)) => return Err(std::io::Error::other(message)),
            Err(_) => {
                return Err(std::io::Error::other(format!(
                    "host did not answer within {}s",
                    HANDSHAKE_TIMEOUT.as_secs()
                )))
            }
        };

        // Name both versions: with many hosts, "incompatible" alone does not say
        // which end to upgrade.
        match negotiate(peer_version) {
            Negotiation::Ok => {}
            Negotiation::PeerTooOld { peer, min_supported } => {
                return Err(std::io::Error::other(format!(
                    "host speaks protocol {peer}, this herdr needs at least {min_supported}; re-provision the host"
                )))
            }
            Negotiation::PeerTooNew { peer, ours } => {
                return Err(std::io::Error::other(format!(
                    "host speaks protocol {peer}, this herdr understands up to {ours}; upgrade this herdr"
                )))
            }
        }

        Ok(Self {
            writer,
            channels,
            next_channel: AtomicU64::new(1),
            peer_version,
        })
    }

    /// Protocol version the host advertised. Surfaced for diagnostics: with many
    /// hosts, version skew is the failure people hit most.
    pub fn peer_version(&self) -> u32 {
        self.peer_version
    }

    /// Start a process on the host and return the fd to give the PTY actor.
    ///
    /// The returned fd behaves like a PTY master for reading and writing. It is
    /// not a tty, so window-size changes must go through [`Self::resize`].
    pub fn open_channel(&self, spec: SpawnSpec) -> std::io::Result<(ChannelId, OwnedFd)> {
        let channel = self.next_channel.fetch_add(1, Ordering::Relaxed);
        let (actor_side, local_side) = UnixStream::pair()?;

        // The actor polls its fd, so it must not block on a slow peer.
        actor_side.set_nonblocking(true)?;

        self.channels.lock().map_err(|_| poisoned())?.insert(
            channel,
            ChannelEnd {
                local: local_side.try_clone()?,
            },
        );

        self.send(&ToHost::Spawn {
            channel,
            spec: spec.clone(),
        })?;

        // Pump user input: whatever the actor writes becomes a Data frame.
        {
            let writer = Arc::clone(&self.writer);
            let channels = Arc::clone(&self.channels);
            std::thread::spawn(move || pump_user_input(channel, local_side, writer, channels));
        }

        let owned = unsafe { OwnedFd::from_raw_fd(actor_side.into_raw_fd()) };
        Ok((channel, owned))
    }

    /// Push a window size to the host. This is the message that replaces the
    /// local `TIOCSWINSZ` ioctl for a remote pane.
    pub fn resize(
        &self,
        channel: ChannelId,
        rows: u16,
        cols: u16,
        cell_width_px: u32,
        cell_height_px: u32,
    ) -> std::io::Result<()> {
        self.send(&ToHost::Resize {
            channel,
            rows,
            cols,
            cell_width_px,
            cell_height_px,
        })
    }

    /// Ask the host to terminate a channel's process session.
    pub fn shutdown_channel(&self, channel: ChannelId) -> std::io::Result<()> {
        let result = self.send(&ToHost::Shutdown { channel });
        // Close regardless, so the actor sees EOF even if the link is already gone.
        close_channel(&self.channels, channel);
        result
    }

    fn send(&self, message: &ToHost) -> std::io::Result<()> {
        let mut guard = self.writer.lock().map_err(|_| poisoned())?;
        write_frame(&mut *guard, message).map_err(std::io::Error::other)?;
        guard.flush()
    }
}

/// Fan host frames out to the per-channel sockets the actors read from.
fn dispatch_from_host<R: Read>(
    mut reader: R,
    channels: Channels,
    welcome: std::sync::mpsc::Sender<Result<u32, String>>,
) {
    let mut welcome = Some(welcome);

    while let Ok(message) = read_frame::<_, FromHost>(&mut reader) {
        // The first frame must be the welcome; anything else means the peer is
        // not speaking this protocol and the caller should hear about it rather
        // than waiting out the deadline.
        if let Some(tx) = welcome.take() {
            let _ = match &message {
                FromHost::Welcome { version } => tx.send(Ok(*version)),
                other => tx.send(Err(format!(
                    "expected a welcome from the host, got {other:?}"
                ))),
            };
        }

        match message {
            FromHost::Data { channel, bytes } => {
                let Ok(mut map) = channels.lock() else { break };
                if let Some(end) = map.get_mut(&channel) {
                    // A failed write means the actor's end is gone; drop the
                    // channel rather than retrying into a closed socket.
                    if end.local.write_all(&bytes).is_err() {
                        map.remove(&channel);
                    }
                }
            }
            FromHost::Exited { channel, .. } | FromHost::SpawnFailed { channel, .. } => {
                // Must SHUT DOWN, not merely drop. The input pump holds a second
                // clone of this socket, so dropping one handle leaves it open and
                // the actor never sees EOF — a finished remote pane would hang
                // forever. Shutdown reaches every handle at once, giving the actor
                // the same EOF a local PTY produces when its child dies.
                close_channel(&channels, channel);
            }
            FromHost::Spawned { .. } | FromHost::Welcome { .. } => {}
        }
    }

    // If the link died before a welcome, unblock the caller instead of leaving it
    // to time out.
    if let Some(tx) = welcome.take() {
        let _ = tx.send(Err(
            "host closed the connection before a handshake".to_string()
        ));
    }

    // The link died. Close every channel so no pane is left waiting forever on
    // a socket that will never produce another byte.
    let ids: Vec<ChannelId> = channels
        .lock()
        .map(|map| map.keys().copied().collect())
        .unwrap_or_default();
    for channel in ids {
        close_channel(&channels, channel);
    }
}

/// Remove a channel and shut its socket down so every handle observes EOF.
fn close_channel(channels: &Channels, channel: ChannelId) {
    let Some(end) = channels
        .lock()
        .ok()
        .and_then(|mut map| map.remove(&channel))
    else {
        return;
    };
    let _ = end.local.shutdown(std::net::Shutdown::Both);
}

/// Forward bytes the actor writes to the host as `Data` frames.
fn pump_user_input(
    channel: ChannelId,
    mut local: UnixStream,
    writer: Arc<Mutex<Box<dyn Write + Send>>>,
    channels: Channels,
) {
    let mut buffer = [0u8; 8192];
    loop {
        match local.read(&mut buffer) {
            Ok(0) | Err(_) => break,
            Ok(n) => {
                let Ok(mut guard) = writer.lock() else { break };
                let sent = write_frame(
                    &mut *guard,
                    &ToHost::Data {
                        channel,
                        bytes: buffer[..n].to_vec(),
                    },
                )
                .and_then(|()| guard.flush().map_err(super::protocol::FramingError::Io));
                if sent.is_err() {
                    break;
                }
            }
        }
    }
    channels.lock().ok().map(|mut map| map.remove(&channel));
}

fn poisoned() -> std::io::Error {
    std::io::Error::other("pty-host link state poisoned")
}
