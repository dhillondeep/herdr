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
//!
//! # Surviving a dropped connection
//!
//! The daemon keeps the PTYs when its client goes away, so a closed laptop does
//! not end the work. This side is what makes that visible: the transport is
//! *replaceable*. When the reader dies the link does not close its panes — it
//! redials, re-handshakes, and asks the daemon per pane whether it can carry on
//! from the offset it had reached.
//!
//! The reconnect is a redial, not a preserved connection. Nothing at any
//! transport layer survives a closed lid, so none of this tries to.
//!
//! Two rules shape everything here:
//!
//! - **A gap in PTY bytes is not a dropped frame.** herdr's parser is downstream
//!   of this link, so a hole means a half-parsed escape sequence, wrong charset
//!   and mode state, and silent holes in scrollback that the user will read as
//!   real output. Every gap is therefore closed with a parser reset and a visible
//!   marker. Gap-free, or explicitly marked; there is no third option.
//! - **Never replay input.** Output replayed twice is a cosmetic problem;
//!   keystrokes replayed into a coding agent are destructive. Input written while
//!   disconnected is discarded.

use std::collections::HashMap;
use std::io::{Read, Write};
use std::os::fd::{FromRawFd, IntoRawFd, OwnedFd};
use std::os::unix::net::UnixStream;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{mpsc, Arc, Mutex};

use super::protocol::{
    framing_error_is_retryable, negotiate, read_frame, write_frame, ChannelId, FramingError,
    FromHost, GoneReason, Negotiation, SpawnSpec, ToHost, HOST_PROTOCOL_VERSION,
};

/// Per-channel state the link retains after handing the actor its end.
struct ChannelEnd {
    /// Our side of the socket pair: host output is written here for the actor to
    /// read, and user input written by the actor is read from here.
    local: UnixStream,
    /// How many bytes of this channel's output stream have reached the actor.
    ///
    /// This is the resume point, and it counts what was *delivered* rather than
    /// what was received, so a write that failed cannot make us claim ground we
    /// never gave the parser.
    out_offset: u64,
    /// Last window size pushed to the host, replayed after a reconnect.
    ///
    /// Without this a pane that was resized while the link was down keeps the
    /// host's stale winsize, and a full-screen agent redraws at the wrong size
    /// with nothing to indicate why.
    last_resize: Option<Resize>,
    /// Whether output has been lost on this channel since it was created.
    truncated: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Resize {
    rows: u16,
    cols: u16,
    cell_width_px: u32,
    cell_height_px: u32,
}

type Channels = Arc<Mutex<HashMap<ChannelId, ChannelEnd>>>;

/// Where a link is in its lifecycle.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LinkStatus {
    Connected,
    /// The transport died and a redial is in progress. Panes are intact on the
    /// host; their output is accumulating in the daemon's log.
    Reconnecting,
    /// No transport, and no further attempt will be made.
    Closed,
}

/// What a reconnect meant for one pane.
///
/// Reported separately from the byte stream because the user-visible consequences
/// differ and conflating them is the worst available outcome: a pane whose agent
/// is gone must never be presented as one that merely lost some scrollback.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PaneResume {
    /// Caught up exactly. Invisible to the user, which is the goal.
    Resumed,
    /// Alive, but some output could not be recovered. Marked in the stream.
    Truncated,
    /// The daemon restarted. The process is gone and no output was lost — there
    /// is no output any more. Panes must be shown as host-stopped, not exited.
    HostRestarted,
    /// The process finished while the client was away. An ordinary end.
    ChildExited,
}

/// One connection's byte streams, plus the process behind them if any.
pub struct Transport {
    pub reader: Box<dyn Read + Send>,
    pub writer: Box<dyn Write + Send>,
    /// Killed when this transport is replaced, so a redial does not accumulate
    /// ssh processes and zombies.
    pub child: Option<std::process::Child>,
}

/// Opens a fresh transport. Called for the first connect and every redial.
///
/// A closure rather than a target string because it is the only thing about a
/// link that knows what ssh is: tests redial over pipes, production over ssh, and
/// the reconnect logic cannot tell the difference.
type Dialer = Arc<dyn Fn() -> std::io::Result<Transport> + Send + Sync>;

/// The framed writer, replaceable underneath everyone holding a reference.
///
/// `None` while disconnected. Sends then report "not sent" rather than failing,
/// because a disconnect is an expected condition on this path and treating it as
/// an error would tear down panes the daemon is still running.
struct Wire {
    writer: Mutex<Option<Box<dyn Write + Send>>>,
}

impl Wire {
    fn new() -> Self {
        Self {
            writer: Mutex::new(None),
        }
    }

    /// `Ok(true)` if the frame went out, `Ok(false)` if there was no connection to
    /// put it on.
    fn send(&self, message: &ToHost) -> std::io::Result<bool> {
        let mut guard = self.writer.lock().map_err(|_| poisoned())?;
        let Some(writer) = guard.as_mut() else {
            return Ok(false);
        };
        let sent = write_frame(&mut *writer, message)
            .and_then(|()| writer.flush().map_err(FramingError::Io));
        if sent.is_err() {
            // The transport is gone. Drop it here so nothing else tries; the
            // reader will notice independently and start the redial.
            *guard = None;
            return Ok(false);
        }
        Ok(true)
    }

    fn install(&self, writer: Box<dyn Write + Send>) {
        if let Ok(mut guard) = self.writer.lock() {
            *guard = Some(writer);
        }
    }

    fn clear(&self) {
        if let Ok(mut guard) = self.writer.lock() {
            *guard = None;
        }
    }
}

/// Everything the link shares with its dispatcher and supervisor threads.
struct Shared {
    channels: Channels,
    wire: Wire,
    /// Epoch of the daemon we are bound to.
    ///
    /// Sent back on `Attach` so the daemon can answer the one question offsets
    /// cannot: is this the same daemon that owned these panes? Updated only after
    /// an `Attach` has been sent with the previous value, or the check would
    /// always compare the new epoch against itself and never fire.
    epoch: AtomicU64,
    status: Mutex<LinkStatus>,
    /// Per-pane reconnect outcomes waiting to be read by the layers above.
    resume: Mutex<Vec<(ChannelId, PaneResume)>>,
    /// Why each channel ended, kept after the channel itself is gone.
    ///
    /// The pane learns its process ended by seeing EOF on a socket, which says
    /// nothing about why. Without this, a host that restarted is indistinguishable
    /// from an agent that finished — and closing a pane as "done" when its machine
    /// went away is the one outcome the epoch check exists to prevent.
    gone: Mutex<HashMap<ChannelId, GoneReason>>,
    /// Set on an explicit close, so a redial is not attempted for a link nobody
    /// wants any more.
    closing: AtomicBool,
    /// Set when the link died for a reason a redial cannot fix — the two sides
    /// disagreeing about the bytes on the wire. Retrying that spins forever.
    fatal: AtomicBool,
    /// The process behind the live transport, so closing the link can unblock a
    /// reader that is parked on it.
    child: Mutex<Option<std::process::Child>>,
    /// Callers waiting on an `Exec`, by request id.
    ///
    /// A map rather than a channel per call so a dead transport can fail every waiter
    /// at once: an exec whose answer will never arrive has to return, or the thread
    /// that asked is parked forever.
    execs: Mutex<HashMap<u64, mpsc::Sender<ExecOutput>>>,
    next_exec_id: AtomicU64,
    /// Channels closed while disconnected. Re-sent after a reconnect, otherwise
    /// closing a pane offline leaves its process running on the host forever.
    pending_shutdown: Mutex<Vec<ChannelId>>,
}

/// A connected pty-host link.
pub struct HostLink {
    shared: Arc<Shared>,
    next_channel: AtomicU64,
    /// Version the peer advertised, for diagnostics.
    peer_version: u32,
}

/// How long to wait for a host to answer a handshake.
///
/// Bounded because this can run where a keypress is waiting: an unreachable or
/// wedged host must fail rather than freeze the interface.
const HANDSHAKE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(20);

/// First redial delay. Doubles up to [`redial_max_delay`].
const REDIAL_BASE_DELAY: std::time::Duration = std::time::Duration::from_millis(250);

/// Bytes that put a VT parser back into a known state after a gap.
///
/// `ESC \` first: if the bytes we lost had opened an OSC, DCS or APC string, the
/// parser is inside one and would swallow everything that follows — including the
/// reset itself. `ESC c` (RIS) then clears modes, charsets, the scroll region and
/// the alternate screen, which are exactly the pieces of state a truncated stream
/// leaves wrong and which no amount of subsequent output repairs.
const RESYNC: &[u8] = b"\x1b\\\x1bc";

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

/// How many redials before a link gives up and closes its panes.
///
/// Counted in attempts rather than elapsed time on purpose. A laptop that was
/// asleep for eight hours has burned no attempts, because the sleeping thread was
/// not running — whereas a deadline measured in wall clock would have expired
/// before the machine even woke up, which is the exact case this exists for.
fn redial_attempts() -> u32 {
    env_u32("HERDR_HOST_REDIAL_ATTEMPTS", 30)
}

/// Ceiling on the backoff delay.
fn redial_max_delay() -> std::time::Duration {
    std::time::Duration::from_millis(u64::from(env_u32("HERDR_HOST_REDIAL_MAX_MS", 30_000)))
}

fn env_u32(key: &str, default: u32) -> u32 {
    std::env::var(key)
        .ok()
        .and_then(|raw| raw.parse().ok())
        .unwrap_or(default)
}

/// Exponential backoff with jitter.
///
/// Jitter matters more than it looks: several panes on several hosts all lose
/// their links at the same moment when a laptop wakes, and an unjittered backoff
/// makes them retry in lockstep, so every attempt hits a network that is either
/// up for all of them or down for all of them.
fn redial_delay(attempt: u32) -> std::time::Duration {
    let max = redial_max_delay();
    let scaled = REDIAL_BASE_DELAY.saturating_mul(1u32 << attempt.min(16));
    let capped = scaled.min(max);
    let jitter = jitter_fraction();
    // Up to 25% either side, never below the base delay.
    let millis = capped.as_millis() as u64;
    let spread = millis / 4;
    let offset = if spread == 0 {
        0
    } else {
        jitter % (spread * 2)
    };
    // Clamped after jittering, not before: adding up to a quarter on top of an
    // already-capped delay would put the result over the ceiling the cap exists to
    // guarantee. Never zero either — a zero delay is a spin loop against an
    // unreachable host.
    let jittered = millis
        .saturating_sub(spread)
        .saturating_add(offset)
        .clamp(1, millis.max(1));
    std::time::Duration::from_millis(jittered)
}

/// Cheap entropy for jitter. The clock is enough here — this does not need to be
/// unpredictable, only uncorrelated between links.
fn jitter_fraction() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|since| since.subsec_nanos() as u64)
        .unwrap_or(0)
}

/// What a command on the host printed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExecOutput {
    /// `None` when the process was killed by a signal or never started.
    pub code: Option<i32>,
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
}

impl ExecOutput {
    pub fn succeeded(&self) -> bool {
        self.code == Some(0)
    }
}

/// How long to wait for a command on the host.
///
/// Bounded because callers are background workers that run on a timer: one wedged host
/// must not accumulate parked threads, and a stale answer is no worse than none.
const EXEC_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(20);

/// Where ssh keeps the multiplexing socket for a host.
///
/// A shared master turns a redial into opening a channel on a connection that is
/// already up, rather than a fresh TCP handshake, key exchange and — for hosts reached
/// through a `ProxyCommand`, which is how workspace managers expose theirs — a fresh
/// proxy process.
///
/// **This is not a measured speedup.** On a Coder-proxied workspace over a good link,
/// a cold connection took 261ms and a multiplexed one 279ms: the same, within noise.
/// What it actually buys is bounded work per redial on the paths where that work is
/// not free — a host that re-authenticates, or a proxy that is slow to spawn — and one
/// session per host instead of one per redial when a flapping network is reconnecting
/// repeatedly. Anyone tempted to justify this by latency should measure their own path
/// first; on this one there is nothing to find.
///
/// The path is derived from the target rather than from this process, so a herdr that
/// restarts reuses a master that is still alive.
///
/// `None` when no short enough path is available, in which case multiplexing is simply
/// not used: `sun_path` is byte-limited (104 on macOS, 108 on Linux) and a path over
/// that limit makes ssh fail outright, which would be a worse trade than a slower
/// reconnect.
fn control_path(target: &str) -> Option<std::path::PathBuf> {
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};
    use std::os::unix::ffi::OsStrExt;
    use std::os::unix::fs::DirBuilderExt;

    let mut hasher = DefaultHasher::new();
    target.hash(&mut hasher);
    let name = format!("{:08x}", hasher.finish() as u32);

    // Short bases first. `/tmp` is tried even when it is not the platform temp dir,
    // because macOS temp paths are long enough on their own to exhaust the limit.
    let mut bases = vec![std::path::PathBuf::from("/tmp")];
    let platform = std::env::temp_dir();
    if platform != std::path::Path::new("/tmp") {
        bases.push(platform);
    }

    for base in bases {
        // Per-user so two accounts on one machine cannot collide, and 0700 because a
        // control socket is enough to open a session as its owner.
        let dir = base.join(format!("herdr-ctl-{}", unsafe { libc::getuid() }));
        let path = dir.join(&name);
        if path.as_os_str().as_bytes().len() > 103 {
            continue;
        }
        if std::fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(&dir)
            .is_ok()
        {
            return Some(path);
        }
    }
    None
}

/// Drop a multiplexing master that may be wedged.
///
/// A master whose network has gone but whose TCP has not yet noticed will accept a
/// new channel and then hang. Every redial would inherit that until the master aged
/// out, so retries clear it first: the cost is one short-lived ssh invocation at
/// exactly the moment something has already gone wrong.
fn drop_control_master(target: &str, path: &std::path::Path) {
    let _ = std::process::Command::new("ssh")
        .arg("-o")
        .arg("BatchMode=yes")
        .arg("-S")
        .arg(path)
        .arg("-O")
        .arg("exit")
        .arg(target)
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status();
}

impl HostLink {
    /// Connect to a host by running `herdr pty-host` there over ssh.
    ///
    /// ssh is only a way to carry stdio, so it is confined to this one function;
    /// everything else works on streams and is exercised over pipes in tests.
    /// Keepalives are set so a dead link surfaces rather than hanging forever.
    ///
    /// The returned link redials this same target for as long as it lives, so a
    /// dropped connection recovers without the caller doing anything.
    pub fn connect_over_ssh(target: &str) -> std::io::Result<Self> {
        let owned = target.to_string();
        // Held across dials so a failure can quote what the host actually said.
        let last_stderr: Arc<Mutex<String>> = Arc::new(Mutex::new(String::new()));
        let stderr_slot = Arc::clone(&last_stderr);
        let control = control_path(target);
        let dialed_before = AtomicBool::new(false);

        let dialer: Dialer = Arc::new(move || {
            // Only on a retry: the first dial has nothing stale to clear, and doing
            // it there would throw away a master another herdr is using.
            if dialed_before.swap(true, Ordering::SeqCst) {
                if let Some(path) = control.as_deref() {
                    drop_control_master(&owned, path);
                }
            }

            let mut command = std::process::Command::new("ssh");
            command
                .arg("-o")
                .arg("BatchMode=yes")
                // Fail fast on an unreachable host instead of sitting in ssh's
                // default connect timeout.
                .arg("-o")
                .arg("ConnectTimeout=10")
                .arg("-o")
                .arg("ServerAliveInterval=30")
                .arg("-o")
                .arg("ServerAliveCountMax=6");
            if let Some(path) = control.as_deref() {
                command
                    .arg("-S")
                    .arg(path)
                    .arg("-o")
                    .arg("ControlMaster=auto")
                    // Bounded rather than `yes`: a master that outlives its usefulness
                    // is a wedged connection waiting to be inherited, and the window
                    // only has to cover a redial.
                    .arg("-o")
                    .arg("ControlPersist=30");
            }
            let mut child = command
                // No tty: this is a framed byte protocol, and a pty would mangle it.
                .arg("-T")
                .arg(&owned)
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

            let reader = child
                .stdout
                .take()
                .ok_or_else(|| std::io::Error::other("ssh produced no stdout"))?;
            let writer = child
                .stdin
                .take()
                .ok_or_else(|| std::io::Error::other("ssh produced no stdin"))?;

            // Drained on a thread rather than left in the pipe: ssh blocks once
            // the buffer fills, and this is the only explanation a user gets for
            // a host that will not start.
            if let Some(mut pipe) = child.stderr.take() {
                let slot = Arc::clone(&stderr_slot);
                std::thread::spawn(move || {
                    let mut raw = Vec::new();
                    let _ = pipe.read_to_end(&mut raw);
                    if let Ok(mut guard) = slot.lock() {
                        *guard = String::from_utf8_lossy(&raw).trim().to_string();
                    }
                });
            }

            Ok(Transport {
                reader: Box::new(reader),
                writer: Box::new(writer),
                child: Some(child),
            })
        });

        Self::connect_with_dialer(dialer, true).map_err(|err| {
            let stderr = last_stderr
                .lock()
                .map(|guard| guard.clone())
                .unwrap_or_default();
            let detail = if stderr.is_empty() {
                // The most common cause by far is no herdr on the host.
                "Check that herdr is installed there, or run `herdr host probe` for detail."
                    .to_string()
            } else {
                format!("host said: {stderr}")
            };
            std::io::Error::other(format!(
                "could not start herdr pty-host on {target}: {err}. {detail}"
            ))
        })
    }

    /// Handshake over an already-established byte stream, with no redial.
    ///
    /// Taking streams rather than spawning ssh keeps the transport out of this
    /// layer: the same code is driven over pipes in tests and over ssh in
    /// production, so the interesting logic is exercised without a network. A
    /// caller who hands over a stream has nothing to redial, so when it dies the
    /// panes close — the behaviour a single-shot link has always had.
    // Used by tests and by callers that already hold a stream; production goes
    // through `connect_over_ssh`, which needs the redial.
    #[allow(dead_code)]
    pub fn connect<R: Read + Send + 'static>(
        reader: R,
        writer: Box<dyn Write + Send>,
    ) -> std::io::Result<Self> {
        let once = Mutex::new(Some(Transport {
            reader: Box::new(reader),
            writer,
            child: None,
        }));
        let dialer: Dialer = Arc::new(move || {
            once.lock()
                .map_err(|_| poisoned())?
                .take()
                .ok_or_else(|| std::io::Error::other("this link cannot be redialled"))
        });
        Self::connect_with_dialer(dialer, false)
    }

    /// Connect using `dialer`, optionally redialling it forever.
    fn connect_with_dialer(dialer: Dialer, redial: bool) -> std::io::Result<Self> {
        let shared = Arc::new(Shared {
            channels: Arc::new(Mutex::new(HashMap::new())),
            wire: Wire::new(),
            epoch: AtomicU64::new(0),
            status: Mutex::new(LinkStatus::Reconnecting),
            resume: Mutex::new(Vec::new()),
            gone: Mutex::new(HashMap::new()),
            closing: AtomicBool::new(false),
            fatal: AtomicBool::new(false),
            child: Mutex::new(None),
            execs: Mutex::new(HashMap::new()),
            next_exec_id: AtomicU64::new(1),
            pending_shutdown: Mutex::new(Vec::new()),
        });

        // The first attempt happens inline so the caller learns immediately that a
        // host is unreachable or speaks the wrong protocol, rather than getting a
        // link that looks fine and never carries anything.
        let (peer_version, dispatcher) = open(&dialer, &shared)?;
        set_status(&shared, LinkStatus::Connected);

        {
            let shared = Arc::clone(&shared);
            std::thread::spawn(move || supervise(dialer, shared, dispatcher, redial));
        }

        Ok(Self {
            shared,
            next_channel: AtomicU64::new(1),
            peer_version,
        })
    }

    /// Protocol version the host advertised. Surfaced for diagnostics: with many
    /// hosts, version skew is the failure people hit most.
    pub fn peer_version(&self) -> u32 {
        self.peer_version
    }

    /// Where this link is in its lifecycle.
    pub fn status(&self) -> LinkStatus {
        self.shared
            .status
            .lock()
            .map(|guard| *guard)
            .unwrap_or(LinkStatus::Closed)
    }

    // Consumed by the pane layer in the next chunk, which maps a channel back to
    // a pane so `HostRestarted` can show as host-stopped rather than exited. Kept
    // here because this is where the information exists, and both are covered by
    // tests.
    /// Take the reconnect outcomes recorded since this was last called.
    ///
    /// Drained rather than observed so nothing is reported twice, and per pane
    /// rather than per link because a reconnect can resume one pane and lose
    /// another.
    #[allow(dead_code)]
    pub fn drain_resume_events(&self) -> Vec<(ChannelId, PaneResume)> {
        self.shared
            .resume
            .lock()
            .map(|mut queue| std::mem::take(&mut *queue))
            .unwrap_or_default()
    }

    /// Run a command on the host and wait for what it printed.
    ///
    /// Blocking, and therefore for background work only — never the render path. It
    /// exists so facts about the machine the work is on can be asked of that machine:
    /// answering them locally is not merely unavailable but wrong, because a path that
    /// happens to exist here describes a different repository entirely.
    pub fn exec(&self, argv: &[String], cwd: Option<&str>) -> std::io::Result<ExecOutput> {
        let id = self.shared.next_exec_id.fetch_add(1, Ordering::Relaxed);
        let (tx, rx) = mpsc::channel();
        self.shared
            .execs
            .lock()
            .map_err(|_| poisoned())?
            .insert(id, tx);

        let sent = self.shared.wire.send(&ToHost::Exec {
            id,
            argv: argv.to_vec(),
            cwd: cwd.map(str::to_string),
        })?;
        if !sent {
            self.shared.execs.lock().ok().map(|mut map| map.remove(&id));
            return Err(std::io::Error::other("host link is reconnecting"));
        }

        match rx.recv_timeout(EXEC_TIMEOUT) {
            Ok(output) => Ok(output),
            // Either the deadline passed or the transport died and dropped the sender.
            // Both mean no answer is coming, and both must clear the registration or
            // the map grows for the life of the link.
            Err(_) => {
                self.shared.execs.lock().ok().map(|mut map| map.remove(&id));
                Err(std::io::Error::other("no answer from the host"))
            }
        }
    }

    /// Why a channel ended, if the host said.
    ///
    /// Read when the pane observes EOF, which is the moment it has to decide whether
    /// this was an ordinary exit or a machine disappearing underneath it.
    pub fn gone_reason(&self, channel: ChannelId) -> Option<GoneReason> {
        self.shared
            .gone
            .lock()
            .ok()
            .and_then(|gone| gone.get(&channel).copied())
    }

    /// Whether a channel has lost output at any point in its life.
    #[allow(dead_code)]
    pub fn channel_truncated(&self, channel: ChannelId) -> bool {
        self.shared
            .channels
            .lock()
            .map(|map| map.get(&channel).is_some_and(|end| end.truncated))
            .unwrap_or(false)
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

        self.shared.channels.lock().map_err(|_| poisoned())?.insert(
            channel,
            ChannelEnd {
                local: local_side.try_clone()?,
                out_offset: 0,
                last_resize: None,
                truncated: false,
            },
        );

        // Refuse rather than create a pane the host has never heard of: a Spawn
        // dropped on the floor would come back from the next Attach as `Gone`, so
        // the user would watch a pane appear and then die for no visible reason.
        let sent = self.shared.wire.send(&ToHost::Spawn {
            channel,
            spec: spec.clone(),
        })?;
        if !sent {
            close_channel(&self.shared.channels, channel);
            return Err(std::io::Error::other(
                "host link is reconnecting; try again in a moment",
            ));
        }

        // Pump user input: whatever the actor writes becomes a Data frame.
        {
            let shared = Arc::clone(&self.shared);
            std::thread::spawn(move || pump_user_input(channel, local_side, shared));
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
        // Remembered even when it cannot be sent, so a reconnect can bring the
        // host's winsize back in line with what the pane actually is.
        if let Ok(mut map) = self.shared.channels.lock() {
            if let Some(end) = map.get_mut(&channel) {
                end.last_resize = Some(Resize {
                    rows,
                    cols,
                    cell_width_px,
                    cell_height_px,
                });
            }
        }
        self.shared.wire.send(&ToHost::Resize {
            channel,
            rows,
            cols,
            cell_width_px,
            cell_height_px,
        })?;
        Ok(())
    }

    /// Ask the host to terminate a channel's process session.
    pub fn shutdown_channel(&self, channel: ChannelId) -> std::io::Result<()> {
        let sent = self.shared.wire.send(&ToHost::Shutdown { channel })?;
        if !sent {
            // Queued rather than dropped: forgetting it would leave the process
            // running on the host with nothing left that refers to it.
            if let Ok(mut pending) = self.shared.pending_shutdown.lock() {
                pending.push(channel);
            }
        }
        // Close regardless, so the actor sees EOF even if the link is already gone.
        close_channel(&self.shared.channels, channel);
        Ok(())
    }

    /// Stop redialling and close every pane.
    pub fn close(&self) {
        self.shared.closing.store(true, Ordering::SeqCst);
        self.shared.wire.clear();
        // Kill the transport so a reader parked on it wakes up and the supervisor
        // observes the close rather than waiting out a keepalive.
        if let Ok(mut guard) = self.shared.child.lock() {
            if let Some(mut child) = guard.take() {
                let _ = child.kill();
                let _ = child.wait();
            }
        }
        set_status(&self.shared, LinkStatus::Closed);
        close_all_channels(&self.shared.channels);
    }
}

impl Drop for HostLink {
    fn drop(&mut self) {
        self.close();
    }
}

/// Dial, handshake, and start dispatching. Returns the peer version and the
/// dispatcher thread, which the supervisor waits on.
fn open(
    dialer: &Dialer,
    shared: &Arc<Shared>,
) -> std::io::Result<(u32, std::thread::JoinHandle<()>)> {
    let transport = dialer()?;

    // Replace the previous process handle, reaping it: a redial that leaked one
    // zombie per attempt would eventually be the reason the host stops working.
    if let Ok(mut guard) = shared.child.lock() {
        if let Some(mut old) = std::mem::replace(&mut *guard, transport.child) {
            let _ = old.kill();
            let _ = old.wait();
        }
    }

    shared.wire.install(transport.writer);

    let (welcome_tx, welcome_rx) = mpsc::channel();
    let dispatcher = {
        let shared = Arc::clone(shared);
        std::thread::spawn(move || dispatch_from_host(transport.reader, shared, welcome_tx))
    };

    // Sent after the dispatcher exists so a host that answers instantly is not
    // racing an unspawned reader.
    let hello_sent = shared.wire.send(&ToHost::Hello {
        version: HOST_PROTOCOL_VERSION,
    })?;
    if !hello_sent {
        abandon(shared, dispatcher);
        return Err(std::io::Error::other("host link closed before a handshake"));
    }

    // The dispatcher reads every frame including the first and reports the welcome
    // through a channel. That is what lets the handshake have a DEADLINE: a plain
    // blocking read on a wedged host would hang the caller forever, and this runs
    // where a keypress is waiting.
    let (peer_version, epoch) = match welcome_rx.recv_timeout(HANDSHAKE_TIMEOUT) {
        Ok(Ok(welcome)) => welcome,
        Ok(Err(message)) => {
            abandon(shared, dispatcher);
            return Err(std::io::Error::other(message));
        }
        Err(_) => {
            abandon(shared, dispatcher);
            return Err(std::io::Error::other(format!(
                "host did not answer within {}s",
                HANDSHAKE_TIMEOUT.as_secs()
            )));
        }
    };

    // Name both versions: with many hosts, "incompatible" alone does not say
    // which end to upgrade.
    match negotiate(peer_version) {
        Negotiation::Ok => {}
        Negotiation::PeerTooOld {
            peer,
            min_supported,
        } => {
            abandon(shared, dispatcher);
            return Err(std::io::Error::other(format!(
                "host speaks protocol {peer}, this herdr needs at least {min_supported}; re-provision the host"
            )));
        }
        Negotiation::PeerTooNew { peer, ours } => {
            abandon(shared, dispatcher);
            return Err(std::io::Error::other(format!(
                "host speaks protocol {peer}, this herdr understands up to {ours}; upgrade this herdr"
            )));
        }
    }

    // Ask about every pane we still hold, quoting the epoch we had BEFORE this
    // handshake. Swapping first and sending the new value would compare the
    // daemon's epoch against itself, so a restarted daemon would look like the
    // same one and every pane would appear to resume into a process that no
    // longer exists.
    let previous_epoch = shared.epoch.swap(epoch, Ordering::SeqCst);
    let panes = pane_offsets(&shared.channels);
    if !panes.is_empty() {
        let _ = shared.wire.send(&ToHost::Attach {
            host_epoch: previous_epoch,
            panes,
        });
        resend_resizes(shared);
    }
    flush_pending_shutdowns(shared);

    Ok((peer_version, dispatcher))
}

/// Tear down a transport whose handshake did not complete.
fn abandon(shared: &Arc<Shared>, dispatcher: std::thread::JoinHandle<()>) {
    shared.wire.clear();
    if let Ok(mut guard) = shared.child.lock() {
        if let Some(mut child) = guard.take() {
            let _ = child.kill();
            let _ = child.wait();
        }
    }
    // The reader may be parked; killing the process above is what releases it.
    let _ = dispatcher.join();
}

/// Keep the link connected for as long as anyone holds it.
fn supervise(
    dialer: Dialer,
    shared: Arc<Shared>,
    mut dispatcher: std::thread::JoinHandle<()>,
    redial: bool,
) {
    loop {
        let _ = dispatcher.join();
        shared.wire.clear();

        if shared.closing.load(Ordering::SeqCst) {
            break;
        }
        // The two sides disagree about the bytes on the wire; a redial produces
        // the same disagreement, so stop rather than spin.
        if !redial || shared.fatal.load(Ordering::SeqCst) {
            break;
        }

        set_status(&shared, LinkStatus::Reconnecting);
        match redial_loop(&dialer, &shared) {
            Some(next) => {
                dispatcher = next;
                set_status(&shared, LinkStatus::Connected);
            }
            None => break,
        }
    }

    // Nothing will produce another byte for these panes, so close them rather
    // than leave the actors waiting on a socket forever.
    set_status(&shared, LinkStatus::Closed);
    close_all_channels(&shared.channels);
}

fn redial_loop(dialer: &Dialer, shared: &Arc<Shared>) -> Option<std::thread::JoinHandle<()>> {
    let attempts = redial_attempts();
    for attempt in 0..attempts {
        std::thread::sleep(redial_delay(attempt));
        if shared.closing.load(Ordering::SeqCst) {
            return None;
        }
        match open(dialer, shared) {
            Ok((_, dispatcher)) => return Some(dispatcher),
            Err(_) => continue,
        }
    }
    None
}

fn pane_offsets(channels: &Channels) -> Vec<(ChannelId, u64)> {
    channels
        .lock()
        .map(|map| {
            map.iter()
                .map(|(channel, end)| (*channel, end.out_offset))
                .collect()
        })
        .unwrap_or_default()
}

fn resend_resizes(shared: &Arc<Shared>) {
    let sizes: Vec<(ChannelId, Resize)> = shared
        .channels
        .lock()
        .map(|map| {
            map.iter()
                .filter_map(|(channel, end)| end.last_resize.map(|size| (*channel, size)))
                .collect()
        })
        .unwrap_or_default();
    for (channel, size) in sizes {
        let _ = shared.wire.send(&ToHost::Resize {
            channel,
            rows: size.rows,
            cols: size.cols,
            cell_width_px: size.cell_width_px,
            cell_height_px: size.cell_height_px,
        });
    }
}

fn flush_pending_shutdowns(shared: &Arc<Shared>) {
    let queued: Vec<ChannelId> = shared
        .pending_shutdown
        .lock()
        .map(|mut pending| std::mem::take(&mut *pending))
        .unwrap_or_default();
    for channel in queued {
        let _ = shared.wire.send(&ToHost::Shutdown { channel });
    }
}

fn set_status(shared: &Arc<Shared>, status: LinkStatus) {
    if let Ok(mut guard) = shared.status.lock() {
        // A closed link stays closed; a late redial must not resurrect it.
        if *guard != LinkStatus::Closed {
            *guard = status;
        }
    }
}

fn note_resume(shared: &Arc<Shared>, channel: ChannelId, outcome: PaneResume) {
    if let Ok(mut queue) = shared.resume.lock() {
        queue.push((channel, outcome));
    }
}

/// Fan host frames out to the per-channel sockets the actors read from.
///
/// Returns when the transport dies. Deliberately does NOT close channels: whether
/// a dead transport means dead panes is the supervisor's decision, and getting it
/// wrong here would kill the agents on every wifi blip.
fn dispatch_from_host(
    mut reader: Box<dyn Read + Send>,
    shared: Arc<Shared>,
    welcome: mpsc::Sender<Result<(u32, u64), String>>,
) {
    let mut welcome = Some(welcome);

    loop {
        let message = match read_frame::<_, FromHost>(&mut reader) {
            Ok(message) => message,
            Err(error) => {
                if !framing_error_is_retryable(&error) {
                    shared.fatal.store(true, Ordering::SeqCst);
                }
                break;
            }
        };

        // The first frame must be the welcome; anything else means the peer is
        // not speaking this protocol and the caller should hear about it rather
        // than waiting out the deadline.
        if let Some(tx) = welcome.take() {
            let _ = match &message {
                FromHost::Welcome {
                    version,
                    host_epoch,
                } => tx.send(Ok((*version, *host_epoch))),
                other => tx.send(Err(format!(
                    "expected a welcome from the host, got {other:?}"
                ))),
            };
        }

        match message {
            FromHost::Data {
                channel,
                from,
                bytes,
            } => deliver(&shared, channel, from, &bytes),
            FromHost::Replay {
                channel,
                from,
                bytes,
            } => {
                deliver(&shared, channel, from, &bytes);
                note_resume(&shared, channel, PaneResume::Resumed);
            }
            FromHost::Snapshot {
                channel,
                out_offset,
                ansi,
            } => {
                // Too far behind to replay, but the host re-derived the screen. Show
                // it rather than a blank pane: this is the case an overnight reattach
                // always lands in, so it is the one that decides whether any of this
                // is worth having.
                if reseed(&shared, channel, out_offset, &ansi) {
                    note_resume(&shared, channel, PaneResume::Truncated);
                } else {
                    note_resume(&shared, channel, PaneResume::Resumed);
                }
            }
            FromHost::Desync {
                channel,
                available_from: _,
                out_offset,
            } => {
                // The bytes between where we were and where the stream is now are
                // gone for good. Reset the parser and say so in the pane: silently
                // continuing would put a hole in the middle of what the user reads
                // as real output.
                if resync(&shared, channel, out_offset) {
                    note_resume(&shared, channel, PaneResume::Truncated);
                } else {
                    // Live output had already carried us past the point the host
                    // resynced to, so nothing was lost here.
                    note_resume(&shared, channel, PaneResume::Resumed);
                }
            }
            FromHost::Gone { channel, reason } => {
                if let Ok(mut gone) = shared.gone.lock() {
                    gone.insert(channel, reason);
                }
                match reason {
                    GoneReason::HostRestarted => {
                        // Said in the pane before it closes, because an agent that
                        // vanished with the host must not read as one that finished.
                        write_notice(
                            &shared,
                            channel,
                            b"\r\n\x1b[2m-- herdr: the host restarted; this pane's process is gone --\x1b[0m\r\n",
                        );
                        note_resume(&shared, channel, PaneResume::HostRestarted);
                    }
                    GoneReason::ChildExited => {
                        note_resume(&shared, channel, PaneResume::ChildExited);
                    }
                }
                close_channel(&shared.channels, channel);
            }
            FromHost::Exited { channel, .. } | FromHost::SpawnFailed { channel, .. } => {
                // Must SHUT DOWN, not merely drop. The input pump holds a second
                // clone of this socket, so dropping one handle leaves it open and
                // the actor never sees EOF — a finished remote pane would hang
                // forever. Shutdown reaches every handle at once, giving the actor
                // the same EOF a local PTY produces when its child dies.
                close_channel(&shared.channels, channel);
            }
            FromHost::ExecResult {
                id,
                code,
                stdout,
                stderr,
            } => {
                if let Some(waiter) = shared.execs.lock().ok().and_then(|mut map| map.remove(&id)) {
                    let _ = waiter.send(ExecOutput {
                        code,
                        stdout,
                        stderr,
                    });
                }
            }
            FromHost::Spawned { .. } | FromHost::Welcome { .. } => {}
        }
    }

    // Every exec waiting on this transport will never be answered on it. Dropping the
    // senders is what wakes those threads; leaving them registered would park each one
    // until its own deadline for no reason.
    if let Ok(mut execs) = shared.execs.lock() {
        execs.clear();
    }

    // If the link died before a welcome, unblock the caller instead of leaving it
    // to time out.
    if let Some(tx) = welcome.take() {
        let _ = tx.send(Err(
            "host closed the connection before a handshake".to_string()
        ));
    }
}

/// What to do with a positioned run of output, given where the parser has reached.
///
/// Separated from the writing so the arithmetic can be tested without a socket.
/// An off-by-one here is silent, unreproducible grid corruption — the one failure
/// mode in this whole path that leaves no trace to debug from — so it is the part
/// that most needs to be reachable by a property test.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Reconciled {
    /// Every byte in the frame has already been given to the parser.
    AlreadySeen,
    /// Write the frame from `skip` onwards; the parser then stands at `next`.
    Write { skip: usize, next: u64 },
    /// `missing` bytes between the parser and this frame will never arrive. Reset,
    /// mark, then write the whole frame; the parser then stands at `next`.
    Gap { missing: u64, next: u64 },
}

/// Decide how a frame at `from` relates to a parser that has consumed `delivered`
/// bytes of this stream.
///
/// Every case is a real one. An overlap happens because answering an `Attach` is
/// not atomic with respect to output still being produced, so a `Replay` and a
/// live `Data` frame can cover the same bytes. A gap should be impossible over a
/// stream transport, which is exactly why it is handled: if one ever occurs it is a
/// bug, and feeding it to the parser would corrupt the grid silently rather than
/// reporting anything at all.
pub(super) fn reconcile(delivered: u64, from: u64, len: usize) -> Reconciled {
    let next = from.saturating_add(len as u64);
    if next <= delivered {
        return Reconciled::AlreadySeen;
    }
    if from > delivered {
        return Reconciled::Gap {
            missing: from - delivered,
            next,
        };
    }
    Reconciled::Write {
        skip: (delivered - from) as usize,
        next,
    }
}

/// Write one positioned run of output to a channel's actor.
fn deliver(shared: &Arc<Shared>, channel: ChannelId, from: u64, bytes: &[u8]) {
    let Ok(mut map) = shared.channels.lock() else {
        return;
    };
    let Some(end) = map.get_mut(&channel) else {
        return;
    };

    let (payload, next, gap) = match reconcile(end.out_offset, from, bytes.len()) {
        Reconciled::AlreadySeen => return,
        Reconciled::Write { skip, next } => (&bytes[skip..], next, 0),
        Reconciled::Gap { missing, next } => (bytes, next, missing),
    };

    if gap > 0 {
        end.truncated = true;
        let mut notice = Vec::from(RESYNC);
        notice.extend_from_slice(&truncation_marker(gap));
        if end.local.write_all(&notice).is_err() {
            map.remove(&channel);
            return;
        }
    }

    // A failed write means the actor's end is gone; drop the channel rather than
    // retrying into a closed socket. The offset only advances on success, so a
    // partial delivery can never be mistaken for a complete one.
    if end.local.write_all(payload).is_err() {
        map.remove(&channel);
        return;
    }
    end.out_offset = next;
    if gap > 0 {
        drop(map);
        note_resume(shared, channel, PaneResume::Truncated);
    }
}

/// Handle a `Desync`: the host cannot catch this pane up without a hole.
///
/// Returns whether anything was actually lost, so the caller only records a
/// truncation that happened.
fn resync(shared: &Arc<Shared>, channel: ChannelId, host_offset: u64) -> bool {
    let Ok(mut map) = shared.channels.lock() else {
        return false;
    };
    let Some(end) = map.get_mut(&channel) else {
        return false;
    };

    // The host reports where the live stream stood when it answered the attach,
    // and output kept being produced while that answer was in flight — so a live
    // frame can carry the parser PAST this point before the answer arrives. Taking
    // the reported offset unconditionally would then move the cursor BACKWARDS and
    // re-deliver bytes the parser already has. Whatever gap existed was reported by
    // `deliver` when it saw that frame jump ahead, so there is nothing left to say.
    if host_offset <= end.out_offset {
        return false;
    }

    let missing = host_offset - end.out_offset;
    end.truncated = true;
    // Jump to where the live stream is, so the frames that follow line up instead
    // of each looking like a fresh gap.
    end.out_offset = host_offset;

    let mut notice = Vec::from(RESYNC);
    notice.extend_from_slice(&truncation_marker(missing));
    if end.local.write_all(&notice).is_err() {
        map.remove(&channel);
    }
    true
}

/// Replace a pane's screen with a host-rendered snapshot.
///
/// Returns whether anything was actually restored, so a stale snapshot — one the
/// parser has already advanced past — is ignored the same way a stale `Desync` is,
/// rather than winding the cursor backwards.
///
/// The scrollback behind the snapshot is genuinely gone, so it is marked. Showing
/// the screen without saying the history is missing would leave the user scrolling
/// up into output that silently predates the gap.
fn reseed(shared: &Arc<Shared>, channel: ChannelId, host_offset: u64, ansi: &str) -> bool {
    let Ok(mut map) = shared.channels.lock() else {
        return false;
    };
    let Some(end) = map.get_mut(&channel) else {
        return false;
    };
    if host_offset <= end.out_offset {
        return false;
    }

    let missing = host_offset - end.out_offset;
    end.truncated = true;
    end.out_offset = host_offset;

    // Reset first: the snapshot assumes a known parser state, and whatever the gap
    // left half-parsed would otherwise swallow the front of it.
    let mut payload = Vec::from(RESYNC);
    payload.extend_from_slice(ansi.as_bytes());
    payload.extend_from_slice(&snapshot_marker(missing));
    if end.local.write_all(&payload).is_err() {
        map.remove(&channel);
    }
    true
}

/// Text the user sees when the screen was restored but the history behind it was not.
fn snapshot_marker(missing: u64) -> Vec<u8> {
    format!(
        "\r\n\x1b[2m-- herdr: reconnected; screen restored, {missing} bytes of scrollback \
         were lost --\x1b[0m\r\n"
    )
    .into_bytes()
}

/// Text the user sees where output was lost.
///
/// Visible on purpose. A silent truncation is indistinguishable from an agent that
/// simply printed nothing, and the whole point of preferring an explicit `Desync`
/// over a partial replay is that the user gets told.
fn truncation_marker(missing: u64) -> Vec<u8> {
    format!(
        "\r\n\x1b[2m-- herdr: reconnected; {missing} bytes of output while disconnected \
         could not be recovered --\x1b[0m\r\n"
    )
    .into_bytes()
}

/// Put a message in a pane's own output, without disturbing offsets.
///
/// Not counted in `out_offset` because it is not part of the host's stream; the
/// pane is about to close, so the offset will never be used again either way.
fn write_notice(shared: &Arc<Shared>, channel: ChannelId, notice: &[u8]) {
    if let Ok(mut map) = shared.channels.lock() {
        if let Some(end) = map.get_mut(&channel) {
            let _ = end.local.write_all(notice);
        }
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

fn close_all_channels(channels: &Channels) {
    let ids: Vec<ChannelId> = channels
        .lock()
        .map(|map| map.keys().copied().collect())
        .unwrap_or_default();
    for channel in ids {
        close_channel(channels, channel);
    }
}

/// Forward bytes the actor writes to the host as `Data` frames.
///
/// A send that cannot go out is **discarded, not queued**. Buffering keystrokes
/// across a disconnect and delivering them on reconnect would replay input into
/// whatever the agent is doing minutes later, which is destructive in a way that
/// replaying output is not.
fn pump_user_input(channel: ChannelId, mut local: UnixStream, shared: Arc<Shared>) {
    let mut buffer = [0u8; 8192];
    loop {
        match local.read(&mut buffer) {
            // EOF from the actor is the only reason to stop: it means the pane is
            // finished. A failed send is a disconnect, and the pane outlives that.
            Ok(0) | Err(_) => break,
            Ok(n) => {
                if shared
                    .wire
                    .send(&ToHost::Data {
                        channel,
                        bytes: buffer[..n].to_vec(),
                    })
                    .is_err()
                {
                    break;
                }
            }
        }
    }
    shared
        .channels
        .lock()
        .ok()
        .map(|mut map| map.remove(&channel));
}

fn poisoned() -> std::io::Error {
    std::io::Error::other("pty-host link state poisoned")
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{Duration, Instant};

    const PATIENCE: Duration = Duration::from_secs(10);

    /// A dialer that hands out socket pairs, and a receiver giving the test the
    /// host side of each one.
    ///
    /// This is the whole reason [`Dialer`] is a closure: a redial over sockets is
    /// indistinguishable to the link from a redial over ssh, so every reconnect
    /// path can be driven deterministically with no network and no subprocess.
    fn socket_dialer() -> (Dialer, mpsc::Receiver<UnixStream>) {
        let (tx, rx) = mpsc::channel();
        let dialer: Dialer = Arc::new(move || {
            let (host, client) = UnixStream::pair()?;
            let reader = client.try_clone()?;
            tx.send(host)
                .map_err(|_| std::io::Error::other("the test dropped the host side"))?;
            Ok(Transport {
                reader: Box::new(reader),
                writer: Box::new(client),
                child: None,
            })
        });
        (dialer, rx)
    }

    /// Take the next connection the link dialled, with a read deadline so a broken
    /// expectation fails the test instead of hanging it.
    fn next_connection(hosts: &mpsc::Receiver<UnixStream>) -> UnixStream {
        let host = hosts
            .recv_timeout(PATIENCE)
            .expect("the link should have dialled");
        host.set_read_timeout(Some(PATIENCE)).expect("read timeout");
        host
    }

    fn host_recv(host: &mut UnixStream) -> ToHost {
        read_frame::<_, ToHost>(host).expect("a frame from the link")
    }

    fn host_send(host: &mut UnixStream, message: &FromHost) {
        write_frame(host, message).expect("write to the link");
        host.flush().expect("flush");
    }

    /// Answer a `Hello` with a `Welcome` carrying `epoch`.
    fn greet(host: &mut UnixStream, epoch: u64) {
        match host_recv(host) {
            ToHost::Hello { version } => assert_eq!(version, HOST_PROTOCOL_VERSION),
            other => panic!("expected Hello, got {other:?}"),
        }
        host_send(
            host,
            &FromHost::Welcome {
                version: HOST_PROTOCOL_VERSION,
                host_epoch: epoch,
            },
        );
    }

    /// Connect a link whose first handshake this thread answers.
    fn connect_link(epoch: u64) -> (HostLink, mpsc::Receiver<UnixStream>, UnixStream) {
        let (dialer, hosts) = socket_dialer();
        let connecting = std::thread::spawn(move || HostLink::connect_with_dialer(dialer, true));
        let mut host = next_connection(&hosts);
        greet(&mut host, epoch);
        let link = connecting
            .join()
            .expect("connect thread")
            .expect("handshake");
        (link, hosts, host)
    }

    /// Open a channel and answer its `Spawn`, returning the actor's fd as a stream.
    fn open_pane(link: &HostLink, host: &mut UnixStream) -> (ChannelId, UnixStream) {
        let (channel, fd) = link
            .open_channel(SpawnSpec {
                argv: vec!["cat".into()],
                cwd: None,
                env: Vec::new(),
                rows: 24,
                cols: 80,
            })
            .expect("open channel");
        match host_recv(host) {
            ToHost::Spawn { channel: got, .. } => assert_eq!(got, channel),
            other => panic!("expected Spawn, got {other:?}"),
        }
        host_send(host, &FromHost::Spawned { channel, pid: 4242 });
        (channel, UnixStream::from(fd))
    }

    /// Read from the actor's (non-blocking) end until `needle` appears.
    fn read_until(stream: &mut UnixStream, needle: &str) -> String {
        let deadline = Instant::now() + PATIENCE;
        let mut seen = String::new();
        let mut buffer = [0u8; 4096];
        while Instant::now() < deadline {
            match stream.read(&mut buffer) {
                Ok(0) => break,
                Ok(n) => {
                    seen.push_str(&String::from_utf8_lossy(&buffer[..n]));
                    if seen.contains(needle) {
                        return seen;
                    }
                }
                Err(ref err) if err.kind() == std::io::ErrorKind::WouldBlock => {
                    std::thread::sleep(Duration::from_millis(10));
                }
                Err(_) => break,
            }
        }
        panic!("never saw {needle:?}; saw {seen:?}");
    }

    /// Everything readable from the actor's end within a short settling period.
    fn drain(stream: &mut UnixStream, settle: Duration) -> Vec<u8> {
        let deadline = Instant::now() + settle;
        let mut seen = Vec::new();
        let mut buffer = [0u8; 4096];
        while Instant::now() < deadline {
            match stream.read(&mut buffer) {
                Ok(0) => break,
                Ok(n) => seen.extend_from_slice(&buffer[..n]),
                Err(ref err) if err.kind() == std::io::ErrorKind::WouldBlock => {
                    std::thread::sleep(Duration::from_millis(10));
                }
                Err(_) => break,
            }
        }
        seen
    }

    #[test]
    fn a_dead_transport_does_not_close_panes_and_the_link_resumes_them() {
        // The headline behaviour: a dropped connection must not end the work. The
        // pane stays open, the link redials on its own, and the bytes produced
        // while it was down arrive with no gap and no duplication.
        let (link, hosts, mut host) = connect_link(7);
        let (channel, mut actor) = open_pane(&link, &mut host);

        host_send(
            &mut host,
            &FromHost::Data {
                channel,
                from: 0,
                bytes: b"before-".to_vec(),
            },
        );
        assert_eq!(read_until(&mut actor, "before-"), "before-");

        // The link dies with no warning, exactly as a closed lid looks from here.
        drop(host);

        let mut second = next_connection(&hosts);
        greet(&mut second, 7);

        // The epoch quoted must be the one from BEFORE this handshake. Sending the
        // new value would compare the daemon's epoch against itself, so a restarted
        // daemon would look like the same one and every pane would appear to resume
        // into a process that no longer exists.
        match host_recv(&mut second) {
            ToHost::Attach { host_epoch, panes } => {
                assert_eq!(host_epoch, 7, "must quote the epoch it had before");
                assert_eq!(
                    panes,
                    vec![(channel, 7)],
                    "offset is what reached the actor"
                );
            }
            other => panic!("expected Attach, got {other:?}"),
        }

        host_send(
            &mut second,
            &FromHost::Replay {
                channel,
                from: 7,
                bytes: b"after".to_vec(),
            },
        );
        assert_eq!(read_until(&mut actor, "after"), "after");

        // Invisible to the user is the goal, so nothing may have been marked.
        assert!(!link.channel_truncated(channel));
        assert_eq!(
            link.drain_resume_events(),
            vec![(channel, PaneResume::Resumed)]
        );
        assert_eq!(link.status(), LinkStatus::Connected);
    }

    #[test]
    fn an_overlapping_replay_is_not_written_to_the_parser_twice() {
        // Answering an Attach is not atomic with respect to output still being
        // produced, so a Replay legitimately overlaps bytes already delivered.
        // Writing them again would duplicate whatever the agent last drew.
        let (link, hosts, mut host) = connect_link(1);
        let (channel, mut actor) = open_pane(&link, &mut host);

        host_send(
            &mut host,
            &FromHost::Data {
                channel,
                from: 0,
                bytes: b"abcdef".to_vec(),
            },
        );
        assert_eq!(read_until(&mut actor, "abcdef"), "abcdef");
        drop(host);

        let mut second = next_connection(&hosts);
        greet(&mut second, 1);
        let _ = host_recv(&mut second); // Attach

        // Deliberately starts before where we had reached.
        host_send(
            &mut second,
            &FromHost::Replay {
                channel,
                from: 0,
                bytes: b"abcdefghi".to_vec(),
            },
        );

        let tail = String::from_utf8(drain(&mut actor, Duration::from_millis(400))).unwrap();
        assert_eq!(tail, "ghi", "only the unseen suffix may reach the parser");
        assert!(!link.channel_truncated(channel));
    }

    #[test]
    fn a_replay_wholly_behind_the_cursor_delivers_nothing() {
        let (link, hosts, mut host) = connect_link(1);
        let (channel, mut actor) = open_pane(&link, &mut host);
        host_send(
            &mut host,
            &FromHost::Data {
                channel,
                from: 0,
                bytes: b"0123456789".to_vec(),
            },
        );
        assert_eq!(read_until(&mut actor, "0123456789"), "0123456789");
        drop(host);

        let mut second = next_connection(&hosts);
        greet(&mut second, 1);
        let _ = host_recv(&mut second);
        host_send(
            &mut second,
            &FromHost::Replay {
                channel,
                from: 2,
                bytes: b"2345".to_vec(),
            },
        );

        assert!(
            drain(&mut actor, Duration::from_millis(400)).is_empty(),
            "bytes already given to the parser must not be sent again"
        );
    }

    #[test]
    fn a_desync_resets_the_parser_and_says_so_before_continuing() {
        // The invariant that matters most: a hole must never reach the parser
        // unannounced. A half-parsed escape sequence is permanent grid corruption,
        // and silent holes in scrollback read as output the agent never produced.
        let (link, hosts, mut host) = connect_link(5);
        let (channel, mut actor) = open_pane(&link, &mut host);
        host_send(
            &mut host,
            &FromHost::Data {
                channel,
                from: 0,
                bytes: b"start".to_vec(),
            },
        );
        assert_eq!(read_until(&mut actor, "start"), "start");
        drop(host);

        let mut second = next_connection(&hosts);
        greet(&mut second, 5);
        let _ = host_recv(&mut second);

        // The host ran far ahead of us and can no longer close the gap.
        host_send(
            &mut second,
            &FromHost::Desync {
                channel,
                available_from: 900_000,
                out_offset: 1_000_005,
            },
        );

        let notice = drain(&mut actor, Duration::from_millis(400));
        assert!(
            notice.starts_with(RESYNC),
            "the parser must be reset before anything else: {notice:?}"
        );
        let text = String::from_utf8_lossy(&notice);
        assert!(text.contains("1000000"), "must name the loss: {text}");
        assert!(link.channel_truncated(channel));
        assert_eq!(
            link.drain_resume_events(),
            vec![(channel, PaneResume::Truncated)]
        );

        // And the offset must have jumped to the live position, or every frame
        // that follows would look like a fresh gap and mark the pane again.
        host_send(
            &mut second,
            &FromHost::Data {
                channel,
                from: 1_000_005,
                bytes: b"onwards".to_vec(),
            },
        );
        let tail = String::from_utf8(drain(&mut actor, Duration::from_millis(400))).unwrap();
        assert_eq!(tail, "onwards", "no second marker: {tail:?}");
    }

    #[test]
    fn a_gap_in_live_output_is_marked_rather_than_fed_to_the_parser() {
        // Should be impossible over a stream transport, which is exactly why it is
        // handled: if it ever happens it is a bug, and the failure mode without
        // this is silent corruption rather than any report at all.
        let (link, _hosts, mut host) = connect_link(1);
        let (channel, mut actor) = open_pane(&link, &mut host);
        host_send(
            &mut host,
            &FromHost::Data {
                channel,
                from: 0,
                bytes: b"aaa".to_vec(),
            },
        );
        assert_eq!(read_until(&mut actor, "aaa"), "aaa");

        host_send(
            &mut host,
            &FromHost::Data {
                channel,
                from: 100,
                bytes: b"bbb".to_vec(),
            },
        );
        let seen = drain(&mut actor, Duration::from_millis(400));
        assert!(seen.starts_with(RESYNC), "{seen:?}");
        let text = String::from_utf8_lossy(&seen);
        assert!(text.contains("97"), "must name the 97-byte gap: {text}");
        assert!(text.ends_with("bbb"), "{text}");
        assert!(link.channel_truncated(channel));
    }

    #[test]
    fn a_restarted_host_reports_the_pane_gone_rather_than_finished() {
        // An agent that vanished with its host must never read as one that
        // finished. The pane closes either way, so the difference is only ever
        // visible if it is said out loud.
        let (link, hosts, mut host) = connect_link(11);
        let (channel, mut actor) = open_pane(&link, &mut host);
        drop(host);

        let mut second = next_connection(&hosts);
        // A different epoch: this is a new daemon that never had our panes.
        greet(&mut second, 12);
        match host_recv(&mut second) {
            ToHost::Attach { host_epoch, .. } => assert_eq!(host_epoch, 11),
            other => panic!("expected Attach, got {other:?}"),
        }
        host_send(
            &mut second,
            &FromHost::Gone {
                channel,
                reason: GoneReason::HostRestarted,
            },
        );

        let text =
            String::from_utf8_lossy(&drain(&mut actor, Duration::from_millis(400))).to_string();
        assert!(text.contains("host restarted"), "{text}");
        assert_eq!(
            link.drain_resume_events(),
            vec![(channel, PaneResume::HostRestarted)]
        );
    }

    #[test]
    fn input_typed_while_disconnected_is_discarded_not_replayed() {
        // Replaying output is cosmetic; replaying keystrokes into a coding agent
        // minutes later is destructive. This is the one thing that must never be
        // buffered across a reconnect.
        let (link, hosts, mut host) = connect_link(3);
        let (channel, mut actor) = open_pane(&link, &mut host);
        drop(host);

        // Typed into a pane whose link is down.
        actor
            .write_all(
                b"rm -rf /
",
            )
            .expect("write");
        std::thread::sleep(Duration::from_millis(100));

        let mut second = next_connection(&hosts);
        greet(&mut second, 3);

        // Everything the link says on the new connection, for a moment.
        second
            .set_read_timeout(Some(Duration::from_millis(400)))
            .unwrap();
        let mut frames = Vec::new();
        while let Ok(frame) = read_frame::<_, ToHost>(&mut second) {
            frames.push(frame);
        }
        assert!(
            frames
                .iter()
                .any(|frame| matches!(frame, ToHost::Attach { .. })),
            "should have re-attached: {frames:?}"
        );
        assert!(
            !frames
                .iter()
                .any(|frame| matches!(frame, ToHost::Data { .. })),
            "input from while the link was down must not be delivered: {frames:?}"
        );
        // And the pane is still alive: typing now must reach the host, or
        // "discarded" would have quietly meant "the pane stopped working".
        actor.write_all(b"echo ok\n").expect("write");
        second.set_read_timeout(Some(PATIENCE)).unwrap();
        let delivered = loop {
            match read_frame::<_, ToHost>(&mut second).expect("a frame") {
                ToHost::Data {
                    channel: got,
                    bytes,
                } => {
                    assert_eq!(got, channel);
                    break bytes;
                }
                _ => continue,
            }
        };
        assert_eq!(delivered, b"echo ok\n");
    }

    #[test]
    fn the_window_size_is_pushed_again_after_a_reconnect() {
        // A resize that happened while the link was down leaves the host's winsize
        // stale, and a full-screen agent then redraws at the wrong size with
        // nothing to indicate why.
        let (link, hosts, mut host) = connect_link(2);
        let (channel, _actor) = open_pane(&link, &mut host);
        link.resize(channel, 50, 200, 8, 16).expect("resize");
        match host_recv(&mut host) {
            ToHost::Resize { rows, cols, .. } => {
                assert_eq!((rows, cols), (50, 200));
            }
            other => panic!("expected Resize, got {other:?}"),
        }
        drop(host);

        let mut second = next_connection(&hosts);
        greet(&mut second, 2);
        second
            .set_read_timeout(Some(Duration::from_millis(600)))
            .unwrap();
        let mut frames = Vec::new();
        while let Ok(frame) = read_frame::<_, ToHost>(&mut second) {
            frames.push(frame);
        }
        assert!(
            frames.iter().any(|frame| matches!(
                frame,
                ToHost::Resize {
                    rows: 50,
                    cols: 200,
                    ..
                }
            )),
            "the size must be pushed again: {frames:?}"
        );
    }

    #[test]
    fn a_shutdown_issued_while_disconnected_reaches_the_host_later() {
        // Dropping it would leave the process running on the host with nothing
        // left that refers to it — a leak the user cannot even see.
        let (link, hosts, mut host) = connect_link(4);
        let (channel, _actor) = open_pane(&link, &mut host);
        drop(host);

        link.shutdown_channel(channel).expect("shutdown");

        let mut second = next_connection(&hosts);
        greet(&mut second, 4);
        second
            .set_read_timeout(Some(Duration::from_millis(600)))
            .unwrap();
        let mut frames = Vec::new();
        while let Ok(frame) = read_frame::<_, ToHost>(&mut second) {
            frames.push(frame);
        }
        assert!(
            frames
                .iter()
                .any(|frame| matches!(frame, ToHost::Shutdown { channel: got } if *got == channel)),
            "the queued shutdown must be re-sent: {frames:?}"
        );
    }

    #[test]
    fn a_link_that_cannot_be_redialled_closes_its_panes() {
        // The single-shot behaviour a caller who hands over a raw stream gets:
        // there is nothing to redial, so a pane must see EOF rather than wait
        // forever on a socket that will never produce another byte.
        let (host, client) = UnixStream::pair().expect("pair");
        let mut host = host;
        host.set_read_timeout(Some(PATIENCE)).unwrap();
        let reader = client.try_clone().expect("clone");
        let connecting = std::thread::spawn(move || HostLink::connect(reader, Box::new(client)));
        greet(&mut host, 1);
        let link = connecting.join().unwrap().expect("handshake");

        let (channel, mut actor) = open_pane(&link, &mut host);
        drop(host);

        let deadline = Instant::now() + PATIENCE;
        let mut buffer = [0u8; 64];
        loop {
            assert!(Instant::now() < deadline, "pane never saw EOF");
            match actor.read(&mut buffer) {
                Ok(0) => break,
                Ok(_) => {}
                Err(ref err) if err.kind() == std::io::ErrorKind::WouldBlock => {
                    std::thread::sleep(Duration::from_millis(10))
                }
                Err(_) => break,
            }
        }
        assert_eq!(link.status(), LinkStatus::Closed);
        let _ = channel;
    }

    #[test]
    fn opening_a_pane_while_reconnecting_fails_instead_of_creating_a_ghost() {
        // A Spawn dropped on the floor comes back from the next Attach as `Gone`,
        // so the user would watch a pane appear and then die for no visible reason.
        let (link, _hosts, host) = connect_link(1);
        drop(host);
        // The wire is torn down as soon as the write fails, so a spawn attempted
        // during the gap must be refused rather than silently lost.
        link.shared.wire.clear();
        let result = link.open_channel(SpawnSpec {
            argv: vec!["cat".into()],
            cwd: None,
            env: Vec::new(),
            rows: 24,
            cols: 80,
        });
        assert!(result.is_err(), "should refuse while disconnected");
    }

    #[test]
    fn reconcile_covers_every_relation_a_frame_can_have_to_the_cursor() {
        // Direct rather than only through the schedule: the daemon now orders a
        // channel's frames strictly, so a *partial* overlap — a frame that starts
        // behind the cursor and ends ahead of it — cannot be produced by a correct
        // host at all. That makes it exactly the branch a property test cannot
        // reach and the one most likely to rot, so it is pinned here.
        assert_eq!(reconcile(0, 0, 0), Reconciled::AlreadySeen);
        assert_eq!(reconcile(10, 0, 10), Reconciled::AlreadySeen);
        assert_eq!(reconcile(10, 4, 3), Reconciled::AlreadySeen);
        assert_eq!(
            reconcile(0, 0, 5),
            Reconciled::Write { skip: 0, next: 5 },
            "a frame exactly at the cursor is written whole"
        );
        assert_eq!(
            reconcile(10, 10, 5),
            Reconciled::Write { skip: 0, next: 15 }
        );
        assert_eq!(
            reconcile(10, 4, 12),
            Reconciled::Write { skip: 6, next: 16 },
            "a partial overlap keeps only the unseen suffix"
        );
        assert_eq!(
            reconcile(10, 12, 4),
            Reconciled::Gap {
                missing: 2,
                next: 16
            },
            "a frame ahead of the cursor leaves a hole that must be reported"
        );
    }

    #[test]
    fn a_snapshot_restores_the_screen_and_says_the_scrollback_went() {
        // The overnight case. Replay is bounded by the host's log, so any long
        // absence lands here — and a pane that comes back blank is the difference
        // between this feature being useful and merely being safe.
        let (link, hosts, mut host) = connect_link(9);
        let (channel, mut actor) = open_pane(&link, &mut host);
        host_send(
            &mut host,
            &FromHost::Data {
                channel,
                from: 0,
                bytes: b"early".to_vec(),
            },
        );
        assert_eq!(read_until(&mut actor, "early"), "early");
        drop(host);

        let mut second = next_connection(&hosts);
        greet(&mut second, 9);
        let _ = host_recv(&mut second); // Attach
        host_send(
            &mut second,
            &FromHost::Snapshot {
                channel,
                out_offset: 500_005,
                ansi: "\x1b[2J\x1b[Hrestored-screen".to_string(),
            },
        );

        let seen = drain(&mut actor, Duration::from_millis(400));
        assert!(
            seen.starts_with(RESYNC),
            "the parser must be reset before the snapshot, or whatever the gap left \
             half-parsed swallows the front of it: {seen:?}"
        );
        let text = String::from_utf8_lossy(&seen);
        assert!(text.contains("restored-screen"), "{text}");
        // The screen is back but the history behind it is not, and saying so is the
        // difference between honest and merely reassuring.
        assert!(text.contains("scrollback"), "{text}");
        assert!(text.contains("500000"), "must name the loss: {text}");
        assert!(link.channel_truncated(channel));
        assert_eq!(
            link.drain_resume_events(),
            vec![(channel, PaneResume::Truncated)]
        );

        // And the cursor moved to the snapshot's position, so live output lines up.
        host_send(
            &mut second,
            &FromHost::Data {
                channel,
                from: 500_005,
                bytes: b"live".to_vec(),
            },
        );
        let tail = String::from_utf8(drain(&mut actor, Duration::from_millis(400))).unwrap();
        assert_eq!(tail, "live", "no second marker: {tail:?}");
    }

    #[test]
    fn a_snapshot_behind_the_cursor_is_ignored_rather_than_obeyed() {
        // Same race as a stale desync: live output can carry the parser past the point
        // the snapshot describes while it is in flight. Painting it then would replace
        // the current screen with an older one — visibly wrong, and it would look like
        // the agent had undone its own work.
        let (link, _hosts, mut host) = connect_link(1);
        let (channel, mut actor) = open_pane(&link, &mut host);
        host_send(
            &mut host,
            &FromHost::Data {
                channel,
                from: 0,
                bytes: b"0123456789".to_vec(),
            },
        );
        assert_eq!(read_until(&mut actor, "0123456789"), "0123456789");

        host_send(
            &mut host,
            &FromHost::Snapshot {
                channel,
                out_offset: 4,
                ansi: "\x1b[2J\x1b[Hstale".to_string(),
            },
        );
        assert!(
            drain(&mut actor, Duration::from_millis(300)).is_empty(),
            "a stale snapshot must not repaint the pane"
        );
        assert!(!link.channel_truncated(channel), "nothing was lost");
    }

    #[test]
    fn a_desync_behind_the_cursor_is_ignored_rather_than_obeyed() {
        // The host reports where the stream stood when it answered; live output can
        // carry the parser past that point while the answer is in flight. Obeying it
        // would wind the cursor BACK and re-deliver bytes the parser already has,
        // and it would print a truncation marker for nothing.
        let (link, _hosts, mut host) = connect_link(1);
        let (channel, mut actor) = open_pane(&link, &mut host);
        host_send(
            &mut host,
            &FromHost::Data {
                channel,
                from: 0,
                bytes: b"0123456789".to_vec(),
            },
        );
        assert_eq!(read_until(&mut actor, "0123456789"), "0123456789");

        host_send(
            &mut host,
            &FromHost::Desync {
                channel,
                available_from: 0,
                out_offset: 4,
            },
        );
        assert!(
            drain(&mut actor, Duration::from_millis(300)).is_empty(),
            "a stale desync must produce neither a marker nor a re-delivery"
        );
        assert!(!link.channel_truncated(channel), "nothing was lost");

        // And the cursor really did stay put: the next live frame lines up.
        host_send(
            &mut host,
            &FromHost::Data {
                channel,
                from: 10,
                bytes: b"onwards".to_vec(),
            },
        );
        let tail = String::from_utf8(drain(&mut actor, Duration::from_millis(300))).unwrap();
        assert_eq!(tail, "onwards", "cursor moved: {tail:?}");
    }

    #[test]
    fn a_control_path_is_short_enough_for_a_unix_socket_and_stable_per_target() {
        // Over the sun_path limit ssh fails outright rather than degrading, so a path
        // that is too long would turn a working host into a broken one. And it has to
        // be the same path every time for the same target, or a redial would build a
        // second master instead of reusing the one that is already up — which is the
        // entire point of having it.
        use std::os::unix::ffi::OsStrExt;

        let first = control_path("some-host.example.internal");
        let again = control_path("some-host.example.internal");
        assert_eq!(first, again, "must be stable for one target");
        if let Some(path) = first.as_deref() {
            assert!(path.as_os_str().as_bytes().len() <= 103, "{path:?}");
        }

        // Long names must not silently produce an unusable path.
        let long = "a".repeat(400);
        if let Some(path) = control_path(&long) {
            assert!(path.as_os_str().as_bytes().len() <= 103, "{path:?}");
        }
    }

    #[test]
    fn different_targets_do_not_share_a_control_socket() {
        // Sharing one would multiplex two machines onto one connection, so a session
        // could be opened on the wrong host entirely.
        let a = control_path("host-a");
        let b = control_path("host-b");
        assert_ne!(a, b);
        assert!(a.is_some() && b.is_some());
    }

    #[test]
    fn redial_delay_grows_and_then_stops_growing() {
        // Uncapped growth would mean a link that has been down a while takes
        // hours to notice the network came back.
        let max = redial_max_delay();
        let first = redial_delay(0);
        let later = redial_delay(4);
        assert!(first < later, "{first:?} should be shorter than {later:?}");
        for attempt in 0..40 {
            assert!(
                redial_delay(attempt) <= max,
                "attempt {attempt} exceeded the cap"
            );
        }
    }

    #[test]
    fn redial_delay_never_reaches_zero() {
        // A zero delay is a spin loop against an unreachable host.
        for attempt in 0..40 {
            assert!(redial_delay(attempt) > std::time::Duration::ZERO);
        }
    }

    #[test]
    fn the_resync_prologue_closes_a_string_before_resetting() {
        // If the lost bytes opened an OSC/DCS/APC string the parser is inside one
        // and would swallow the reset itself, leaving the terminal broken with no
        // way back. ST must therefore come first.
        assert_eq!(&RESYNC[..2], b"\x1b\\");
        assert_eq!(&RESYNC[2..], b"\x1bc");
    }

    #[test]
    fn the_truncation_marker_names_the_amount_lost() {
        let marker = String::from_utf8(truncation_marker(4096)).unwrap();
        assert!(marker.contains("4096"), "{marker}");
        assert!(marker.contains("herdr"), "{marker}");
        // Must start on a fresh line: dropping it mid-line would corrupt whatever
        // the agent had half-drawn.
        assert!(marker.starts_with("\r\n"), "{marker:?}");
    }
}
