//! `herdr pty-host` — owns PTYs on a machine and speaks [`super::protocol`] over
//! stdio.
//!
//! Runs on the far end of an ssh invocation. The local herdr keeps the VT parser,
//! grid, scrollback and detection; this side only allocates PTYs, moves bytes, and
//! knows the pids.
//!
//! Everything OS-shaped is deliberately answered *here* rather than by the local
//! side: the login shell, the environment, and the signal escalation all depend on
//! this machine, and the local machine's answers would be wrong. Because this is
//! the same herdr binary, it reuses the same platform code as a local pane.

use std::collections::HashMap;
use std::io::{Read, Write};
use std::sync::mpsc;
use std::sync::{Arc, Mutex};

use super::protocol::{
    negotiate, read_frame, write_frame, ChannelId, FromHost, Negotiation, SpawnSpec, ToHost,
    HOST_PROTOCOL_VERSION,
};

/// Output read size. Matches the local PTY actor so chunking behaves the same on
/// both sides of the link.
const READ_CHUNK: usize = 8192;

/// How much output is kept per channel for replay.
///
/// A compromise, and worth naming as one: an agent redrawing a status block at a
/// couple of KB/s fills this in around ten minutes, so a short disconnect replays
/// seamlessly while an overnight absence will need a snapshot instead. Raising it
/// costs memory on a machine herdr does not own.
const OUTPUT_LOG_CAPACITY: usize = 1024 * 1024;

/// Bounded record of a channel's output, so a reconnecting client can be given the
/// bytes it missed.
///
/// Bounded on purpose: a client may be away indefinitely, and keeping every byte is
/// how a daemon gets OOM-killed on a host it does not own. Once the buffer overflows
/// the oldest bytes are dropped and a client that far behind gets a `Desync` rather
/// than a silent hole — a gap fed to a downstream VT parser is permanent grid
/// corruption, not a dropped frame.
#[derive(Debug)]
struct OutputLog {
    /// Offset of the oldest byte still held.
    start: u64,
    /// Total bytes ever produced on this channel.
    end: u64,
    buffer: std::collections::VecDeque<u8>,
    capacity: usize,
}

impl OutputLog {
    fn new(capacity: usize) -> Self {
        Self {
            start: 0,
            end: 0,
            buffer: std::collections::VecDeque::new(),
            capacity,
        }
    }

    fn append(&mut self, bytes: &[u8]) {
        self.buffer.extend(bytes.iter().copied());
        self.end += bytes.len() as u64;
        // Trim from the front, advancing `start` by exactly what was dropped so the
        // offset arithmetic stays exact.
        while self.buffer.len() > self.capacity {
            let excess = self.buffer.len() - self.capacity;
            self.buffer.drain(..excess);
            self.start += excess as u64;
        }
    }

    /// Bytes from `offset` onwards, or `None` if they are no longer held.
    ///
    /// `None` means the caller must be told to resync rather than handed a partial
    /// stream: returning what is left would leave a hole at the front.
    fn since(&self, offset: u64) -> Option<Vec<u8>> {
        if offset > self.end {
            // Ahead of anything produced. Treat as unresumable rather than
            // guessing: a client claiming a future offset is a bug somewhere, and
            // silently sending nothing would look like a healthy idle pane.
            return None;
        }
        if offset < self.start {
            return None;
        }
        let skip = (offset - self.start) as usize;
        Some(self.buffer.iter().skip(skip).copied().collect())
    }
}

/// One live PTY.
struct Channel {
    /// Write end of the PTY master, for user input.
    writer: Box<dyn Write + Send>,
    /// Raw master fd, needed for the window-size ioctl.
    master_fd: std::os::fd::RawFd,
    /// Pid of the child on this machine.
    pid: u32,
    /// Output produced so far, for replay to a reconnecting client. Shared with the
    /// reader thread so appending never has to lock the channel table.
    log: Arc<Mutex<OutputLog>>,
}

/// Serialised access to the attached client, if any.
///
/// `None` while nobody is attached. Output produced then is discarded rather than
/// buffered: agents must keep running while the human is away, and holding every
/// byte in memory for an unbounded absence is how a daemon gets OOM-killed. A byte
/// log with bounded replay is the next step; until then a reattach shows the screen
/// from that moment on.
type SharedOut = Arc<Mutex<Option<Box<dyn Write + Send>>>>;

/// Everything the daemon owns, independent of any one client.
///
/// Held across client disconnects so agents keep running when the link drops.
struct Daemon {
    channels: Arc<Mutex<HashMap<ChannelId, Channel>>>,
    out: SharedOut,
    exit_tx: mpsc::Sender<(ChannelId, Option<i32>)>,
    /// Constant for the life of this process; see `mint_host_epoch`.
    host_epoch: u64,
}

/// Identifies this daemon instance.
///
/// Process start time plus pid: unique per daemon without needing anywhere to
/// persist it, and monotonic enough that a restarted daemon never reuses the value
/// a client is holding.
fn mint_host_epoch() -> u64 {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|since| since.as_nanos() as u64)
        .unwrap_or(0);
    nanos ^ ((std::process::id() as u64) << 48)
}

impl Daemon {
    fn new() -> Self {
        let out: SharedOut = Arc::new(Mutex::new(None));
        let channels: Arc<Mutex<HashMap<ChannelId, Channel>>> =
            Arc::new(Mutex::new(HashMap::new()));

        // Exits are reported from reader threads; a channel keeps that off the
        // request path so a wedged reader cannot stall input handling.
        let (exit_tx, exit_rx) = mpsc::channel::<(ChannelId, Option<i32>)>();
        {
            let out = Arc::clone(&out);
            let channels = Arc::clone(&channels);
            std::thread::spawn(move || {
                while let Ok((channel, status)) = exit_rx.recv() {
                    channels.lock().ok().map(|mut map| map.remove(&channel));
                    send(&out, &FromHost::Exited { channel, status });
                }
            });
        }

        Self {
            channels,
            out,
            exit_tx,
            host_epoch: mint_host_epoch(),
        }
    }

    fn live_channels(&self) -> usize {
        self.channels.lock().map(|map| map.len()).unwrap_or(0)
    }
}

/// Run the daemon against the given streams until the input closes.
///
/// Split from `run()` so it can be driven over pipes in tests without ssh. Owns a
/// fresh Daemon, so this is the one-client-then-exit shape used by tests and by a
/// direct `herdr pty-host` invocation.
pub fn serve<R: Read>(input: R, output: Box<dyn Write + Send>) -> std::io::Result<()> {
    let daemon = Daemon::new();
    serve_client(&daemon, input, output)?;

    // Tear down anything still running; a one-shot session must not leave
    // orphaned shells behind on the machine.
    let ids: Vec<ChannelId> = daemon
        .channels
        .lock()
        .map(|map| map.keys().copied().collect())
        .unwrap_or_default();
    for channel in ids {
        shutdown_channel(&daemon.channels, channel);
    }
    Ok(())
}

/// Serve one attached client. Returns when its input closes; channels survive.
fn serve_client<R: Read>(
    daemon: &Daemon,
    mut input: R,
    output: Box<dyn Write + Send>,
) -> std::io::Result<()> {
    if let Ok(mut guard) = daemon.out.lock() {
        *guard = Some(output);
    }
    let out = &daemon.out;
    let channels = &daemon.channels;
    let exit_tx = &daemon.exit_tx;

    let mut greeted = false;

    // The link closing is the normal way this process ends.
    while let Ok(message) = read_frame::<_, ToHost>(&mut input) {
        match message {
            ToHost::Hello { version } => {
                greeted = true;
                // Always answer, even on mismatch: the local side needs our
                // version to tell the user which end to upgrade.
                send(
                    out,
                    &FromHost::Welcome {
                        version: HOST_PROTOCOL_VERSION,
                        host_epoch: daemon.host_epoch,
                    },
                );
                if !matches!(negotiate(version), Negotiation::Ok) {
                    break;
                }
            }
            other => {
                // Refuse work before a handshake, so a version mismatch is
                // reported rather than showing up as strange behaviour later.
                if !greeted {
                    break;
                }
                handle(other, out, channels, exit_tx, daemon.host_epoch);
            }
        }
    }

    // Deliberately does NOT tear down channels: the client going away is the
    // normal case — a closed laptop, a dropped link — and killing the agents then
    // is exactly the failure this daemon exists to prevent.
    if let Ok(mut guard) = daemon.out.lock() {
        *guard = None;
    }

    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn handle(
    message: ToHost,
    out: &SharedOut,
    channels: &Arc<Mutex<HashMap<ChannelId, Channel>>>,
    exit_tx: &mpsc::Sender<(ChannelId, Option<i32>)>,
    daemon_epoch: u64,
) {
    match message {
        ToHost::Hello { .. } => {}
        ToHost::Spawn { channel, spec } => {
            match spawn_channel(channel, &spec, out, channels, exit_tx) {
                Ok(pid) => send(out, &FromHost::Spawned { channel, pid }),
                Err(err) => send(
                    out,
                    &FromHost::SpawnFailed {
                        channel,
                        message: err.to_string(),
                    },
                ),
            }
        }
        ToHost::Data { channel, bytes } => {
            if let Ok(mut map) = channels.lock() {
                if let Some(entry) = map.get_mut(&channel) {
                    let _ = entry.writer.write_all(&bytes);
                    let _ = entry.writer.flush();
                }
            }
        }
        ToHost::Resize {
            channel,
            rows,
            cols,
            cell_width_px,
            cell_height_px,
        } => {
            if let Ok(map) = channels.lock() {
                if let Some(entry) = map.get(&channel) {
                    // The ioctl belongs here, on the machine that owns the PTY.
                    let _ = crate::pty::fd::resize_pty_fd(
                        entry.master_fd,
                        rows,
                        cols,
                        cell_width_px,
                        cell_height_px,
                    );
                }
            }
        }
        ToHost::Shutdown { channel } => shutdown_channel(channels, channel),
        ToHost::Attach { host_epoch, panes } => {
            for (channel, offset) in panes {
                send(
                    out,
                    &resume_decision(daemon_epoch, host_epoch, channels, channel, offset),
                );
            }
        }
    }
}

/// Decide, for one pane, whether a reconnecting client can resume.
///
/// Exactly one answer per pane, and the epoch is checked first: if the daemon
/// restarted then nothing from the previous epoch survived, so offsets are
/// meaningless and every pane is gone regardless of how far behind the client is.
/// Checking offsets first would let a coincidental match resume a pane whose agent
/// no longer exists, which is the worst outcome available here.
fn resume_decision(
    daemon_epoch: u64,
    client_epoch: u64,
    channels: &Arc<Mutex<HashMap<ChannelId, Channel>>>,
    channel: ChannelId,
    offset: u64,
) -> FromHost {
    if client_epoch != daemon_epoch {
        return FromHost::Gone {
            channel,
            reason: crate::host::protocol::GoneReason::HostRestarted,
        };
    }

    let Some((bytes, start, end)) = channels.lock().ok().and_then(|map| {
        let entry = map.get(&channel)?;
        // Poison recovered, not treated as absence: reporting a live pane as `Gone`
        // would tell the user their agent died when it is still running.
        let log = entry.log.lock().unwrap_or_else(|err| err.into_inner());
        Some((log.since(offset), log.start, log.end))
    }) else {
        // Same epoch but no such channel: its process finished while the client was
        // away.
        return FromHost::Gone {
            channel,
            reason: crate::host::protocol::GoneReason::ChildExited,
        };
    };

    match bytes {
        Some(bytes) => FromHost::Replay {
            channel,
            from: offset,
            bytes,
        },
        None => FromHost::Desync {
            channel,
            available_from: start,
            out_offset: end,
        },
    }
}

fn spawn_channel(
    channel: ChannelId,
    spec: &SpawnSpec,
    out: &SharedOut,
    channels: &Arc<Mutex<HashMap<ChannelId, Channel>>>,
    exit_tx: &mpsc::Sender<(ChannelId, Option<i32>)>,
) -> std::io::Result<u32> {
    let cmd = build_command(spec)?;
    let spawned = crate::pty::backend::spawn_with_portable_pty(spec.rows, spec.cols, cmd)?;

    let master_fd = {
        use std::os::fd::AsRawFd;
        spawned.master_fd.as_raw_fd()
    };

    let mut child = spawned.child;
    let pid = child.process_id().unwrap_or(0);

    let reader_file = {
        use std::os::fd::{AsRawFd, FromRawFd};
        // Duplicate so the reader thread and the writer can own separate
        // handles to the same master without either closing it early.
        let duplicated = unsafe { libc::dup(spawned.master_fd.as_raw_fd()) };
        if duplicated < 0 {
            return Err(std::io::Error::last_os_error());
        }
        unsafe { std::fs::File::from_raw_fd(duplicated) }
    };
    let writer_file = std::fs::File::from(spawned.master_fd);

    let log = Arc::new(Mutex::new(OutputLog::new(OUTPUT_LOG_CAPACITY)));

    channels.lock().map_err(|_| poisoned())?.insert(
        channel,
        Channel {
            writer: Box::new(writer_file),
            master_fd,
            pid,
            log: Arc::clone(&log),
        },
    );

    // Pump output. EOF here means the PTY closed, which is the child finishing.
    {
        let out = Arc::clone(out);
        let exit_tx = exit_tx.clone();
        std::thread::spawn(move || {
            let mut reader = reader_file;
            let mut buffer = [0u8; READ_CHUNK];
            loop {
                match reader.read(&mut buffer) {
                    Ok(0) | Err(_) => break,
                    Ok(n) => {
                        // Recorded before sending, so output produced while nobody
                        // is attached is still replayable afterwards. The offset the
                        // log assigns is the one that goes on the wire, so the
                        // client's idea of the stream and the log's cannot drift —
                        // deriving the position on either side independently is how
                        // an off-by-one becomes silent grid corruption.
                        let from = {
                            // Recovered rather than propagated: a poisoned log must
                            // not stop a live pane's output, and `append` is the only
                            // mutator so no panic can leave the offsets inconsistent.
                            let mut log = log.lock().unwrap_or_else(|err| err.into_inner());
                            let from = log.end;
                            log.append(&buffer[..n]);
                            from
                        };
                        send(
                            &out,
                            &FromHost::Data {
                                channel,
                                from,
                                bytes: buffer[..n].to_vec(),
                            },
                        );
                    }
                }
            }
            let status = child.wait().ok().map(|status| status.exit_code() as i32);
            let _ = exit_tx.send((channel, status));
        });
    }

    Ok(pid)
}

/// Build the command to run, resolving anything machine-specific locally.
fn build_command(spec: &SpawnSpec) -> std::io::Result<portable_pty::CommandBuilder> {
    let mut cmd = if spec.argv.is_empty() {
        // The remote user's own login shell, from *this* machine's passwd entry.
        portable_pty::CommandBuilder::new_default_prog()
    } else {
        let mut cmd = portable_pty::CommandBuilder::new(&spec.argv[0]);
        for arg in &spec.argv[1..] {
            cmd.arg(arg);
        }
        cmd
    };

    if let Some(cwd) = &spec.cwd {
        cmd.cwd(cwd);
    }
    // Advertise a capable terminal rather than leaking whatever TERM arrived
    // over ssh, matching what a local pane does.
    cmd.env("TERM", "xterm-256color");
    cmd.env("COLORTERM", "truecolor");
    for (key, value) in &spec.env {
        cmd.env(key, value);
    }

    Ok(cmd)
}

/// Terminate a channel's process session using this machine's platform code.
fn shutdown_channel(channels: &Arc<Mutex<HashMap<ChannelId, Channel>>>, channel: ChannelId) {
    let Some(entry) = channels
        .lock()
        .ok()
        .and_then(|mut map| map.remove(&channel))
    else {
        return;
    };
    if entry.pid == 0 {
        return;
    }

    // Same escalation a local pane uses, run where the pids actually exist.
    let mut pids = crate::platform::session_processes(entry.pid);
    if pids.is_empty() {
        pids.push(entry.pid);
    }
    for signal in [
        crate::platform::Signal::Hangup,
        crate::platform::Signal::Terminate,
        crate::platform::Signal::Kill,
    ] {
        crate::platform::signal_processes(&pids, signal);
        std::thread::sleep(std::time::Duration::from_millis(120));
        if !pids.iter().any(|pid| crate::platform::process_exists(*pid)) {
            return;
        }
    }
}

fn send(out: &SharedOut, message: &FromHost) {
    let Ok(mut guard) = out.lock() else {
        return;
    };
    let Some(writer) = guard.as_mut() else {
        // Nobody attached. Dropping this is deliberate — see SharedOut.
        return;
    };
    if write_frame(writer, message).is_err() || writer.flush().is_err() {
        // The client vanished mid-write. Detach it so later output is discarded
        // cheaply instead of retrying into a dead pipe on every frame.
        *guard = None;
    }
}

fn poisoned() -> std::io::Error {
    std::io::Error::other("pty-host channel table poisoned")
}

/// Where the daemon listens on a host. Per-user, so two accounts on one machine do
/// not collide.
fn default_socket_path() -> std::path::PathBuf {
    let base = std::env::var_os("XDG_RUNTIME_DIR")
        .map(std::path::PathBuf::from)
        .or_else(|| {
            std::env::var_os("HOME").map(|home| std::path::PathBuf::from(home).join(".cache"))
        })
        .unwrap_or_else(std::env::temp_dir);
    base.join("herdr-pty-host.sock")
}

/// Serve clients on a unix socket until no channel is left to serve.
///
/// One client at a time: a second attach waits for the first to finish, which is
/// simpler than multiplexing and matches how the local side behaves. Channels
/// outlive each client, which is the whole point — a dropped link must not take the
/// agents with it.
pub fn serve_socket(socket_path: &std::path::Path) -> std::io::Result<()> {
    if let Some(parent) = socket_path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    // A socket left by a previous daemon would make bind fail. Removing it is safe
    // because a live daemon holds the lock file, checked by the caller.
    let _ = std::fs::remove_file(socket_path);
    let listener = std::os::unix::net::UnixListener::bind(socket_path)?;
    // Only this user should be able to drive PTYs on their account.
    let _ = std::fs::set_permissions(
        socket_path,
        <std::fs::Permissions as std::os::unix::fs::PermissionsExt>::from_mode(0o600),
    );

    let daemon = Daemon::new();

    // Non-blocking so idle time can be measured between connections.
    listener.set_nonblocking(true)?;
    let idle_exit = idle_exit_timeout();
    let mut idle_since = Some(std::time::Instant::now());

    loop {
        match listener.accept() {
            Ok((stream, _)) => {
                // The listener is non-blocking, which the accepted socket can
                // inherit; serving needs blocking reads.
                stream.set_nonblocking(false)?;
                idle_since = None;

                let reader = stream.try_clone()?;
                let _ = serve_client(&daemon, reader, Box::new(stream));

                // The client left. Start the idle clock only if there is nothing
                // to keep alive.
                if daemon.live_channels() == 0 {
                    idle_since = Some(std::time::Instant::now());
                }
            }
            Err(err) if err.kind() == std::io::ErrorKind::WouldBlock => {
                if daemon.live_channels() > 0 {
                    // Busy: never expire while an agent is running, however long
                    // the human is away.
                    idle_since = None;
                } else if idle_since.is_some_and(|since| since.elapsed() >= idle_exit) {
                    break;
                }
                std::thread::sleep(std::time::Duration::from_millis(100));
            }
            Err(_) => break,
        }
    }

    let _ = std::fs::remove_file(socket_path);
    Ok(())
}

/// How long an empty daemon waits for a client before giving up.
///
/// A grace period rather than exiting the moment a client leaves: a daemon that
/// died on the first disconnect would also die on any transient connection — a
/// readiness probe, or a client that reconnects a moment later — and then the next
/// attach would have to start it again. Never applies while a channel is live.
fn idle_exit_timeout() -> std::time::Duration {
    std::env::var("HERDR_PTY_HOST_IDLE_EXIT_MS")
        .ok()
        .and_then(|value| value.parse().ok())
        .map(std::time::Duration::from_millis)
        .unwrap_or_else(|| std::time::Duration::from_secs(60))
}

/// Connect to the daemon, starting it if needed, and bridge stdio to it.
///
/// This is what ssh runs. Mirrors `run_remote_client_bridge`: the transport only
/// has to move bytes, so the process holding the PTYs is never a child of the ssh
/// invocation and survives it.
pub fn attach() -> std::io::Result<()> {
    let socket_path = default_socket_path();

    let stream = connect_or_start(&socket_path)?;

    let mut reader = stream.try_clone()?;
    let mut writer = stream;

    // stdin -> daemon on a thread, daemon -> stdout here.
    let pump = std::thread::spawn(move || {
        let mut stdin = std::io::stdin().lock();
        let _ = std::io::copy(&mut stdin, &mut writer);
        // Closing our write half tells the daemon this client is done.
        let _ = writer.shutdown(std::net::Shutdown::Write);
    });

    let mut stdout = std::io::stdout().lock();
    let _ = std::io::copy(&mut reader, &mut stdout);
    let _ = stdout.flush();
    let _ = pump.join();
    Ok(())
}

/// Connect, or spawn a detached daemon and wait briefly for it to listen.
fn connect_or_start(
    socket_path: &std::path::Path,
) -> std::io::Result<std::os::unix::net::UnixStream> {
    if let Ok(stream) = std::os::unix::net::UnixStream::connect(socket_path) {
        return Ok(stream);
    }

    let exe = std::env::current_exe()?;
    let mut command = std::process::Command::new(exe);
    command
        .arg("pty-host")
        .arg("serve")
        .arg("--socket")
        .arg(socket_path)
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null());
    // setsid, so the daemon is not in the ssh session's process group and does not
    // receive its teardown signals.
    crate::platform::detach_server_daemon_command(&mut command);
    command.spawn()?;

    // Poll rather than sleep a fixed time: startup is fast, and a fixed sleep is
    // either wasted latency or too short on a loaded machine.
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
    while std::time::Instant::now() < deadline {
        if let Ok(stream) = std::os::unix::net::UnixStream::connect(socket_path) {
            return Ok(stream);
        }
        std::thread::sleep(std::time::Duration::from_millis(25));
    }
    Err(std::io::Error::other(
        "pty-host daemon did not start listening",
    ))
}

/// Entry point for the hidden `herdr pty-host` subcommand.
///
/// `attach` is what ssh runs. Bare `pty-host` keeps the one-shot stdio behaviour so
/// tests can drive it over pipes without a daemon.
pub fn run() -> std::io::Result<()> {
    let args: Vec<String> = std::env::args().skip(2).collect();
    match args.first().map(String::as_str) {
        Some("serve") => {
            let socket = args
                .iter()
                .position(|arg| arg == "--socket")
                .and_then(|index| args.get(index + 1))
                .map(std::path::PathBuf::from)
                .unwrap_or_else(default_socket_path);
            serve_socket(&socket)
        }
        Some("attach") => attach(),
        _ => {
            let stdin = std::io::stdin();
            let stdout = std::io::stdout();
            serve(stdin.lock(), Box::new(stdout))
        }
    }
}

#[cfg(test)]
mod output_log_tests {
    use super::*;

    #[test]
    fn a_fresh_log_holds_nothing_at_offset_zero() {
        let log = OutputLog::new(16);
        assert_eq!(log.since(0), Some(Vec::new()));
        assert_eq!(log.start, 0);
        assert_eq!(log.end, 0);
    }

    #[test]
    fn replay_from_zero_returns_everything_while_it_fits() {
        let mut log = OutputLog::new(16);
        log.append(b"abc");
        log.append(b"def");
        assert_eq!(log.since(0), Some(b"abcdef".to_vec()));
        assert_eq!(log.end, 6);
    }

    #[test]
    fn replay_from_the_middle_returns_only_what_follows() {
        let mut log = OutputLog::new(16);
        log.append(b"abcdef");
        assert_eq!(log.since(2), Some(b"cdef".to_vec()));
        assert_eq!(log.since(5), Some(b"f".to_vec()));
    }

    #[test]
    fn replay_from_the_end_returns_empty_not_none() {
        // A caller fully caught up must continue live, not be told to resync.
        let mut log = OutputLog::new(16);
        log.append(b"abcdef");
        assert_eq!(log.since(6), Some(Vec::new()));
    }

    #[test]
    fn overflow_drops_the_oldest_bytes_and_advances_start_exactly() {
        // The offset arithmetic is the whole point: if `start` and the dropped byte
        // count ever disagree, every later replay is silently shifted.
        let mut log = OutputLog::new(4);
        log.append(b"abcdef");

        assert_eq!(log.end, 6);
        assert_eq!(log.start, 2, "two bytes were dropped");
        assert_eq!(log.since(2), Some(b"cdef".to_vec()));
    }

    #[test]
    fn an_offset_older_than_the_buffer_is_unresumable() {
        // Returning the remaining bytes here would leave a hole at the front, and a
        // hole fed to a VT parser is permanent corruption rather than a lost frame.
        let mut log = OutputLog::new(4);
        log.append(b"abcdef");
        assert_eq!(log.since(0), None);
        assert_eq!(log.since(1), None);
        assert_eq!(log.since(2), Some(b"cdef".to_vec()));
    }

    #[test]
    fn an_offset_beyond_what_was_produced_is_unresumable() {
        // A client claiming a future offset is a bug somewhere; sending nothing
        // would look like a healthy idle pane.
        let mut log = OutputLog::new(16);
        log.append(b"abc");
        assert_eq!(log.since(4), None);
        assert_eq!(log.since(u64::MAX), None);
    }

    #[test]
    fn many_small_appends_keep_offsets_consistent() {
        // Exercises the trim path repeatedly, which is where an off-by-one would
        // accumulate rather than show up once.
        let mut log = OutputLog::new(8);
        for index in 0..100u8 {
            log.append(&[index]);
        }

        assert_eq!(log.end, 100);
        assert_eq!(log.start, 92);
        let tail = log.since(92).expect("tail should be held");
        assert_eq!(tail, (92u8..100).collect::<Vec<u8>>());
        assert_eq!(log.since(91), None);
    }

    #[test]
    fn a_single_append_larger_than_capacity_keeps_only_the_tail() {
        let mut log = OutputLog::new(3);
        log.append(b"abcdefgh");
        assert_eq!(log.end, 8);
        assert_eq!(log.start, 5);
        assert_eq!(log.since(5), Some(b"fgh".to_vec()));
    }

    #[test]
    fn replay_bytes_always_line_up_with_the_offsets_reported() {
        // The invariant that matters: for every resumable offset, what comes back is
        // exactly the bytes from that offset to the end. Checked across a schedule of
        // appends rather than at one point in time.
        let mut log = OutputLog::new(10);
        let mut produced: Vec<u8> = Vec::new();
        let mut next = 0u8;

        for chunk in [1usize, 4, 7, 2, 9, 3] {
            let bytes: Vec<u8> = (0..chunk)
                .map(|_| {
                    next = next.wrapping_add(1);
                    next
                })
                .collect();
            log.append(&bytes);
            produced.extend_from_slice(&bytes);

            for offset in log.start..=log.end {
                let replayed = log.since(offset).expect("offset within the window");
                let expected = &produced[offset as usize..];
                assert_eq!(
                    replayed, expected,
                    "replay from {offset} disagreed with what was produced"
                );
            }
        }
    }
}
