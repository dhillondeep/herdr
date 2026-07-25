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

/// One live PTY.
struct Channel {
    /// Write end of the PTY master, for user input.
    writer: Box<dyn Write + Send>,
    /// Raw master fd, needed for the window-size ioctl.
    master_fd: std::os::fd::RawFd,
    /// Pid of the child on this machine.
    pid: u32,
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
                handle(other, out, channels, exit_tx);
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

fn handle(
    message: ToHost,
    out: &SharedOut,
    channels: &Arc<Mutex<HashMap<ChannelId, Channel>>>,
    exit_tx: &mpsc::Sender<(ChannelId, Option<i32>)>,
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

    channels.lock().map_err(|_| poisoned())?.insert(
        channel,
        Channel {
            writer: Box::new(writer_file),
            master_fd,
            pid,
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
                    Ok(n) => send(
                        &out,
                        &FromHost::Data {
                            channel,
                            bytes: buffer[..n].to_vec(),
                        },
                    ),
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
