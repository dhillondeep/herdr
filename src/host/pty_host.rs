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

/// Serialised access to stdout: several reader threads report on one stream.
type SharedOut = Arc<Mutex<Box<dyn Write + Send>>>;

/// Run the daemon against the given streams until the input closes.
///
/// Split from `run()` so it can be driven over pipes in tests without ssh.
pub fn serve<R: Read>(mut input: R, output: Box<dyn Write + Send>) -> std::io::Result<()> {
    let out: SharedOut = Arc::new(Mutex::new(output));
    let channels: Arc<Mutex<HashMap<ChannelId, Channel>>> = Arc::new(Mutex::new(HashMap::new()));

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

    let mut greeted = false;

    // The link closing is the normal way this process ends.
    while let Ok(message) = read_frame::<_, ToHost>(&mut input) {
        match message {
            ToHost::Hello { version } => {
                greeted = true;
                // Always answer, even on mismatch: the local side needs our
                // version to tell the user which end to upgrade.
                send(
                    &out,
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
                handle(other, &out, &channels, &exit_tx);
            }
        }
    }

    // Tear down anything still running; this process exiting must not leave
    // orphaned shells behind on the machine.
    let ids: Vec<ChannelId> = channels
        .lock()
        .map(|map| map.keys().copied().collect())
        .unwrap_or_default();
    for channel in ids {
        shutdown_channel(&channels, channel);
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
    if let Ok(mut writer) = out.lock() {
        // A write failure means the local side is gone; the read loop will see
        // EOF and shut everything down, so there is nothing useful to do here.
        let _ = write_frame(&mut *writer, message);
        let _ = writer.flush();
    }
}

fn poisoned() -> std::io::Error {
    std::io::Error::other("pty-host channel table poisoned")
}

/// Entry point for the hidden `herdr pty-host` subcommand.
pub fn run() -> std::io::Result<()> {
    let stdin = std::io::stdin();
    let stdout = std::io::stdout();
    serve(stdin.lock(), Box::new(stdout))
}
