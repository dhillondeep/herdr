//! Does a process started through the daemon outlive the client that asked for it?
//!
//! That is the whole point of the daemon being persistent, and it is the one
//! property that cannot be inferred from the code: it depends on process groups,
//! signal delivery and who owns the PTY.
//!
//! Local sockets and a file-based heartbeat, deliberately. An earlier attempt to
//! check this over ssh with `pgrep -f` measured the wrong thing twice — the search
//! pattern appeared in the command doing the searching, so it counted itself.
//! Counting lines in a file the remote process appends to cannot be fooled that way.

use std::os::unix::net::UnixStream;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

mod client {
    use serde::{Deserialize, Serialize};

    pub const HOST_PROTOCOL_VERSION: u32 = 4;

    #[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
    pub struct SpawnSpec {
        pub argv: Vec<String>,
        pub cwd: Option<String>,
        pub env: Vec<(String, String)>,
        pub rows: u16,
        pub cols: u16,
    }

    #[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
    pub enum ToHost {
        Hello {
            version: u32,
        },
        Spawn {
            channel: u64,
            spec: SpawnSpec,
        },
        Data {
            channel: u64,
            bytes: Vec<u8>,
        },
        Resize {
            channel: u64,
            rows: u16,
            cols: u16,
            cell_width_px: u32,
            cell_height_px: u32,
        },
        Shutdown {
            channel: u64,
        },
        Attach {
            host_epoch: u64,
            panes: Vec<(u64, u64)>,
        },
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
    pub enum GoneReason {
        ChildExited,
        HostRestarted,
    }

    #[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
    pub enum FromHost {
        Welcome {
            version: u32,
            host_epoch: u64,
        },
        Spawned {
            channel: u64,
            pid: u32,
        },
        SpawnFailed {
            channel: u64,
            message: String,
        },
        Data {
            channel: u64,
            from: u64,
            bytes: Vec<u8>,
        },
        Exited {
            channel: u64,
            status: Option<i32>,
        },
        Replay {
            channel: u64,
            from: u64,
            bytes: Vec<u8>,
        },
        Snapshot {
            channel: u64,
            out_offset: u64,
            ansi: String,
        },
        Desync {
            channel: u64,
            available_from: u64,
            out_offset: u64,
        },
        Gone {
            channel: u64,
            reason: GoneReason,
        },
    }

    pub fn write<W: std::io::Write, M: Serialize>(
        writer: &mut W,
        message: &M,
    ) -> std::io::Result<()> {
        let payload = bincode::serde::encode_to_vec(message, bincode::config::standard())
            .map_err(std::io::Error::other)?;
        writer.write_all(&(payload.len() as u32).to_le_bytes())?;
        writer.write_all(&payload)?;
        writer.flush()
    }

    pub fn read<R: std::io::Read, M: for<'de> Deserialize<'de>>(
        reader: &mut R,
    ) -> std::io::Result<M> {
        let mut len = [0u8; 4];
        reader.read_exact(&mut len)?;
        let len = u32::from_le_bytes(len) as usize;
        let mut payload = vec![0u8; len];
        reader.read_exact(&mut payload)?;
        let (message, _) = bincode::serde::decode_from_slice(&payload, bincode::config::standard())
            .map_err(std::io::Error::other)?;
        Ok(message)
    }
}

use client::{FromHost, SpawnSpec, ToHost, HOST_PROTOCOL_VERSION};

fn binary() -> std::path::PathBuf {
    let mut path = std::env::current_exe().expect("test exe");
    path.pop();
    if path.ends_with("deps") {
        path.pop();
    }
    path.join("herdr")
}

/// Unique paths so concurrent test binaries never share a socket or heartbeat.
fn scratch(tag: &str) -> std::path::PathBuf {
    std::env::temp_dir().join(format!(
        "herdr-persist-{}-{}-{}",
        tag,
        std::process::id(),
        Instant::now().elapsed().as_nanos()
    ))
}

struct Daemon {
    child: Child,
    socket: std::path::PathBuf,
}

impl Daemon {
    fn start(socket: std::path::PathBuf) -> Self {
        // Drop always kills and waits; the panic path below is a test failure, so
        // an unreaped child there does not matter.
        #[allow(clippy::zombie_processes)]
        let child = Command::new(binary())
            .arg("pty-host")
            .arg("serve")
            .arg("--socket")
            .arg(&socket)
            // Short idle expiry so the exit test does not wait out the production
            // grace period.
            .env("HERDR_PTY_HOST_IDLE_EXIT_MS", "1200")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("spawn daemon");

        let deadline = Instant::now() + Duration::from_secs(10);
        while Instant::now() < deadline {
            if UnixStream::connect(&socket).is_ok() {
                return Self { child, socket };
            }
            std::thread::sleep(Duration::from_millis(25));
        }
        panic!("daemon never started listening on {}", socket.display());
    }

    fn connect(&self) -> UnixStream {
        self.connect_with_epoch().0
    }

    fn connect_with_epoch(&self) -> (UnixStream, u64) {
        let mut stream = UnixStream::connect(&self.socket).expect("connect");
        client::write(
            &mut stream,
            &ToHost::Hello {
                version: HOST_PROTOCOL_VERSION,
            },
        )
        .expect("hello");
        let epoch = match client::read::<_, FromHost>(&mut stream).expect("welcome") {
            FromHost::Welcome {
                version,
                host_epoch,
            } => {
                assert_eq!(version, HOST_PROTOCOL_VERSION);
                host_epoch
            }
            other => panic!("expected Welcome, got {other:?}"),
        };
        (stream, epoch)
    }

    fn is_running(&mut self) -> bool {
        matches!(self.child.try_wait(), Ok(None))
    }
}

impl Drop for Daemon {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        let _ = std::fs::remove_file(&self.socket);
    }
}

fn heartbeat_lines(path: &std::path::Path) -> usize {
    std::fs::read_to_string(path)
        .map(|text| text.lines().count())
        .unwrap_or(0)
}

/// Spawn a channel that appends a line every 100ms, and wait until it is alive.
fn spawn_heartbeat(stream: &mut UnixStream, channel: u64, heartbeat: &std::path::Path) {
    client::write(
        stream,
        &ToHost::Spawn {
            channel,
            spec: SpawnSpec {
                argv: vec![
                    "sh".to_string(),
                    "-c".to_string(),
                    // Emits to BOTH stdout and the file: the file proves the
                    // process is alive without pattern-matching process names, and
                    // the stdout is what the output log records for replay.
                    format!(
                        "while :; do printf 'tick\\n'; printf 'tick\\n' >> {}; sleep 0.1; done",
                        heartbeat.display()
                    ),
                ],
                cwd: None,
                env: Vec::new(),
                rows: 24,
                cols: 80,
            },
        },
    )
    .expect("spawn");

    match client::read::<_, FromHost>(stream).expect("spawned") {
        FromHost::Spawned { pid, .. } => assert!(pid > 0),
        other => panic!("expected Spawned, got {other:?}"),
    }

    let deadline = Instant::now() + Duration::from_secs(10);
    while Instant::now() < deadline {
        if heartbeat_lines(heartbeat) > 0 {
            return;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    panic!("heartbeat never started writing");
}

#[test]
fn a_process_outlives_the_client_that_asked_for_it() {
    let socket = scratch("sock");
    let heartbeat = scratch("beat");
    let _ = std::fs::remove_file(&heartbeat);

    let mut daemon = Daemon::start(socket.clone());
    let mut stream = daemon.connect();
    spawn_heartbeat(&mut stream, 1, &heartbeat);

    let before = heartbeat_lines(&heartbeat);
    assert!(before > 0, "heartbeat should be running while connected");

    // Drop the client. This is the disconnect being tested: a closed laptop or a
    // dead link looks exactly like this to the daemon.
    drop(stream);
    std::thread::sleep(Duration::from_millis(1500));

    let after = heartbeat_lines(&heartbeat);
    assert!(
        after > before,
        "the process must keep running after its client disconnects: {before} -> {after}"
    );
    assert!(
        daemon.is_running(),
        "the daemon must stay alive while a channel is live"
    );

    let _ = std::fs::remove_file(&heartbeat);
}

#[test]
fn a_second_client_can_attach_after_the_first_leaves() {
    // Persistence is only useful if something can connect again afterwards.
    let socket = scratch("sock2");
    let heartbeat = scratch("beat2");
    let _ = std::fs::remove_file(&heartbeat);

    let mut daemon = Daemon::start(socket.clone());

    let mut first = daemon.connect();
    spawn_heartbeat(&mut first, 1, &heartbeat);
    drop(first);
    std::thread::sleep(Duration::from_millis(400));

    // A fresh client must be accepted and served, not refused because the daemon
    // is still holding the previous session.
    //
    // Its own heartbeat file, not the first channel's: sharing one would make the
    // assertion unable to tell which channel produced the growth, and it would pass
    // on the first channel's output alone.
    let second_beat = scratch("beat2b");
    let _ = std::fs::remove_file(&second_beat);
    let mut second = daemon.connect();
    spawn_heartbeat(&mut second, 2, &second_beat);

    // Polled rather than a fixed sleep: the suite runs tests in parallel, so a
    // fixed wait is load-sensitive and flaky.
    let deadline = Instant::now() + Duration::from_secs(10);
    while Instant::now() < deadline && heartbeat_lines(&second_beat) < 2 {
        std::thread::sleep(Duration::from_millis(50));
    }

    assert!(
        heartbeat_lines(&second_beat) >= 2,
        "the reattached client should be able to start work of its own"
    );
    assert!(daemon.is_running());

    let _ = std::fs::remove_file(&heartbeat);
    let _ = std::fs::remove_file(&second_beat);
}

#[test]
fn the_daemon_exits_once_nothing_is_left_to_serve() {
    // Persistence must not mean lingering forever: an idle daemon on every host a
    // user ever touched would be its own problem.
    let socket = scratch("sock3");
    let mut daemon = Daemon::start(socket.clone());

    let mut stream = daemon.connect();
    client::write(
        &mut stream,
        &ToHost::Spawn {
            channel: 1,
            spec: SpawnSpec {
                argv: vec!["sh".to_string(), "-c".to_string(), "exit 0".to_string()],
                cwd: None,
                env: Vec::new(),
                rows: 24,
                cols: 80,
            },
        },
    )
    .expect("spawn");

    // Drain until the channel reports it finished.
    let deadline = Instant::now() + Duration::from_secs(10);
    while Instant::now() < deadline {
        match client::read::<_, FromHost>(&mut stream) {
            Ok(FromHost::Exited { .. }) => break,
            Ok(_) => {}
            Err(_) => break,
        }
    }
    drop(stream);

    let deadline = Instant::now() + Duration::from_secs(10);
    while Instant::now() < deadline {
        if !daemon.is_running() {
            return;
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    panic!("daemon should exit once no channel is live and no client is attached");
}

/// Read frames until one concerns `channel`, so unrelated live output does not
/// confuse the assertion.
fn next_for_channel(stream: &mut UnixStream, channel: u64) -> FromHost {
    let deadline = Instant::now() + Duration::from_secs(10);
    while Instant::now() < deadline {
        match client::read::<_, FromHost>(stream) {
            Ok(message) => {
                let concerns = match &message {
                    FromHost::Replay { channel: c, .. }
                    | FromHost::Snapshot { channel: c, .. }
                    | FromHost::Desync { channel: c, .. }
                    | FromHost::Gone { channel: c, .. } => *c == channel,
                    _ => false,
                };
                if concerns {
                    return message;
                }
            }
            Err(_) => break,
        }
    }
    panic!("no resume answer for channel {channel}");
}

#[test]
fn no_live_output_reaches_a_reattached_client_before_its_resume_answer() {
    // The ordering that lets the client trust its own cursor. A pane produces
    // output continuously, so on reconnect there is a live frame ready to go at the
    // same moment as the replay. If the live frame went first it would land ahead of
    // the client's cursor and be read as a gap — a "bytes were lost" marker for
    // bytes that were arriving in the very next frame. The daemon therefore holds a
    // channel's live output until that channel has been answered.
    let socket = scratch("attach-order");
    let heartbeat = scratch("attach-order-beat");
    let _ = std::fs::remove_file(&heartbeat);

    let daemon = Daemon::start(socket.clone());
    let (mut first, epoch) = daemon.connect_with_epoch();
    spawn_heartbeat(&mut first, 1, &heartbeat);
    // Read enough that the client is genuinely behind when it leaves.
    std::thread::sleep(Duration::from_millis(400));
    drop(first);

    // Keep producing with nobody attached, so the log has a backlog and the reader
    // thread is actively trying to send.
    std::thread::sleep(Duration::from_millis(700));

    let mut second = daemon.connect();

    // The attach is deliberately delayed rather than sent at once. Racing it
    // against the pane's own timing would make this test pass or fail by luck; a
    // held-back attach turns the same question into a deterministic one — during
    // this window the pane is definitely producing output (it ticks every 100ms),
    // so if any of it arrives, the gate is not working.
    second
        .set_read_timeout(Some(Duration::from_millis(200)))
        .expect("read timeout");
    // Bounded by a deadline as well as by the per-read timeout, and it stops at the
    // first offending frame. Draining until the reads dry up would never terminate
    // when the gate is broken, because a pane that ticks faster than the timeout
    // keeps the loop fed — the failing case has to finish too.
    let window = Instant::now() + Duration::from_millis(600);
    let mut early = None;
    while Instant::now() < window && early.is_none() {
        match client::read::<_, FromHost>(&mut second) {
            Ok(FromHost::Data {
                channel: 1, from, ..
            }) => early = Some(from),
            Ok(_) => continue,
            Err(_) => continue,
        }
    }
    assert!(
        early.is_none(),
        "live output must not reach a client that has not been told where to resume \
         from; got a frame at offset {early:?}"
    );

    second
        .set_read_timeout(Some(Duration::from_secs(10)))
        .expect("read timeout");
    client::write(
        &mut second,
        &ToHost::Attach {
            host_epoch: epoch,
            panes: vec![(1, 0)],
        },
    )
    .expect("attach");

    // And the answer, when it comes, is the first thing about this channel.
    let deadline = Instant::now() + Duration::from_secs(10);
    let mut first_for_channel = None;
    while Instant::now() < deadline && first_for_channel.is_none() {
        match client::read::<_, FromHost>(&mut second) {
            Ok(message) => match &message {
                FromHost::Data { channel: 1, .. }
                | FromHost::Replay { channel: 1, .. }
                | FromHost::Desync { channel: 1, .. }
                | FromHost::Gone { channel: 1, .. } => first_for_channel = Some(message),
                _ => continue,
            },
            Err(_) => break,
        }
    }

    match first_for_channel.expect("something for channel 1") {
        FromHost::Replay { from, bytes, .. } => {
            assert_eq!(from, 0);
            // Everything produced during the wait is in the replay, not lost.
            assert!(!bytes.is_empty(), "the held-back output must be replayed");
        }
        other => panic!("the resume answer must come first, got {other:?}"),
    }

    let _ = std::fs::remove_file(&heartbeat);
}

#[test]
fn reattaching_with_a_current_offset_replays_what_was_missed() {
    let socket = scratch("resume-ok");
    let heartbeat = scratch("resume-ok-beat");
    let _ = std::fs::remove_file(&heartbeat);

    let daemon = Daemon::start(socket.clone());
    let (mut first, epoch) = daemon.connect_with_epoch();
    spawn_heartbeat(&mut first, 1, &heartbeat);
    drop(first);

    // Let the pane produce output with nobody attached — this is what must be
    // replayable.
    std::thread::sleep(Duration::from_millis(700));

    let mut second = daemon.connect();
    client::write(
        &mut second,
        &ToHost::Attach {
            host_epoch: epoch,
            panes: vec![(1, 0)],
        },
    )
    .expect("attach");

    match next_for_channel(&mut second, 1) {
        FromHost::Replay { from, bytes, .. } => {
            assert_eq!(from, 0);
            assert!(
                !bytes.is_empty(),
                "output produced while detached should be replayed"
            );
        }
        other => panic!("expected Replay, got {other:?}"),
    }

    let _ = std::fs::remove_file(&heartbeat);
}

#[test]
fn reattaching_after_the_daemon_restarted_reports_gone_not_a_stale_frame() {
    // The distinction that matters most: a wrong epoch must never resume, however
    // plausible the offsets look, or the client would show a frame for a pane whose
    // agent no longer exists.
    let socket = scratch("resume-epoch");
    let heartbeat = scratch("resume-epoch-beat");
    let _ = std::fs::remove_file(&heartbeat);

    let daemon = Daemon::start(socket.clone());
    let (mut first, epoch) = daemon.connect_with_epoch();
    spawn_heartbeat(&mut first, 1, &heartbeat);
    drop(first);
    std::thread::sleep(Duration::from_millis(300));

    let mut second = daemon.connect();
    client::write(
        &mut second,
        &ToHost::Attach {
            // A different epoch, as a client would hold after the daemon restarted.
            host_epoch: epoch.wrapping_add(1),
            panes: vec![(1, 0)],
        },
    )
    .expect("attach");

    match next_for_channel(&mut second, 1) {
        FromHost::Gone { reason, .. } => {
            assert_eq!(reason, client::GoneReason::HostRestarted);
        }
        other => panic!("expected Gone/HostRestarted, got {other:?}"),
    }

    let _ = std::fs::remove_file(&heartbeat);
}

#[test]
fn reattaching_to_a_finished_pane_reports_gone_child_exited() {
    let socket = scratch("resume-exited");
    let daemon = Daemon::start(socket.clone());
    let (mut first, epoch) = daemon.connect_with_epoch();

    client::write(
        &mut first,
        &ToHost::Spawn {
            channel: 1,
            spec: SpawnSpec {
                argv: vec!["sh".to_string(), "-c".to_string(), "exit 0".to_string()],
                cwd: None,
                env: Vec::new(),
                rows: 24,
                cols: 80,
            },
        },
    )
    .expect("spawn");

    let deadline = Instant::now() + Duration::from_secs(10);
    while Instant::now() < deadline {
        match client::read::<_, FromHost>(&mut first) {
            Ok(FromHost::Exited { .. }) => break,
            Ok(_) => {}
            Err(_) => break,
        }
    }

    client::write(
        &mut first,
        &ToHost::Attach {
            host_epoch: epoch,
            panes: vec![(1, 0)],
        },
    )
    .expect("attach");

    match next_for_channel(&mut first, 1) {
        FromHost::Gone { reason, .. } => assert_eq!(reason, client::GoneReason::ChildExited),
        other => panic!("expected Gone/ChildExited, got {other:?}"),
    }
}

#[test]
fn an_unresumable_offset_gets_the_screen_the_host_re_derived() {
    // An offset the daemon never produced cannot be replayed from, and sending
    // nothing would look like a healthy idle pane. But a bare "you are out of sync"
    // leaves the pane blank until the application redraws, which for an idle
    // full-screen agent may be never — so the host parses its own output and sends
    // back what the screen actually looks like. This is the path every overnight
    // reattach takes, so it is the one that decides whether any of this is useful.
    let socket = scratch("resume-snapshot");
    let heartbeat = scratch("resume-snapshot-beat");
    let _ = std::fs::remove_file(&heartbeat);

    let daemon = Daemon::start(socket.clone());
    let (mut stream, epoch) = daemon.connect_with_epoch();
    spawn_heartbeat(&mut stream, 1, &heartbeat);
    // Let the pane draw something for the shadow screen to hold.
    std::thread::sleep(Duration::from_millis(400));

    client::write(
        &mut stream,
        &ToHost::Attach {
            host_epoch: epoch,
            panes: vec![(1, u64::MAX / 2)],
        },
    )
    .expect("attach");

    match next_for_channel(&mut stream, 1) {
        FromHost::Snapshot {
            out_offset, ansi, ..
        } => {
            assert!(out_offset < u64::MAX / 2);
            // The host's own parse of the pane's output, not a canned frame.
            assert!(ansi.contains("tick"), "{ansi:?}");
        }
        other => panic!("expected Snapshot, got {other:?}"),
    }

    let _ = std::fs::remove_file(&heartbeat);
}

#[test]
fn an_unresumable_offset_still_desyncs_when_there_is_no_screen_to_send() {
    // The snapshot is an improvement on the desync, not a replacement for it. A pane
    // that has drawn nothing has no screen worth sending, and inventing a blank one
    // would clear a pane for no reason.
    let socket = scratch("resume-desync");

    let daemon = Daemon::start(socket.clone());
    let (mut stream, epoch) = daemon.connect_with_epoch();
    client::write(
        &mut stream,
        &ToHost::Spawn {
            channel: 1,
            spec: SpawnSpec {
                argv: vec!["sleep".to_string(), "30".to_string()],
                cwd: None,
                env: Vec::new(),
                rows: 24,
                cols: 80,
            },
        },
    )
    .expect("spawn");
    match client::read::<_, FromHost>(&mut stream).expect("spawned") {
        FromHost::Spawned { pid, .. } => assert!(pid > 0),
        other => panic!("expected Spawned, got {other:?}"),
    }

    client::write(
        &mut stream,
        &ToHost::Attach {
            host_epoch: epoch,
            panes: vec![(1, u64::MAX / 2)],
        },
    )
    .expect("attach");

    match next_for_channel(&mut stream, 1) {
        FromHost::Desync { out_offset, .. } => assert!(out_offset < u64::MAX / 2),
        other => panic!("expected Desync for a pane with a blank screen, got {other:?}"),
    }
}
