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

    pub const HOST_PROTOCOL_VERSION: u32 = 1;

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
    }

    #[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
    pub enum FromHost {
        Welcome { version: u32 },
        Spawned { channel: u64, pid: u32 },
        SpawnFailed { channel: u64, message: String },
        Data { channel: u64, bytes: Vec<u8> },
        Exited { channel: u64, status: Option<i32> },
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
        let mut stream = UnixStream::connect(&self.socket).expect("connect");
        client::write(
            &mut stream,
            &ToHost::Hello {
                version: HOST_PROTOCOL_VERSION,
            },
        )
        .expect("hello");
        match client::read::<_, FromHost>(&mut stream).expect("welcome") {
            FromHost::Welcome { version } => assert_eq!(version, HOST_PROTOCOL_VERSION),
            other => panic!("expected Welcome, got {other:?}"),
        }
        stream
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
                    format!(
                        "while :; do printf 'tick\\n' >> {}; sleep 0.1; done",
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
    let mut second = daemon.connect();
    let before = heartbeat_lines(&heartbeat);
    spawn_heartbeat(&mut second, 2, &heartbeat);
    std::thread::sleep(Duration::from_millis(600));

    assert!(
        heartbeat_lines(&heartbeat) > before,
        "the reattached client should be able to start work"
    );
    assert!(daemon.is_running());

    let _ = std::fs::remove_file(&heartbeat);
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
