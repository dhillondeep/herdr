//! Drives the local `HostLink` against a real `herdr pty-host` subprocess.
//!
//! This is the join between the two halves: the link hands out a socket fd that
//! behaves like a PTY master, and the daemon owns the actual PTY. Reading and
//! writing that fd directly is exactly what the PTY actor does, so exercising it
//! here covers the byte path without needing the app.
//!
//! No ssh: the transport only has to deliver stdio, and doing it over pipes keeps
//! the test deterministic.

use std::io::{Read, Write};
use std::os::unix::net::UnixStream;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

/// Talks to the daemon by spawning the built binary.
struct Daemon {
    child: Child,
}

impl Daemon {
    /// Returns the daemon plus the streams to hand to a link.
    fn start() -> (Self, std::process::ChildStdout, std::process::ChildStdin) {
        let mut path = std::env::current_exe().expect("test exe");
        path.pop();
        if path.ends_with("deps") {
            path.pop();
        }
        let mut child = Command::new(path.join("herdr"))
            .arg("pty-host")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .expect("spawn pty-host");
        let stdout = child.stdout.take().expect("stdout");
        let stdin = child.stdin.take().expect("stdin");
        (Self { child }, stdout, stdin)
    }
}

impl Drop for Daemon {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// Read from a non-blocking fd until `needle` appears.
fn read_until(stream: &mut UnixStream, needle: &str, timeout: Duration) -> String {
    let deadline = Instant::now() + timeout;
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
                std::thread::sleep(Duration::from_millis(20));
            }
            Err(_) => break,
        }
    }
    panic!("never saw {needle:?}; saw {seen:?}");
}

/// The link is crate-internal, so these tests exercise it through the binary's
/// own integration surface: a helper subcommand would be the alternative, but
/// duplicating the tiny client here keeps the production surface clean.
mod client {
    use serde::{Deserialize, Serialize};

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
        // Tags are positional in bincode, so every variant must exist here even
        // where this test never sends it.
        #[allow(dead_code)]
        Exec {
            id: u64,
            argv: Vec<String>,
            cwd: Option<String>,
        },
        #[allow(dead_code)]
        Detect {
            channel: u64,
            agent: Option<String>,
        },
        // Present only to keep the variant tags aligned with the real protocol.
        // bincode encodes an enum discriminant positionally, so a shim that omits a
        // variant silently renumbers every one after it and this whole test file
        // would be exercising the wrong messages.
        #[allow(dead_code)]
        Attach {
            host_epoch: u64,
            panes: Vec<(u64, u64)>,
        },
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
        // Same reason as `ToHost::Attach`: tags are positional, so the tail of the
        // enum has to exist even where this test never looks at it.
        #[allow(dead_code)]
        Replay {
            channel: u64,
            from: u64,
            bytes: Vec<u8>,
        },
        #[allow(dead_code)]
        Snapshot {
            channel: u64,
            out_offset: u64,
            ansi: String,
        },
        #[allow(dead_code)]
        Desync {
            channel: u64,
            available_from: u64,
            out_offset: u64,
        },
        #[allow(dead_code)]
        ExecResult {
            id: u64,
            code: Option<i32>,
            stdout: Vec<u8>,
            stderr: Vec<u8>,
        },
        #[allow(dead_code)]
        Detected {
            channel: u64,
            state: u8,
            blocker: u8,
            fault: bool,
        },
        #[allow(dead_code)]
        Gone {
            channel: u64,
            reason: u8,
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

use client::{FromHost, SpawnSpec, ToHost};

/// Stand-in for `HostLink`: a socket pair whose local end is pumped to and from
/// the daemon, mirroring exactly what the real link does. The fd the "actor" gets
/// is a socket, which is the property under test.
struct Bridge {
    actor_side: UnixStream,
    _daemon: Daemon,
}

impl Bridge {
    fn spawn(argv: &[&str], rows: u16, cols: u16) -> Self {
        let (daemon, mut stdout, mut stdin) = Daemon::start();

        client::write(&mut stdin, &ToHost::Hello { version: 6 }).expect("hello");
        let welcome: FromHost = client::read(&mut stdout).expect("welcome");
        assert!(matches!(welcome, FromHost::Welcome { .. }));

        client::write(
            &mut stdin,
            &ToHost::Spawn {
                channel: 1,
                spec: SpawnSpec {
                    argv: argv.iter().map(|a| a.to_string()).collect(),
                    cwd: None,
                    env: Vec::new(),
                    rows,
                    cols,
                },
            },
        )
        .expect("spawn");
        let spawned: FromHost = client::read(&mut stdout).expect("spawned");
        assert!(
            matches!(spawned, FromHost::Spawned { .. }),
            "got {spawned:?}"
        );

        let (actor_side, local_side) = UnixStream::pair().expect("pair");
        actor_side.set_nonblocking(true).expect("nonblocking");

        // Host output -> the actor's socket, the direction that makes the fd
        // behave like a PTY master for reads.
        let mut writer_end = local_side.try_clone().expect("clone");
        std::thread::spawn(move || {
            while let Ok(message) = client::read::<_, FromHost>(&mut stdout) {
                match message {
                    FromHost::Data { bytes, .. } => {
                        if writer_end.write_all(&bytes).is_err() {
                            break;
                        }
                    }
                    // Shut the socket down rather than relying on drop: the
                    // input pump holds another clone, so a drop alone would
                    // leave it open and the actor would never see EOF.
                    FromHost::Exited { .. } => {
                        let _ = writer_end.shutdown(std::net::Shutdown::Both);
                        break;
                    }
                    _ => {}
                }
            }
            let _ = writer_end.shutdown(std::net::Shutdown::Both);
        });

        // The actor's writes -> Data frames, the input direction.
        let mut reader_end = local_side;
        let stdin_handle = std::sync::Arc::new(std::sync::Mutex::new(stdin));
        {
            let stdin_handle = std::sync::Arc::clone(&stdin_handle);
            std::thread::spawn(move || {
                let mut buffer = [0u8; 4096];
                while let Ok(n) = reader_end.read(&mut buffer) {
                    if n == 0 {
                        break;
                    }
                    let Ok(mut guard) = stdin_handle.lock() else {
                        break;
                    };
                    if client::write(
                        &mut *guard,
                        &ToHost::Data {
                            channel: 1,
                            bytes: buffer[..n].to_vec(),
                        },
                    )
                    .is_err()
                    {
                        break;
                    }
                }
            });
        }

        RESIZE_SINK
            .lock()
            .unwrap()
            .replace(std::sync::Arc::clone(&stdin_handle));

        Self {
            actor_side,
            _daemon: daemon,
        }
    }

    fn resize(&self, rows: u16, cols: u16) {
        let sink = RESIZE_SINK.lock().unwrap();
        let handle = sink.as_ref().expect("resize sink");
        let mut guard = handle.lock().unwrap();
        client::write(
            &mut *guard,
            &ToHost::Resize {
                channel: 1,
                rows,
                cols,
                cell_width_px: 8,
                cell_height_px: 16,
            },
        )
        .expect("resize");
    }
}

static RESIZE_SINK: std::sync::Mutex<
    Option<std::sync::Arc<std::sync::Mutex<std::process::ChildStdin>>>,
> = std::sync::Mutex::new(None);

#[test]
fn the_fd_handed_to_the_actor_carries_host_output() {
    let mut bridge = Bridge::spawn(&["sh", "-c", "echo through-the-socket; sleep 5"], 24, 80);
    let seen = read_until(
        &mut bridge.actor_side,
        "through-the-socket",
        Duration::from_secs(10),
    );
    assert!(seen.contains("through-the-socket"), "{seen}");
}

#[test]
fn writing_to_the_fd_reaches_the_remote_process() {
    let mut bridge = Bridge::spawn(&["cat"], 24, 80);
    bridge
        .actor_side
        .write_all(b"typed-into-the-socket\n")
        .expect("write");
    let seen = read_until(
        &mut bridge.actor_side,
        "typed-into-the-socket",
        Duration::from_secs(10),
    );
    assert!(seen.contains("typed-into-the-socket"), "{seen}");
}

#[test]
fn resize_travels_as_a_message_because_the_fd_is_not_a_tty() {
    // The whole reason resize is a protocol message: this fd is a socket, so a
    // TIOCSWINSZ ioctl on it fails with ENOTTY. The child is asked directly,
    // since a resize that quietly does nothing would otherwise look fine.
    let mut bridge = Bridge::spawn(&["sh", "-c", "sleep 0.5; stty size; sleep 30"], 24, 80);
    bridge.resize(37, 141);

    let seen = read_until(&mut bridge.actor_side, "37 141", Duration::from_secs(10));
    assert!(
        seen.contains("37 141"),
        "child should see the pushed size: {seen}"
    );
}

#[test]
fn an_ioctl_on_the_actor_fd_would_fail_which_is_why_resize_is_a_message() {
    // Pins the assumption above rather than leaving it as a comment: if this ever
    // starts succeeding, the reason for the message path has changed.
    let (sock, _peer) = UnixStream::pair().expect("pair");
    let size = libc::winsize {
        ws_row: 24,
        ws_col: 80,
        ws_xpixel: 0,
        ws_ypixel: 0,
    };
    let result = unsafe {
        libc::ioctl(
            std::os::fd::AsRawFd::as_raw_fd(&sock),
            libc::TIOCSWINSZ,
            &size,
        )
    };
    assert_eq!(result, -1, "a socket must not accept a window-size ioctl");
}

#[test]
fn the_actor_fd_reports_eof_when_the_remote_process_exits() {
    // EOF is how the actor learns a local child died; a remote exit must present
    // the same way or a finished pane would hang forever.
    let mut bridge = Bridge::spawn(&["sh", "-c", "echo bye; exit 0"], 24, 80);
    let _ = read_until(&mut bridge.actor_side, "bye", Duration::from_secs(10));

    let deadline = Instant::now() + Duration::from_secs(10);
    let mut buffer = [0u8; 256];
    while Instant::now() < deadline {
        match bridge.actor_side.read(&mut buffer) {
            Ok(0) => return,
            Ok(_) => {}
            Err(ref err) if err.kind() == std::io::ErrorKind::WouldBlock => {
                std::thread::sleep(Duration::from_millis(20));
            }
            Err(_) => return,
        }
    }
    panic!("actor fd never reported EOF after the remote process exited");
}
