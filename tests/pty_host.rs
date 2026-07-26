//! Drives `herdr pty-host` as a real subprocess over pipes.
//!
//! No ssh and no network: ssh is just a way to get stdio to another machine, so
//! exercising the daemon over local pipes tests everything except the transport
//! and stays deterministic in CI.

use std::io::Read;
use std::process::{Child, ChildStdin, ChildStdout, Command, Stdio};
use std::time::{Duration, Instant};

/// The message types, mirrored from `src/host/protocol.rs`.
///
/// Duplicated rather than included: an integration test cannot reach the binary
/// crate's internals. The duplication is useful in itself — if the wire types
/// change incompatibly, this stops compiling or stops decoding, which is exactly
/// the contract a protocol should have.
mod protocol {
    use serde::{Deserialize, Serialize};

    pub const HOST_PROTOCOL_VERSION: u32 = 5;

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
        // Tags are positional in bincode, so the tail must exist even unused here.
        #[allow(dead_code)]
        Exec {
            id: u64,
            argv: Vec<String>,
            cwd: Option<String>,
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
    }
}

/// Length-prefixed bincode, matching `crate::protocol::wire`.
mod frame {
    use std::io::{Read, Write};

    pub fn write<W: Write, M: serde::Serialize>(
        writer: &mut W,
        message: &M,
    ) -> std::io::Result<()> {
        let payload = bincode::serde::encode_to_vec(message, bincode::config::standard())
            .map_err(std::io::Error::other)?;
        writer.write_all(&(payload.len() as u32).to_le_bytes())?;
        writer.write_all(&payload)?;
        writer.flush()
    }

    pub fn read<R: Read, M: for<'de> serde::Deserialize<'de>>(
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

use protocol::{FromHost, SpawnSpec, ToHost, HOST_PROTOCOL_VERSION};

fn binary() -> std::path::PathBuf {
    // The test binary lives next to the built herdr binary.
    let mut path = std::env::current_exe().expect("test exe");
    path.pop();
    if path.ends_with("deps") {
        path.pop();
    }
    path.join("herdr")
}

struct Host {
    child: Child,
    stdin: ChildStdin,
    stdout: ChildStdout,
}

impl Host {
    fn start() -> Self {
        let mut child = Command::new(binary())
            .arg("pty-host")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .expect("spawn pty-host");
        let stdin = child.stdin.take().expect("stdin");
        let stdout = child.stdout.take().expect("stdout");
        let mut host = Self {
            child,
            stdin,
            stdout,
        };
        host.send(&ToHost::Hello {
            version: HOST_PROTOCOL_VERSION,
        });
        match host.recv() {
            FromHost::Welcome { version, .. } => assert_eq!(version, HOST_PROTOCOL_VERSION),
            other => panic!("expected Welcome, got {other:?}"),
        }
        host
    }

    fn send(&mut self, message: &ToHost) {
        frame::write(&mut self.stdin, message).expect("send");
    }

    fn recv(&mut self) -> FromHost {
        frame::read(&mut self.stdout).expect("recv")
    }

    /// Collect output for one channel until `needle` appears, or fail.
    fn read_until(&mut self, needle: &str, timeout: Duration) -> String {
        let deadline = Instant::now() + timeout;
        let mut seen = String::new();
        while Instant::now() < deadline {
            match frame::read::<_, FromHost>(&mut self.stdout) {
                Ok(FromHost::Data { bytes, .. }) => {
                    seen.push_str(&String::from_utf8_lossy(&bytes));
                    if seen.contains(needle) {
                        return seen;
                    }
                }
                Ok(FromHost::Exited { .. }) => break,
                Ok(_) => {}
                Err(_) => break,
            }
        }
        panic!("never saw {needle:?}; output so far: {seen:?}");
    }
}

impl Drop for Host {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn spec(argv: &[&str]) -> SpawnSpec {
    SpawnSpec {
        argv: argv.iter().map(|arg| arg.to_string()).collect(),
        cwd: None,
        env: Vec::new(),
        rows: 24,
        cols: 80,
    }
}

#[test]
fn spawns_a_process_and_streams_its_output() {
    let mut host = Host::start();
    host.send(&ToHost::Spawn {
        channel: 1,
        spec: spec(&["sh", "-c", "echo hello-from-pty"]),
    });

    match host.recv() {
        FromHost::Spawned { channel, pid } => {
            assert_eq!(channel, 1);
            assert!(pid > 0, "a spawned child must report a real pid");
        }
        other => panic!("expected Spawned, got {other:?}"),
    }

    let output = host.read_until("hello-from-pty", Duration::from_secs(10));
    assert!(output.contains("hello-from-pty"), "{output}");
}

#[test]
fn reports_exit_after_the_process_finishes() {
    let mut host = Host::start();
    host.send(&ToHost::Spawn {
        channel: 2,
        spec: spec(&["sh", "-c", "exit 3"]),
    });
    assert!(matches!(host.recv(), FromHost::Spawned { .. }));

    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        assert!(Instant::now() < deadline, "no Exited frame arrived");
        match host.recv() {
            FromHost::Exited { channel, .. } => {
                assert_eq!(channel, 2);
                break;
            }
            FromHost::Data { .. } => {}
            other => panic!("unexpected {other:?}"),
        }
    }
}

#[test]
fn input_reaches_the_process() {
    let mut host = Host::start();
    host.send(&ToHost::Spawn {
        channel: 3,
        // `cat` echoes back whatever we type.
        spec: spec(&["cat"]),
    });
    assert!(matches!(host.recv(), FromHost::Spawned { .. }));

    host.send(&ToHost::Data {
        channel: 3,
        bytes: b"round-trip\n".to_vec(),
    });
    let output = host.read_until("round-trip", Duration::from_secs(10));
    assert!(output.contains("round-trip"), "{output}");
}

#[test]
fn resize_is_applied_to_the_remote_pty() {
    // The window size must be a message, not a local ioctl: the PTY is on the
    // far side. Asking the child itself is the only honest check.
    let mut host = Host::start();
    host.send(&ToHost::Spawn {
        channel: 4,
        spec: spec(&["sh", "-c", "sleep 0.4; stty size; sleep 30"]),
    });
    assert!(matches!(host.recv(), FromHost::Spawned { .. }));

    host.send(&ToHost::Resize {
        channel: 4,
        rows: 41,
        cols: 133,
        cell_width_px: 8,
        cell_height_px: 16,
    });

    let output = host.read_until("41 133", Duration::from_secs(10));
    assert!(
        output.contains("41 133"),
        "child should observe the resized window: {output}"
    );
}

#[test]
fn a_failed_spawn_is_reported_rather_than_silently_dropped() {
    let mut host = Host::start();
    host.send(&ToHost::Spawn {
        channel: 5,
        spec: spec(&["herdr-no-such-program-xyz"]),
    });

    match host.recv() {
        FromHost::SpawnFailed { channel, message } => {
            assert_eq!(channel, 5);
            assert!(!message.is_empty(), "failure must carry a reason");
        }
        other => panic!("expected SpawnFailed, got {other:?}"),
    }
}

#[test]
fn shutdown_terminates_the_process_session() {
    let mut host = Host::start();
    host.send(&ToHost::Spawn {
        channel: 6,
        spec: spec(&["sh", "-c", "sleep 300"]),
    });
    let pid = match host.recv() {
        FromHost::Spawned { pid, .. } => pid,
        other => panic!("expected Spawned, got {other:?}"),
    };

    host.send(&ToHost::Shutdown { channel: 6 });

    // Signal escalation happens on the host side; wait for the pid to go away.
    let deadline = Instant::now() + Duration::from_secs(10);
    while Instant::now() < deadline {
        let alive = unsafe { libc::kill(pid as libc::pid_t, 0) } == 0;
        if !alive {
            return;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    panic!("process {pid} survived shutdown");
}

#[test]
fn work_before_a_handshake_is_refused() {
    // Skipping Hello must not be treated as a compatible peer, or a version
    // mismatch would surface as strange behaviour later instead of a clean stop.
    let mut child = Command::new(binary())
        .arg("pty-host")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn");
    let mut stdin = child.stdin.take().expect("stdin");
    let mut stdout = child.stdout.take().expect("stdout");

    frame::write(
        &mut stdin,
        &ToHost::Spawn {
            channel: 1,
            spec: spec(&["sh", "-c", "echo nope"]),
        },
    )
    .expect("write");
    drop(stdin);

    let mut buffer = Vec::new();
    let _ = stdout.read_to_end(&mut buffer);
    assert!(
        buffer.is_empty(),
        "daemon must not act before a handshake, got {buffer:?}"
    );

    let _ = child.kill();
    let _ = child.wait();
}

#[test]
fn an_incompatible_peer_version_stops_the_daemon_after_replying() {
    let mut child = Command::new(binary())
        .arg("pty-host")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn");
    let mut stdin = child.stdin.take().expect("stdin");
    let mut stdout = child.stdout.take().expect("stdout");

    frame::write(&mut stdin, &ToHost::Hello { version: 9_999 }).expect("write");

    // It still answers, so the local side can say which end is wrong.
    let welcome: FromHost = frame::read(&mut stdout).expect("welcome");
    assert!(matches!(welcome, FromHost::Welcome { .. }));

    let status = child.wait().expect("wait");
    assert!(status.success() || status.code().is_some());
}
