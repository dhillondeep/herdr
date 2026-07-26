//! Wire protocol between the local herdr server and a `herdr pty-host` daemon.
//!
//! The local side owns everything that interprets bytes — the VT parser, the
//! grid, scrollback, detection, layout. The daemon owns only the PTYs. So this
//! protocol is deliberately small: spawn a process, move bytes, resize, report
//! exit. Anything richer belongs on the local side.
//!
//! Framing is reused from [`crate::protocol::wire`] so there is one length-prefix
//! implementation in the codebase, but the message set and version are separate:
//! the client/server protocol and the host protocol evolve independently, and a
//! host is provisioned separately from the binary talking to it.

use serde::{Deserialize, Serialize};

pub use crate::protocol::wire::FramingError;

/// Version of this host protocol.
///
/// Deliberately independent of `wire::PROTOCOL_VERSION`. Hosts are provisioned
/// per machine and may lag, so compatibility is a *range* rather than equality —
/// see [`negotiate`]. Exact-match versioning here would mean one stale host
/// bricks that host until re-provisioned.
pub const HOST_PROTOCOL_VERSION: u32 = 5;

/// Oldest host protocol this build can still talk to.
///
/// Tracks `HOST_PROTOCOL_VERSION` for now: the framing is positional, so a frame
/// from an older daemon cannot be decoded by a newer client at all — a stale peer
/// produces a garbled `Welcome` rather than a clean refusal. Nothing is released
/// yet, so there is no back-compatibility to keep, and a host running an older
/// binary reports a clear version mismatch telling the user to re-provision, which
/// `herdr host install` makes a one-liner. Once the message set settles this stops
/// moving and the range starts doing real work.
pub const MIN_SUPPORTED_HOST_PROTOCOL_VERSION: u32 = 5;

/// Cap on a single host frame. Output is chunked well below this; the cap exists
/// so a corrupted length prefix cannot make us allocate wildly.
pub const MAX_HOST_FRAME_SIZE: usize = 1024 * 1024;

/// Identifies one PTY within a host link. Assigned by the local side so it can
/// route replies without waiting for an acknowledgement.
pub type ChannelId = u64;

/// What to run on the remote machine.
///
/// The shell is resolved *by the daemon*, not here: the local machine's `$SHELL`,
/// its passwd entry and its filesystem are all irrelevant to a process that will
/// run somewhere else. Sending a resolved command would bake in local answers.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SpawnSpec {
    /// Explicit argv. Empty means "the remote user's login shell".
    pub argv: Vec<String>,
    /// Working directory on the remote machine. Absent means the remote default.
    pub cwd: Option<String>,
    /// Environment entries to set. Only what herdr needs — the local process
    /// environment is deliberately not shipped.
    pub env: Vec<(String, String)>,
    pub rows: u16,
    pub cols: u16,
}

/// Local server to daemon.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ToHost {
    /// First frame on a link. Carries the local side's protocol version.
    Hello {
        version: u32,
    },
    Spawn {
        channel: ChannelId,
        spec: SpawnSpec,
    },
    /// Bytes typed by the user, destined for the PTY.
    Data {
        channel: ChannelId,
        bytes: Vec<u8>,
    },
    /// Window size change. This is a message rather than an ioctl because the
    /// PTY is on the other side of the link.
    Resize {
        channel: ChannelId,
        rows: u16,
        cols: u16,
        cell_width_px: u32,
        cell_height_px: u32,
    },
    /// Terminate the channel's process session, escalating as needed. Performed
    /// by the daemon, which is where the pids actually live.
    Shutdown {
        channel: ChannelId,
    },
    /// Run a short command on the host and send back what it printed.
    ///
    /// Not a channel: a channel is a PTY with a lifetime, and this is a question with
    /// an answer. It exists because several things herdr reports are facts about the
    /// machine the work is on — what branch a repository is on, how far ahead it is —
    /// and answering them from the local filesystem is not merely unavailable but
    /// actively wrong, since a path that happens to exist locally describes a
    /// different repository entirely.
    ///
    /// Deliberately not a general remote shell: the caller supplies argv, never a
    /// command line, so nothing here parses or quotes on the host's behalf.
    Exec {
        /// Correlates the answer. Assigned by the local side.
        id: u64,
        argv: Vec<String>,
        cwd: Option<String>,
    },
    /// Reconnecting: here is the epoch I last saw and how far I had read on each
    /// pane. Tell me, per pane, whether I can resume.
    ///
    /// Offsets are per pane rather than one stream position because panes are
    /// independent and a busy one must not decide the fate of a quiet one.
    Attach {
        host_epoch: u64,
        panes: Vec<(ChannelId, u64)>,
    },
}

/// Why a pane the client remembered is no longer available.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum GoneReason {
    /// Its process finished.
    ChildExited,
    /// The daemon restarted, so nothing from the previous epoch survived.
    ///
    /// Reported separately because the user-visible meaning differs: a finished
    /// pane is done, whereas a host restart lost work. Showing one as the other is
    /// the worst available outcome.
    HostRestarted,
}

/// Daemon to local server.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum FromHost {
    /// Response to `Hello`, carrying the daemon's version so either side can
    /// refuse a pairing it cannot support, plus who this daemon is.
    Welcome {
        version: u32,
        /// Identifies this daemon instance. A different value means the daemon
        /// restarted, so every channel a client remembers is gone.
        ///
        /// Distinguishing "the network died and the agents are alive" from "the
        /// host restarted and the agents are gone" is the whole reason this
        /// exists. Conflating them is the worst available outcome: the client
        /// would show a plausible stale frame for a pane whose agent no longer
        /// exists.
        host_epoch: u64,
    },
    /// A spawn succeeded. `pid` is the process id **on the host**, useful only
    /// for display and for the daemon's own bookkeeping — never for a local
    /// signal or a local `/proc` read.
    Spawned { channel: ChannelId, pid: u32 },
    /// A spawn failed. The channel is dead; no `Exited` will follow.
    SpawnFailed { channel: ChannelId, message: String },
    /// PTY output, positioned in the channel's output stream.
    ///
    /// `from` is the offset of the first byte, and it is not redundant with
    /// counting received bytes locally. Answering an `Attach` is not atomic with
    /// respect to output still being produced, so a `Replay` and a live `Data`
    /// frame can legitimately overlap; without a position on every frame the
    /// client cannot tell an overlap from new output and would write the same
    /// bytes to the parser twice. It also makes a gap detectable at all rather
    /// than silently corrupting the grid.
    Data {
        channel: ChannelId,
        from: u64,
        bytes: Vec<u8>,
    },
    /// The channel's process finished. `status` is the raw wait status if known.
    Exited {
        channel: ChannelId,
        status: Option<i32>,
    },
    /// The pane can resume: here are the bytes it missed, from `from` onwards.
    /// Invisible to the user — this is the good case.
    Replay {
        channel: ChannelId,
        from: u64,
        bytes: Vec<u8>,
    },
    /// The pane is alive and too far behind to replay, but here is what its screen
    /// looks like right now.
    ///
    /// This is what makes a long absence useful rather than merely safe. Replay is
    /// bounded by the log, so any reattach after more than a few minutes of a busy
    /// agent falls off the end of it — and a `Desync` alone leaves the pane blank
    /// until the application happens to redraw, which for an idle full-screen agent
    /// may be never. The screen is re-derived on the host, where the bytes are.
    ///
    /// Scrollback is *not* included and the client must mark it truncated: this is
    /// the current screen, not the history behind it.
    Snapshot {
        channel: ChannelId,
        /// Stream position the snapshot reflects. The client continues from here.
        out_offset: u64,
        /// ANSI that reconstructs the screen, including the mode switch when the
        /// content lives on the alternate screen.
        ansi: String,
    },
    /// The pane is alive, the client is too far behind to be caught up without a
    /// gap, and no snapshot could be produced. It must mark its scrollback truncated
    /// and never continue as if nothing happened: a hole fed to a VT parser is
    /// permanent corruption, not a missing frame.
    Desync {
        channel: ChannelId,
        /// Oldest offset still held, for diagnostics.
        available_from: u64,
        /// Where the live stream is now.
        out_offset: u64,
    },
    /// The answer to an `Exec`.
    ExecResult {
        id: u64,
        /// `None` when the process was killed by a signal or never started.
        code: Option<i32>,
        stdout: Vec<u8>,
        stderr: Vec<u8>,
    },
    /// The pane no longer exists.
    Gone {
        channel: ChannelId,
        reason: GoneReason,
    },
}

/// Outcome of comparing two protocol versions.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Negotiation {
    Ok,
    /// The peer is too old for this build to talk to.
    PeerTooOld {
        peer: u32,
        min_supported: u32,
    },
    /// The peer speaks a newer protocol than this build understands.
    PeerTooNew {
        peer: u32,
        ours: u32,
    },
}

/// Decide whether we can talk to a peer advertising `peer_version`.
///
/// Accepts a range rather than requiring equality, so a host provisioned by an
/// older herdr keeps working until it is convenient to re-provision it. Failure
/// names both versions, because "incompatible" without numbers is the least
/// actionable possible message when N hosts are involved.
pub fn negotiate(peer_version: u32) -> Negotiation {
    if peer_version < MIN_SUPPORTED_HOST_PROTOCOL_VERSION {
        Negotiation::PeerTooOld {
            peer: peer_version,
            min_supported: MIN_SUPPORTED_HOST_PROTOCOL_VERSION,
        }
    } else if peer_version > HOST_PROTOCOL_VERSION {
        Negotiation::PeerTooNew {
            peer: peer_version,
            ours: HOST_PROTOCOL_VERSION,
        }
    } else {
        Negotiation::Ok
    }
}

/// Whether a framing error is worth retrying.
///
/// A truncated or failed read is a transport problem and a redial may fix it. A
/// decode failure or an oversized frame means the two sides disagree about the
/// bytes on the wire; retrying that forever would spin. Distinguishing them is
/// what keeps reconnect from becoming an infinite loop.
pub fn framing_error_is_retryable(error: &FramingError) -> bool {
    match error {
        FramingError::Io(_) | FramingError::UnexpectedEof => true,
        FramingError::Bincode(_) | FramingError::Oversized { .. } => false,
    }
}

pub fn write_frame<W: std::io::Write, M: Serialize>(
    writer: &mut W,
    message: &M,
) -> Result<(), FramingError> {
    crate::protocol::wire::write_message(writer, message)
}

pub fn read_frame<R: std::io::Read, M: for<'de> Deserialize<'de>>(
    reader: &mut R,
) -> Result<M, FramingError> {
    crate::protocol::wire::read_message(reader, MAX_HOST_FRAME_SIZE)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn spec() -> SpawnSpec {
        SpawnSpec {
            argv: vec!["bash".into(), "-lc".into(), "echo hi".into()],
            cwd: Some("/work".into()),
            env: vec![("HERDR_ENV".into(), "1".into())],
            rows: 24,
            cols: 80,
        }
    }

    #[test]
    fn to_host_messages_round_trip() {
        let messages = vec![
            ToHost::Hello {
                version: HOST_PROTOCOL_VERSION,
            },
            ToHost::Spawn {
                channel: 7,
                spec: spec(),
            },
            ToHost::Data {
                channel: 7,
                bytes: b"ls -la\n".to_vec(),
            },
            ToHost::Resize {
                channel: 7,
                rows: 40,
                cols: 120,
                cell_width_px: 8,
                cell_height_px: 16,
            },
            ToHost::Shutdown { channel: 7 },
        ];

        for message in messages {
            let mut buffer = Vec::new();
            write_frame(&mut buffer, &message).unwrap();
            let decoded: ToHost = read_frame(&mut buffer.as_slice()).unwrap();
            assert_eq!(decoded, message);
        }
    }

    #[test]
    fn from_host_messages_round_trip() {
        let messages = vec![
            FromHost::Welcome {
                version: HOST_PROTOCOL_VERSION,
                host_epoch: 42,
            },
            FromHost::Spawned {
                channel: 1,
                pid: 4242,
            },
            FromHost::SpawnFailed {
                channel: 1,
                message: "no such directory".into(),
            },
            FromHost::Data {
                channel: 1,
                from: 0,
                bytes: vec![0x1b, b'[', b'2', b'J'],
            },
            FromHost::Exited {
                channel: 1,
                status: Some(0),
            },
            FromHost::Exited {
                channel: 1,
                status: None,
            },
        ];

        for message in messages {
            let mut buffer = Vec::new();
            write_frame(&mut buffer, &message).unwrap();
            let decoded: FromHost = read_frame(&mut buffer.as_slice()).unwrap();
            assert_eq!(decoded, message);
        }
    }

    #[test]
    fn several_frames_share_one_stream_without_bleeding() {
        // Byte streams are what this protocol is for, so back-to-back frames
        // must decode independently rather than as one blob.
        let mut buffer = Vec::new();
        let mut at = 0u64;
        for chunk in [&b"one"[..], &b"two"[..], &b"three"[..]] {
            write_frame(
                &mut buffer,
                &FromHost::Data {
                    channel: 3,
                    from: at,
                    bytes: chunk.to_vec(),
                },
            )
            .unwrap();
            at += chunk.len() as u64;
        }

        let mut reader = buffer.as_slice();
        let mut seen = Vec::new();
        for _ in 0..3 {
            let FromHost::Data { from, bytes, .. } =
                read_frame::<_, FromHost>(&mut reader).unwrap()
            else {
                panic!("expected data frames");
            };
            seen.push((from, bytes));
        }
        // Positions as well as payloads: the offsets are what a reconnecting
        // client reconciles against, so a frame that decodes with the wrong `from`
        // is worse than one that fails to decode at all.
        assert_eq!(
            seen,
            vec![
                (0, b"one".to_vec()),
                (3, b"two".to_vec()),
                (6, b"three".to_vec()),
            ]
        );
    }

    #[test]
    fn binary_output_survives_intact() {
        // PTY output is arbitrary bytes: escape sequences, invalid UTF-8, NULs.
        // Anything that assumes text here would corrupt a real terminal stream.
        let bytes: Vec<u8> = (0u8..=255).chain([0x1b, 0x00, 0xff]).collect();
        let message = FromHost::Data {
            channel: 9,
            from: 12_345,
            bytes: bytes.clone(),
        };

        let mut buffer = Vec::new();
        write_frame(&mut buffer, &message).unwrap();
        let decoded: FromHost = read_frame(&mut buffer.as_slice()).unwrap();
        assert_eq!(decoded, message);
    }

    #[test]
    fn the_host_epoch_survives_the_wire() {
        // Everything about telling "link died" from "host restarted" keys on this
        // value, so it must round-trip exactly rather than approximately.
        let message = FromHost::Welcome {
            version: HOST_PROTOCOL_VERSION,
            host_epoch: u64::MAX - 7,
        };
        let mut buffer = Vec::new();
        write_frame(&mut buffer, &message).unwrap();
        let decoded: FromHost = read_frame(&mut buffer.as_slice()).unwrap();
        assert_eq!(decoded, message);
    }

    #[test]
    fn version_negotiation_accepts_a_range_not_just_equality() {
        assert_eq!(negotiate(HOST_PROTOCOL_VERSION), Negotiation::Ok);
        assert_eq!(
            negotiate(MIN_SUPPORTED_HOST_PROTOCOL_VERSION),
            Negotiation::Ok
        );
    }

    #[test]
    fn version_negotiation_names_both_sides_when_it_fails() {
        // With many hosts, "incompatible" without numbers is unactionable.
        assert_eq!(
            negotiate(HOST_PROTOCOL_VERSION + 5),
            Negotiation::PeerTooNew {
                peer: HOST_PROTOCOL_VERSION + 5,
                ours: HOST_PROTOCOL_VERSION,
            }
        );
        assert_eq!(
            negotiate(MIN_SUPPORTED_HOST_PROTOCOL_VERSION - 1),
            Negotiation::PeerTooOld {
                peer: MIN_SUPPORTED_HOST_PROTOCOL_VERSION - 1,
                min_supported: MIN_SUPPORTED_HOST_PROTOCOL_VERSION,
            }
        );
    }

    #[test]
    fn transport_errors_retry_but_disagreement_does_not() {
        assert!(framing_error_is_retryable(&FramingError::UnexpectedEof));
        assert!(framing_error_is_retryable(&FramingError::Io(
            std::io::Error::other("reset")
        )));
        // Retrying a decode failure would spin forever: the bytes will not
        // become decodable on a second attempt.
        assert!(!framing_error_is_retryable(&FramingError::Bincode(
            "bad tag".into()
        )));
        assert!(!framing_error_is_retryable(&FramingError::Oversized {
            claimed: usize::MAX,
            max: MAX_HOST_FRAME_SIZE,
        }));
    }

    #[test]
    fn an_oversized_length_prefix_is_refused_without_allocating() {
        // A corrupted prefix must not turn into a huge allocation.
        let mut buffer = Vec::new();
        buffer.extend_from_slice(&u32::MAX.to_le_bytes());
        let result = read_frame::<_, FromHost>(&mut buffer.as_slice());
        assert!(matches!(result, Err(FramingError::Oversized { .. })));
    }

    #[test]
    fn a_truncated_frame_reports_eof_rather_than_garbage() {
        let mut buffer = Vec::new();
        write_frame(
            &mut buffer,
            &FromHost::Data {
                channel: 1,
                from: 0,
                bytes: vec![1, 2, 3, 4, 5],
            },
        )
        .unwrap();
        buffer.truncate(buffer.len() - 2);

        let result = read_frame::<_, FromHost>(&mut buffer.as_slice());
        assert!(
            matches!(result, Err(FramingError::UnexpectedEof)),
            "expected EOF, got {result:?}"
        );
    }
}
