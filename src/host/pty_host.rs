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
// No `Debug`: the shadow terminal is an opaque VT handle, and a whole grid is not
// something anyone wants in a log line anyway.
struct OutputLog {
    /// Offset of the oldest byte still held.
    start: u64,
    /// Total bytes ever produced on this channel.
    end: u64,
    buffer: std::collections::VecDeque<u8>,
    capacity: usize,
    /// Whether live output for this channel may go to the attached client yet.
    ///
    /// Cleared when a client goes away and set again only when that channel has
    /// been answered in an `Attach`. Without it a reconnecting client can receive a
    /// live frame from beyond its offset *before* the replay that would have filled
    /// the space, and report a gap for bytes that were about to arrive — a marker
    /// claiming loss where there was none, which is worse than no marker at all
    /// because it teaches the user to distrust the real ones.
    ///
    /// Lives in the log, and is read and written under the log's own lock, because
    /// that lock is also what orders appends against sends: the check and the append
    /// happen together, so no byte can fall between the two.
    ready: bool,
    /// Shadow of this channel's visible screen, for the snapshot a client gets when
    /// it has fallen too far behind to be caught up by replay.
    ///
    /// A second VT parser is a cost worth naming: every byte is parsed twice, once
    /// here and once by the client that owns the real grid. It buys the only thing
    /// that makes a long absence useful rather than merely safe — replay is bounded
    /// by the log, so any reattach after more than a few minutes of a busy agent
    /// falls off the end of it, and without a screen to send the pane comes back
    /// blank until the application happens to redraw. For an idle full-screen agent
    /// that may be never.
    ///
    /// The usual hazard with two emulators is that they disagree. Here they are the
    /// same code in the same binary at the same vendored VT version, and a host whose
    /// version does not match is refused at the handshake rather than trusted.
    ///
    /// It lives in the log rather than beside it because one lock has to order both.
    /// A snapshot is only usable if the offset sent with it is exactly what the
    /// screen has consumed; two locks would let those drift, and the difference would
    /// be output silently missing from a restored pane.
    ///
    /// `None` when a shadow could not be created. Losing the snapshot degrades a
    /// reattach to `Desync`; failing the spawn would lose the pane.
    screen: Option<crate::ghostty::Terminal>,
    /// Bytes that fell out of the memory ring, kept on disk so a longer absence can
    /// still be replayed exactly instead of resolving to a snapshot.
    ///
    /// Which agent the host should match when detecting on this channel.
    ///
    /// Beside the screen and under the same lock, because a detection is only
    /// meaningful paired with the screen it was read from — separating them would let
    /// an agent change land between the read and the match.
    detect_agent: Option<crate::detect::Agent>,
    /// The last result sent, so only changes go on the wire.
    last_detected: Option<(crate::detect::AgentState, crate::detect::BlockerKind, bool)>,
    /// `None` when spooling is off or has failed. Losing it is always survivable: the
    /// client gets a `Desync` or a snapshot, which is what it would have got anyway.
    spool: Option<Spool>,
}

/// The part of a channel's output that no longer fits in memory.
///
/// Append-only, and read back only when a client reattaches far behind. Deliberately
/// simple: it exists to widen the replay window, and a design that could corrupt the
/// window would be worse than not having one.
struct Spool {
    file: std::fs::File,
    path: std::path::PathBuf,
    /// Offset of the first byte in the file.
    start: u64,
    /// Bytes currently in the file.
    len: u64,
    /// Cap. Past this the file is discarded whole and starts again — see `append`.
    capacity: u64,
}

impl Spool {
    /// Write bytes that have just aged out of the ring.
    ///
    /// Returns whether the spool is still usable. Any write failure gives up on
    /// spooling for this channel rather than propagating: the log's job is to keep the
    /// pane's output flowing, and a full disk must not take an agent down.
    fn append(&mut self, bytes: &[u8]) -> bool {
        use std::io::Write;

        // Over the cap the whole file is dropped and started again, rather than
        // rewritten to drop a prefix. Rewriting means copying the remainder on every
        // overflow, which on a busy pane is continuous IO on a machine herdr does not
        // own. The cost is that the replay window collapses at once instead of sliding
        // — and a client that lands in that gap gets a snapshot, which is exactly what
        // it would have got with no spool at all.
        if self.len.saturating_add(bytes.len() as u64) > self.capacity {
            if self.file.set_len(0).is_err() {
                return false;
            }
            if std::io::Seek::seek(&mut self.file, std::io::SeekFrom::Start(0)).is_err() {
                return false;
            }
            self.start = self.start.saturating_add(self.len);
            self.len = 0;
        }
        if self.file.write_all(bytes).is_err() {
            return false;
        }
        self.len += bytes.len() as u64;
        true
    }

    /// Bytes from `offset` to the end of the spool, or `None` if it does not hold them.
    fn since(&self, offset: u64) -> Option<Vec<u8>> {
        use std::io::{Read, Seek, SeekFrom};

        if offset < self.start || offset > self.start + self.len {
            return None;
        }
        let skip = offset - self.start;
        let mut file = self.file.try_clone().ok()?;
        file.seek(SeekFrom::Start(skip)).ok()?;
        let mut out = Vec::with_capacity((self.len - skip) as usize);
        file.take(self.len - skip).read_to_end(&mut out).ok()?;
        Some(out)
    }
}

impl Drop for Spool {
    fn drop(&mut self) {
        // Raw PTY output is whatever the agent printed, which routinely includes
        // things nobody wants left on disk. It lives exactly as long as the channel.
        let _ = std::fs::remove_file(&self.path);
    }
}

/// How much of each channel's output may be kept on disk.
///
/// Zero disables spooling entirely, which is the right answer for anyone who would
/// rather not have terminal output written to a host's filesystem at all.
fn spool_capacity() -> u64 {
    std::env::var("HERDR_PTY_HOST_SPOOL_BYTES")
        .ok()
        .and_then(|raw| raw.parse().ok())
        .unwrap_or(32 * 1024 * 1024)
}

/// Where spool files live.
///
/// Deliberately NOT `XDG_RUNTIME_DIR`. On a container that is tmpfs, which is charged
/// to the cgroup memory limit — so a spool meant to protect against losing output would
/// instead get the workspace OOM-killed, destroying the very agents it exists for.
/// `~/.cache` is on the persistent volume on the workspaces this is built for.
fn spool_dir() -> Option<std::path::PathBuf> {
    let home = std::env::var_os("HOME")?;
    Some(std::path::PathBuf::from(home).join(".cache/herdr/spool"))
}

/// Create a spool file for one channel, or `None` if spooling is unavailable.
fn open_spool(channel: ChannelId) -> Option<Spool> {
    use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt};

    let capacity = spool_capacity();
    if capacity == 0 {
        return None;
    }
    let dir = spool_dir()?;
    std::fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(&dir)
        .ok()?;

    // Per process as well as per channel: two daemons must not share a file, and a
    // stale file from a previous daemon must not be read as this one's history.
    let path = dir.join(format!("{}-{channel}", std::process::id()));
    let file = std::fs::OpenOptions::new()
        .create(true)
        .truncate(true)
        .read(true)
        .write(true)
        // 0600: the contents are whatever the agent printed.
        .mode(0o600)
        .open(&path)
        .ok()?;

    Some(Spool {
        file,
        path,
        start: 0,
        len: 0,
        capacity,
    })
}

impl OutputLog {
    fn new(capacity: usize) -> Self {
        Self {
            start: 0,
            end: 0,
            buffer: std::collections::VecDeque::new(),
            capacity,
            // A freshly spawned channel needs no attach: the client has known about
            // it from its first byte.
            ready: true,
            screen: None,
            detect_agent: None,
            last_detected: None,
            spool: None,
        }
    }

    /// A log that also keeps a shadow of the visible screen.
    ///
    /// Scrollback is deliberately zero: the client owns the history, and this exists
    /// only to answer "what is on the screen right now" for a client too far behind
    /// to replay. Keeping scrollback here would duplicate the client's, on a machine
    /// herdr does not own, for no gain.
    fn with_screen(capacity: usize, cols: u16, rows: u16, channel: ChannelId) -> Self {
        let mut log = Self::new(capacity);
        log.screen = crate::ghostty::Terminal::new(cols, rows, 0)
            .inspect_err(|err| tracing::warn!(err = ?err, "no screen shadow; reattach will desync"))
            .ok();
        log.spool = open_spool(channel);
        log
    }

    /// Serialize the shadow screen, if there is one with anything on it.
    fn screen_ansi(&self) -> Option<String> {
        self.screen
            .as_ref()?
            .visible_screen_ansi()
            .ok()
            .filter(|ansi| !ansi.is_empty())
    }

    fn append(&mut self, bytes: &[u8]) {
        // Fed here rather than at the call site so it cannot be forgotten and cannot
        // drift: the screen has consumed exactly the bytes the offsets account for.
        if let Some(screen) = self.screen.as_mut() {
            screen.write(bytes);
        }
        self.buffer.extend(bytes.iter().copied());
        self.end += bytes.len() as u64;
        // Trim from the front, advancing `start` by exactly what was dropped so the
        // offset arithmetic stays exact. What is dropped goes to the spool first, if
        // there is one, so it is aged out of memory rather than lost.
        while self.buffer.len() > self.capacity {
            let excess = self.buffer.len() - self.capacity;
            let evicted: Vec<u8> = self.buffer.drain(..excess).collect();
            if let Some(spool) = self.spool.as_mut() {
                // A spool that cannot be written is dropped entirely rather than left
                // half-written: a file with a hole in it would replay a hole, and a
                // hole fed to a VT parser is permanent corruption rather than a gap.
                if !spool.append(&evicted) {
                    tracing::warn!("output spool failed; replay window is memory only");
                    self.spool = None;
                }
            }
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
            // Older than memory holds. The spool may still have it, in which case the
            // answer is the spooled tail followed by everything in the ring — the two
            // are contiguous by construction, since the spool is written from exactly
            // what the ring evicts.
            let spool = self.spool.as_ref()?;
            let mut out = spool.since(offset)?;
            out.extend(self.buffer.iter().copied());
            return Some(out);
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
type SharedOut = Arc<Outbox>;

/// How many frames may be queued for one channel before its oldest are dropped.
///
/// At the 8 KiB read chunk this is about half a megabyte in flight per pane. Large
/// enough that an ordinary burst never drops anything; small enough that twenty panes
/// cannot pin ten megabytes of unsent output.
const MAX_QUEUED_FRAMES_PER_CHANNEL: usize = 64;

/// Everything waiting to go to the attached client, and the thread that writes it.
///
/// This exists because writing directly from each channel's reader thread means one
/// slow client stalls every pane. A reader would block on the socket while holding the
/// shared writer, so a single pane streaming a build log stops the other nineteen —
/// head-of-line blocking across channels, which no amount of buffering in the log
/// fixes because the log is about memory, not about the client's read rate.
///
/// So readers only ever enqueue, and one writer drains round-robin.
struct Outbox {
    inner: Mutex<OutboxInner>,
    /// The socket itself, behind its OWN lock.
    ///
    /// Separate from the queue on purpose, and the separation is the whole point: a
    /// client whose socket buffer has filled blocks the writer mid-write, and if that
    /// happened under the queue lock then every reader enqueuing, every new client
    /// attaching, and every detach would block behind it — the daemon stops answering
    /// anyone, permanently, and each new connection just adds another stuck process.
    sink: Mutex<Option<Box<dyn Write + Send>>>,
    /// Signals the writer that there is work, or that it should stop.
    ready: std::sync::Condvar,
    /// Signals waiters that everything queued has been written.
    drained: std::sync::Condvar,
}

struct OutboxInner {
    /// Whether a client is attached. Output produced when none is is dropped rather
    /// than queued: the log holds it, and buffering for an absent client without bound
    /// is how a daemon gets OOM-killed.
    ///
    /// A flag rather than the writer itself, so asking "is anyone there" never waits
    /// behind a socket write.
    attached: bool,
    /// Bumped every time a client attaches or detaches.
    ///
    /// The writer takes the socket OUT while it writes, so a detach that happens
    /// meanwhile finds nothing to drop. The generation is how it knows, on finishing,
    /// whether the socket it holds still belongs to the current client — restoring a
    /// stale one would hand the next client the previous client's connection.
    generation: u64,
    /// Frames belonging to no channel — the handshake, exec answers. Never dropped.
    control: std::collections::VecDeque<FromHost>,
    /// Per channel, in order. Ordered map so the round-robin is deterministic.
    channels: std::collections::BTreeMap<ChannelId, std::collections::VecDeque<FromHost>>,
    /// Where the last round-robin pass stopped, so no channel is served twice before
    /// another is served once.
    cursor: ChannelId,
    /// Bytes dropped per channel, so a flooding pane is attributable rather than
    /// merely suspected.
    dropped: HashMap<ChannelId, u64>,
    stop: bool,
}

impl Outbox {
    fn new() -> Arc<Self> {
        Arc::new(Self {
            sink: Mutex::new(None),
            inner: Mutex::new(OutboxInner {
                attached: false,
                generation: 0,
                control: std::collections::VecDeque::new(),
                channels: std::collections::BTreeMap::new(),
                cursor: 0,
                dropped: HashMap::new(),
                stop: false,
            }),
            ready: std::sync::Condvar::new(),
            drained: std::sync::Condvar::new(),
        })
    }

    /// Wait until everything queued has been written, or `timeout` passes.
    ///
    /// Needed because the writer is asynchronous and some frames are the last thing a
    /// client will ever hear: refusing a version mismatch means sending the `Welcome`
    /// that says which version, then closing. Returning without draining would close
    /// first and leave the client to time out with no idea why.
    fn drain(&self, timeout: std::time::Duration) {
        let deadline = std::time::Instant::now() + timeout;
        let Ok(mut inner) = self.inner.lock() else {
            return;
        };
        while inner.attached && (!inner.control.is_empty() || inner.has_channel_work()) {
            let Some(remaining) = deadline.checked_duration_since(std::time::Instant::now()) else {
                return;
            };
            let Ok((next, _)) = self.drained.wait_timeout(inner, remaining) else {
                return;
            };
            inner = next;
        }
    }

    fn install(&self, writer: Box<dyn Write + Send>) {
        if let Ok(mut sink) = self.sink.lock() {
            *sink = Some(writer);
        }
        if let Ok(mut inner) = self.inner.lock() {
            inner.attached = true;
            inner.generation += 1;
        }
        self.ready.notify_all();
    }

    /// Detach the client and discard everything queued for it.
    ///
    /// The queued frames are stale the moment the client goes: the next one attaches at
    /// its own offset and is answered from the log, so delivering leftovers would put
    /// frames in front of that answer and manufacture the very gap the ordering rules
    /// exist to prevent.
    fn detach(&self) {
        if let Ok(mut inner) = self.inner.lock() {
            inner.attached = false;
            inner.generation += 1;
            inner.control.clear();
            inner.channels.clear();
        }
        // `try_lock`, never `lock`. The writer holds this while it is blocked inside a
        // write to a client that stopped reading — which is precisely the case this
        // function has to survive. Failing to take it is fine: the socket is in the
        // writer's hands, and the generation bump above means it will be dropped rather
        // than restored when that write finally returns.
        if let Ok(mut sink) = self.sink.try_lock() {
            *sink = None;
        }
        self.drained.notify_all();
    }

    fn shutdown(&self) {
        if let Ok(mut inner) = self.inner.lock() {
            inner.stop = true;
        }
        self.ready.notify_all();
    }

    /// Bytes dropped for a channel because it outran the client.
    fn dropped_bytes(&self, channel: ChannelId) -> u64 {
        self.inner
            .lock()
            .ok()
            .and_then(|inner| inner.dropped.get(&channel).copied())
            .unwrap_or(0)
    }
}

/// Which channel a frame belongs to, if any.
///
/// Everything about a channel shares that channel's queue so it stays in order with its
/// output. A `Replay` overtaken by the `Data` that follows it would look to the client
/// exactly like the gap the resume ordering was built to rule out.
fn frame_channel(message: &FromHost) -> Option<ChannelId> {
    match message {
        FromHost::Data { channel, .. }
        | FromHost::Spawned { channel, .. }
        | FromHost::SpawnFailed { channel, .. }
        | FromHost::Exited { channel, .. }
        | FromHost::Replay { channel, .. }
        | FromHost::Snapshot { channel, .. }
        | FromHost::Desync { channel, .. }
        | FromHost::Detected { channel, .. }
        | FromHost::Gone { channel, .. } => Some(*channel),
        FromHost::Welcome { .. } | FromHost::ExecResult { .. } => None,
    }
}

/// Run the writer until the daemon stops.
///
/// Frames are taken under the lock and written outside it, so a blocked socket never
/// holds up the readers that are enqueuing.
fn run_outbox(out: SharedOut) {
    loop {
        let batch = {
            let Ok(mut inner) = out.inner.lock() else {
                return;
            };
            loop {
                if inner.stop {
                    return;
                }
                if inner.attached && (!inner.control.is_empty() || inner.has_channel_work()) {
                    break;
                }
                let Ok(next) = out.ready.wait(inner) else {
                    return;
                };
                inner = next;
            }
            inner.take_batch()
        };
        if batch.is_empty() {
            continue;
        }

        // The socket is TAKEN OUT and written to holding no lock at all. A client that
        // has stopped reading blocks this for as long as it likes; if anything else had
        // to wait on it — a reader enqueuing, a new client attaching, a detach — the
        // daemon would stop answering anyone, permanently, and every later connection
        // would just add another stuck process. That is not hypothetical: it is what a
        // half-dead ssh peer did to a real host.
        let (mut writer, generation) = {
            let Ok(mut sink) = out.sink.lock() else {
                return;
            };
            let Ok(inner) = out.inner.lock() else {
                return;
            };
            match sink.take() {
                Some(writer) => (writer, inner.generation),
                // Detached while this batch was in flight; the frames belong to a client
                // that is gone.
                None => continue,
            }
        };

        let mut failed = false;
        for message in &batch {
            if write_frame(&mut writer, message).is_err() {
                failed = true;
                break;
            }
        }
        if !failed && writer.flush().is_err() {
            failed = true;
        }

        {
            let Ok(mut inner) = out.inner.lock() else {
                return;
            };
            // Only give it back if it is still the current client's socket. A detach or
            // a new attach while the write was in flight means this one is stale, and
            // restoring it would hand the next client the previous one's connection.
            let still_current = inner.generation == generation && !failed;
            if still_current {
                if let Ok(mut sink) = out.sink.lock() {
                    *sink = Some(writer);
                }
            } else if failed && inner.generation == generation {
                inner.attached = false;
                inner.control.clear();
                inner.channels.clear();
            }
        }

        if let Ok(inner) = out.inner.lock() {
            if inner.control.is_empty() && !inner.has_channel_work() {
                out.drained.notify_all();
            }
        }
    }
}

impl OutboxInner {
    fn has_channel_work(&self) -> bool {
        self.channels.values().any(|queue| !queue.is_empty())
    }

    /// One pass: all control frames, then at most one frame per channel, resuming
    /// after wherever the last pass stopped.
    ///
    /// One frame each rather than draining a channel dry is the whole point — draining
    /// would let a flooding pane keep the writer to itself for as long as it can
    /// produce.
    fn take_batch(&mut self) -> Vec<FromHost> {
        let mut batch: Vec<FromHost> = self.control.drain(..).collect();

        let ids: Vec<ChannelId> = self.channels.keys().copied().collect();
        let start = ids.iter().position(|id| *id >= self.cursor).unwrap_or(0);
        for step in 0..ids.len() {
            let id = ids[(start + step) % ids.len()];
            if let Some(queue) = self.channels.get_mut(&id) {
                if let Some(message) = queue.pop_front() {
                    batch.push(message);
                }
            }
        }
        if let Some(last) = ids.last() {
            self.cursor = self.cursor.wrapping_add(1).min(last.wrapping_add(1));
        }
        self.channels.retain(|_, queue| !queue.is_empty());
        batch
    }
}

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
        let out: SharedOut = Outbox::new();
        // One writer for the whole daemon, so no reader ever touches the socket.
        {
            let out = Arc::clone(&out);
            std::thread::spawn(move || run_outbox(out));
        }
        let channels: Arc<Mutex<HashMap<ChannelId, Channel>>> =
            Arc::new(Mutex::new(HashMap::new()));
        // Detection for whichever channels the client asks the host to watch.
        {
            let out = Arc::clone(&out);
            let channels = Arc::clone(&channels);
            std::thread::spawn(move || run_host_detection(channels, out));
        }

        // Exits are reported from reader threads; a channel keeps that off the
        // request path so a wedged reader cannot stall input handling.
        let (exit_tx, exit_rx) = mpsc::channel::<(ChannelId, Option<i32>)>();
        {
            let out = Arc::clone(&out);
            let channels = Arc::clone(&channels);
            std::thread::spawn(move || {
                while let Ok((channel, status)) = exit_rx.recv() {
                    // Reported once, where it is attributable: a pane that outran the
                    // client is a fact about that pane, and without naming it the only
                    // symptom is a truncation marker with no cause.
                    let dropped = out.dropped_bytes(channel);
                    if dropped > 0 {
                        tracing::info!(
                            channel,
                            dropped,
                            "pane produced output faster than the client read it"
                        );
                    }
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
    // One-shot: nothing else will be written, so stop the writer rather than leave it
    // parked on a condvar for the life of the process.
    daemon.out.shutdown();
    Ok(())
}

/// Serve one attached client. Returns when its input closes; channels survive.
fn serve_client<R: Read>(
    daemon: &Daemon,
    mut input: R,
    output: Box<dyn Write + Send>,
) -> std::io::Result<()> {
    daemon.out.install(output);
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
    // Anything still queued is the last thing this client will hear — a refusal after
    // a version mismatch is exactly that — so let the writer finish before the socket
    // goes. Bounded, because a client that has already vanished must not hold the
    // daemon up.
    daemon.out.drain(std::time::Duration::from_secs(2));
    daemon.out.detach();

    // Every surviving channel must be re-attached before its output resumes. The
    // next client does not know where these panes got to, so a live frame sent
    // before it has been told would land ahead of its cursor and read as lost
    // output. The bytes are not dropped — they accumulate in each channel's log,
    // which is what the replay is drawn from.
    if let Ok(map) = daemon.channels.lock() {
        for entry in map.values() {
            let mut log = entry.log.lock().unwrap_or_else(|err| err.into_inner());
            log.ready = false;
        }
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
            let log = if let Ok(map) = channels.lock() {
                let Some(entry) = map.get(&channel) else {
                    return;
                };
                // The ioctl belongs here, on the machine that owns the PTY.
                let _ = crate::pty::fd::resize_pty_fd(
                    entry.master_fd,
                    rows,
                    cols,
                    cell_width_px,
                    cell_height_px,
                );
                Arc::clone(&entry.log)
            } else {
                return;
            };
            // The shadow screen has to follow, or a snapshot would reconstruct the
            // pane at the size it had before the last resize — subtly wrong in a way
            // that looks like the agent drawing badly rather than like a herdr bug.
            let mut log = log.lock().unwrap_or_else(|err| err.into_inner());
            if let Some(screen) = log.screen.as_mut() {
                let _ = screen.resize(cols, rows, cell_width_px, cell_height_px);
            }
        }
        ToHost::Shutdown { channel } => shutdown_channel(channels, channel),
        ToHost::Detect { channel, agent } => {
            let log = channels
                .lock()
                .ok()
                .and_then(|map| map.get(&channel).map(|entry| Arc::clone(&entry.log)));
            if let Some(log) = log {
                let mut log = log.lock().unwrap_or_else(|err| err.into_inner());
                log.detect_agent = agent.as_deref().and_then(crate::detect::parse_agent_label);
                // Forget the previous result so the next scan reports whatever the new
                // agent sees, rather than suppressing it as unchanged.
                log.last_detected = None;
            }
        }
        ToHost::Exec { id, argv, cwd } => {
            // On a thread: the read loop is what carries every pane's input, and a git
            // command on a cold repository can take seconds. Blocking here would stall
            // typing in every pane on this host.
            let out = Arc::clone(out);
            std::thread::spawn(move || {
                send(&out, &run_exec(id, &argv, cwd.as_deref()));
            });
        }
        ToHost::Attach { host_epoch, panes } => {
            for (channel, offset) in panes {
                answer_attach(out, channels, daemon_epoch, host_epoch, channel, offset);
            }
        }
    }
}

/// Answer, for one pane, whether a reconnecting client can resume — and let its
/// live output start flowing again.
///
/// Exactly one answer per pane, and the epoch is checked first: if the daemon
/// restarted then nothing from the previous epoch survived, so offsets are
/// meaningless and every pane is gone regardless of how far behind the client is.
/// Checking offsets first would let a coincidental match resume a pane whose agent
/// no longer exists, which is the worst outcome available here.
///
/// The answer is computed and sent while holding the channel's log lock, and the
/// gate on live output is opened before releasing it. That is what guarantees the
/// client sees the answer *before* any live frame for that pane: the reader thread
/// takes the same lock to append and send, so it either ran entirely before this
/// (its bytes are in the replay) or entirely after (its bytes follow the replay).
/// There is no third interleaving, which is why the client never has to guess
/// whether a frame ahead of its cursor is a gap or an overtaken replay.
fn answer_attach(
    out: &SharedOut,
    channels: &Arc<Mutex<HashMap<ChannelId, Channel>>>,
    daemon_epoch: u64,
    client_epoch: u64,
    channel: ChannelId,
    offset: u64,
) {
    if client_epoch != daemon_epoch {
        send(
            out,
            &FromHost::Gone {
                channel,
                reason: crate::host::protocol::GoneReason::HostRestarted,
            },
        );
        return;
    }

    // The log handle is cloned out so the channel table is not held while the log
    // is: one lock at a time keeps the order here trivially consistent with the
    // reader thread's.
    let log = channels
        .lock()
        .ok()
        .and_then(|map| map.get(&channel).map(|entry| Arc::clone(&entry.log)));
    let Some(log) = log else {
        // Same epoch but no such channel: its process finished while the client was
        // away.
        send(
            out,
            &FromHost::Gone {
                channel,
                reason: crate::host::protocol::GoneReason::ChildExited,
            },
        );
        return;
    };

    // Poison recovered, not treated as absence: reporting a live pane as `Gone`
    // would tell the user their agent died when it is still running.
    let mut log = log.lock().unwrap_or_else(|err| err.into_inner());
    let answer = match log.since(offset) {
        Some(bytes) => FromHost::Replay {
            channel,
            from: offset,
            bytes,
        },
        // Too far behind to replay. A screen is far better than nothing here: it is
        // what the pane actually looks like, whereas a bare desync leaves it blank
        // until the application redraws — which an idle full-screen agent may never
        // do. Falls back to the desync when there is no shadow to serialize.
        None => match log.screen_ansi() {
            Some(ansi) => FromHost::Snapshot {
                channel,
                out_offset: log.end,
                ansi,
            },
            None => FromHost::Desync {
                channel,
                available_from: log.start,
                out_offset: log.end,
            },
        },
    };
    send(out, &answer);
    log.ready = true;
}

/// How often the host re-reads its shadow screens looking for a state change.
///
/// Matches the local cadence it replaces. Faster would spend more to learn the same
/// thing; slower would make a pane look busy after it stopped.
const HOST_DETECT_INTERVAL: std::time::Duration = std::time::Duration::from_millis(300);

/// Watch every channel that has been asked for, and report state changes.
///
/// One thread for the whole daemon rather than one per channel: the work is a short
/// screen read and a regex pass, and a thread per pane would cost more in scheduling
/// than the matching does.
fn run_host_detection(channels: Arc<Mutex<HashMap<ChannelId, Channel>>>, out: SharedOut) {
    loop {
        std::thread::sleep(HOST_DETECT_INTERVAL);

        let logs: Vec<(ChannelId, Arc<Mutex<OutputLog>>)> = match channels.lock() {
            Ok(map) => map
                .iter()
                .map(|(channel, entry)| (*channel, Arc::clone(&entry.log)))
                .collect(),
            Err(_) => return,
        };
        if logs.is_empty() {
            continue;
        }

        for (channel, log) in logs {
            let mut log = log.lock().unwrap_or_else(|err| err.into_inner());
            let Some(agent) = log.detect_agent else {
                continue;
            };
            let Some(screen) = log.screen.as_ref() else {
                continue;
            };
            let Some(text) = visible_screen_text(screen) else {
                continue;
            };

            let detection = crate::detect::detect_agent(Some(agent), &text);
            let Some(current) = detection_worth_reporting(&detection, log.last_detected) else {
                continue;
            };
            log.last_detected = Some(current);
            drop(log);

            send(
                &out,
                &FromHost::Detected {
                    channel,
                    state: wire_state(current.0),
                    blocker: wire_blocker(current.1),
                    fault: current.2,
                },
            );
        }
    }
}

/// Whether a detection should go on the wire, and what to remember if so.
///
/// Two reasons to stay quiet, and they are different. A screen the agent has marked
/// skippable is a transcript viewer or a pager — not live state — and reporting from it
/// would overwrite what the agent is actually doing with whatever the user happens to be
/// scrolled to. An unchanged result is simply not news, and sending it anyway would move
/// the cost onto the wire rather than removing it, which is the opposite of the point.
fn detection_worth_reporting(
    detection: &crate::detect::AgentDetection,
    last: Option<(crate::detect::AgentState, crate::detect::BlockerKind, bool)>,
) -> Option<(crate::detect::AgentState, crate::detect::BlockerKind, bool)> {
    if detection.skip_state_update {
        return None;
    }
    let current = (detection.state, detection.blocker, detection.fault);
    (last != Some(current)).then_some(current)
}

/// The shadow screen as plain text, which is what detection matches against.
fn visible_screen_text(terminal: &crate::ghostty::Terminal) -> Option<String> {
    let rows = terminal.rows().ok()?;
    let cols = terminal.cols().ok()?;
    if rows == 0 || cols == 0 {
        return None;
    }
    terminal
        .read_text_viewport(
            (0, 0),
            (cols.saturating_sub(1), u32::from(rows.saturating_sub(1))),
            true,
        )
        .ok()
}

fn wire_state(state: crate::detect::AgentState) -> crate::host::protocol::DetectedState {
    use crate::host::protocol::DetectedState;
    match state {
        crate::detect::AgentState::Idle => DetectedState::Idle,
        crate::detect::AgentState::Working => DetectedState::Working,
        crate::detect::AgentState::Blocked => DetectedState::Blocked,
        crate::detect::AgentState::Unknown => DetectedState::Unknown,
    }
}

fn wire_blocker(blocker: crate::detect::BlockerKind) -> crate::host::protocol::DetectedBlocker {
    use crate::host::protocol::DetectedBlocker;
    match blocker {
        crate::detect::BlockerKind::Permission => DetectedBlocker::Permission,
        crate::detect::BlockerKind::Question => DetectedBlocker::Question,
        crate::detect::BlockerKind::Selection => DetectedBlocker::Selection,
        crate::detect::BlockerKind::Unknown => DetectedBlocker::Unknown,
    }
}

/// Run one command and describe what happened, without ever failing to answer.
///
/// An `Exec` that produces no reply would hang the caller, so every path here — a
/// missing binary, a bad working directory — comes back as a result with the failure in
/// `stderr` rather than as silence.
fn run_exec(id: u64, argv: &[String], cwd: Option<&str>) -> FromHost {
    let Some((program, args)) = argv.split_first() else {
        return FromHost::ExecResult {
            id,
            code: None,
            stdout: Vec::new(),
            stderr: b"empty argv".to_vec(),
        };
    };

    // argv is passed through as given. Nothing here builds a command line, so there is
    // no shell on this path and nothing for a branch name or a path to be quoted
    // against.
    let mut command = std::process::Command::new(program);
    command.args(args);
    if let Some(cwd) = cwd {
        command.current_dir(cwd);
    }

    match command.output() {
        Ok(output) => FromHost::ExecResult {
            id,
            code: output.status.code(),
            stdout: output.stdout,
            stderr: output.stderr,
        },
        Err(err) => FromHost::ExecResult {
            id,
            code: None,
            stdout: Vec::new(),
            stderr: err.to_string().into_bytes(),
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

    let log = Arc::new(Mutex::new(OutputLog::with_screen(
        OUTPUT_LOG_CAPACITY,
        spec.cols,
        spec.rows,
        channel,
    )));

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
                        // Recorded before sending, so output produced while nobody is
                        // attached is still replayable afterwards. The offset the log
                        // assigns is the one that goes on the wire, so the client's
                        // idea of the stream and the log's cannot drift — deriving
                        // the position on either side independently is how an
                        // off-by-one becomes silent grid corruption.
                        //
                        // The lock is held across the send as well, which is what
                        // makes this channel's wire order identical to its log order.
                        // Appending under the lock and sending outside it would let
                        // two chunks reach the client reversed, and a reversed pair
                        // reads as a gap followed by stale bytes.
                        //
                        // Poison is recovered rather than propagated: it must not stop
                        // a live pane's output, and `append` is the only mutator so no
                        // panic can leave the offsets inconsistent.
                        let mut log = log.lock().unwrap_or_else(|err| err.into_inner());
                        let from = log.end;
                        log.append(&buffer[..n]);
                        if log.ready {
                            send(
                                &out,
                                &FromHost::Data {
                                    channel,
                                    from,
                                    bytes: buffer[..n].to_vec(),
                                },
                            );
                        }
                        drop(log);
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
    let Ok(mut inner) = out.inner.lock() else {
        return;
    };
    if !inner.attached {
        // Nobody attached. Dropping is deliberate — the log holds it, and queueing for
        // an absent client without bound is how a daemon gets OOM-killed.
        return;
    }

    match frame_channel(message) {
        None => inner.control.push_back(message.clone()),
        Some(channel) => {
            let queue = inner.channels.entry(channel).or_default();
            if queue.len() >= MAX_QUEUED_FRAMES_PER_CHANNEL {
                // Only output is droppable, and the OLDEST is what goes: on a terminal
                // the newest frame is the one worth having, and stale queued output is
                // exactly what the client no longer needs. Anything else — a resume
                // answer, an exit — must not be dropped at all, so a full queue for
                // those grows rather than loses them.
                if matches!(message, FromHost::Data { .. }) {
                    let mut freed = 0u64;
                    while queue.len() >= MAX_QUEUED_FRAMES_PER_CHANNEL {
                        match queue.pop_front() {
                            Some(FromHost::Data { bytes, .. }) => freed += bytes.len() as u64,
                            // Reached something undroppable; stop rather than lose it.
                            Some(other) => {
                                queue.push_front(other);
                                break;
                            }
                            None => break,
                        }
                    }
                    if freed > 0 {
                        *inner.dropped.entry(channel).or_default() += freed;
                    }
                }
            }
            inner
                .channels
                .entry(channel)
                .or_default()
                .push_back(message.clone());
        }
    }
    drop(inner);
    out.ready.notify_all();
}

fn poisoned() -> std::io::Error {
    std::io::Error::other("pty-host channel table poisoned")
}

/// Where the daemon listens on a host. Per-user, so two accounts on one machine do
/// not collide.
fn default_socket_path() -> std::path::PathBuf {
    // Overridable so `attach` can be driven against a scratch daemon in tests. The
    // bridge is the one part of this that only a real connection exercises, so it
    // needs to be reachable without one.
    if let Some(path) = std::env::var_os("HERDR_PTY_HOST_SOCKET") {
        return std::path::PathBuf::from(path);
    }
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

    // NOT `std::io::copy`. Rust's stdout is block-buffered, and `copy` only flushes
    // when the buffer fills or the stream ends — so on a framed protocol the reply to
    // the handshake sits in the buffer while the client waits out its deadline, and
    // the connection appears to hang rather than fail. Every frame has to be pushed
    // as soon as it exists, because the far side is waiting on it before it will send
    // anything more.
    //
    // This is invisible to any test that drives the daemon's socket directly, which is
    // why it survived until a real connection tried it.
    let mut stdout = std::io::stdout().lock();
    let mut buffer = [0u8; 16 * 1024];
    loop {
        let read = match reader.read(&mut buffer) {
            Ok(0) | Err(_) => break,
            Ok(read) => read,
        };
        if stdout.write_all(&buffer[..read]).is_err() || stdout.flush().is_err() {
            break;
        }
    }
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

    /// Deterministic PRNG, so a schedule that fails is reproducible from its seed.
    /// `rand` is not a dependency and this does not need to be good randomness —
    /// only varied and repeatable.
    struct Rng(u64);

    impl Rng {
        fn next(&mut self) -> u64 {
            // xorshift64*
            let mut x = self.0;
            x ^= x >> 12;
            x ^= x << 25;
            x ^= x >> 27;
            self.0 = x;
            x.wrapping_mul(0x2545_F491_4F6C_DD1D)
        }

        fn below(&mut self, n: u64) -> u64 {
            self.next() % n.max(1)
        }
    }

    /// Models the client's VT parser: what was fed to it, and where it was told
    /// output had been lost.
    struct Parser {
        /// `Some(byte)` at every stream offset that reached the parser.
        seen: Vec<Option<u8>>,
        /// Ranges the user was told about, as `[start, end)`.
        gaps: Vec<(u64, u64)>,
        delivered: u64,
    }

    impl Parser {
        fn new() -> Self {
            Self {
                seen: Vec::new(),
                gaps: Vec::new(),
                delivered: 0,
            }
        }

        /// Apply one positioned frame exactly as the link's `deliver` would.
        fn apply(&mut self, produced: &[u8], from: u64, len: usize) {
            match crate::host::link::reconcile(self.delivered, from, len) {
                crate::host::link::Reconciled::AlreadySeen => {}
                crate::host::link::Reconciled::Write { skip, next } => {
                    self.write(produced, from + skip as u64, next);
                }
                crate::host::link::Reconciled::Gap { missing, next } => {
                    assert!(
                        missing > 0,
                        "a gap of nothing would put a marker in the pane for no reason"
                    );
                    self.gaps.push((self.delivered, from));
                    self.delivered = from;
                    self.write(produced, from, next);
                }
            }
        }

        /// Apply a `Desync`: the host cannot close the gap, so it says where the
        /// live stream is and the client jumps there.
        ///
        /// A report that is already behind the parser is ignored rather than obeyed.
        /// Live output can carry the parser past the point the host resynced to
        /// while the answer is still in flight, and jumping backwards would
        /// re-deliver bytes the parser already has.
        fn desync(&mut self, host_end: u64) {
            if host_end <= self.delivered {
                return;
            }
            self.gaps.push((self.delivered, host_end));
            self.delivered = host_end;
        }

        fn write(&mut self, produced: &[u8], from: u64, next: u64) {
            if next as usize > self.seen.len() {
                self.seen.resize(next as usize, None);
            }
            for offset in from..next {
                // The single strongest check here: a byte handed to the parser
                // twice is duplicated output on screen, and it is exactly what an
                // off-by-one in the overlap trim produces.
                assert!(
                    self.seen[offset as usize].is_none(),
                    "offset {offset} delivered twice"
                );
                self.seen[offset as usize] = Some(produced[offset as usize]);
            }
            self.delivered = next;
        }
    }

    /// Produce a chunk the way the daemon does: into the log first, taking the
    /// offset the log assigns rather than deriving it separately.
    fn produce(rng: &mut Rng, log: &mut OutputLog, produced: &mut Vec<u8>) -> (u64, usize) {
        let len = 1 + rng.below(24) as usize;
        let from = log.end;
        let chunk: Vec<u8> = (0..len).map(|_| rng.below(256) as u8).collect();
        log.append(&chunk);
        produced.extend_from_slice(&chunk);
        (from, len)
    }

    /// A log whose spool is a real file in a scratch directory.
    fn log_with_spool(capacity: usize, spool_capacity: u64, tag: &str) -> OutputLog {
        let dir =
            std::env::temp_dir().join(format!("herdr-spool-test-{}-{tag}", std::process::id()));
        let _ = std::fs::create_dir_all(&dir);
        let path = dir.join("spool");
        let file = std::fs::OpenOptions::new()
            .create(true)
            .truncate(true)
            .read(true)
            .write(true)
            .open(&path)
            .expect("spool file");
        let mut log = OutputLog::new(capacity);
        log.spool = Some(Spool {
            file,
            path,
            start: 0,
            len: 0,
            capacity: spool_capacity,
        });
        log
    }

    fn data(channel: ChannelId, from: u64, len: usize) -> FromHost {
        FromHost::Data {
            channel,
            from,
            bytes: vec![b'x'; len],
        }
    }

    /// An outbox with a writer installed, so `send` queues instead of discarding.
    fn attached_outbox() -> SharedOut {
        let out = Outbox::new();
        out.install(Box::new(std::io::sink()));
        out
    }

    fn detection(state: crate::detect::AgentState, skip: bool) -> crate::detect::AgentDetection {
        crate::detect::AgentDetection {
            state,
            skip_state_update: skip,
            visible_idle: false,
            visible_blocker: false,
            visible_working: false,
            fault: false,
            blocker: crate::detect::BlockerKind::Unknown,
        }
    }

    #[test]
    fn a_transcript_view_is_never_reported_as_live_state() {
        // Scrolling back through history is not the agent doing something. Reporting
        // from it would replace what the agent is actually doing with whatever the user
        // happens to be looking at — and on the host there is no second signal to
        // correct it with.
        assert_eq!(
            detection_worth_reporting(&detection(crate::detect::AgentState::Idle, true), None),
            None
        );
        // The same screen without the skip flag IS news.
        assert!(detection_worth_reporting(
            &detection(crate::detect::AgentState::Idle, false),
            None
        )
        .is_some());
    }

    #[test]
    fn only_a_change_is_worth_sending() {
        // Otherwise this moves the cost onto the wire instead of removing it.
        let current = detection(crate::detect::AgentState::Working, false);
        let seen = Some((
            crate::detect::AgentState::Working,
            crate::detect::BlockerKind::Unknown,
            false,
        ));
        assert_eq!(detection_worth_reporting(&current, seen), None);
        assert!(detection_worth_reporting(&current, None).is_some());
        // A different state is a change even when everything else matches.
        assert!(detection_worth_reporting(
            &detection(crate::detect::AgentState::Idle, false),
            seen
        )
        .is_some());
    }

    /// A writer that blocks until released, standing in for a client that has stopped
    /// reading — the state a half-dead ssh peer leaves behind.
    struct BlockingWriter(std::sync::Arc<(Mutex<bool>, std::sync::Condvar)>);

    impl Write for BlockingWriter {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            let (lock, cv) = &*self.0;
            let mut released = lock.lock().unwrap_or_else(|err| err.into_inner());
            while !*released {
                released = cv.wait(released).unwrap_or_else(|err| err.into_inner());
            }
            Ok(buf.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    #[test]
    fn a_client_that_stops_reading_does_not_wedge_the_whole_daemon() {
        // This is what actually happened on a real host: a client's socket filled, the
        // writer blocked mid-write, and because that write held the queue lock nothing
        // could enqueue, attach or detach ever again. Every later connection hung and
        // left another stuck process behind; only killing the daemon recovered it.
        //
        // So the property is narrow and absolute: while a write is blocked, the rest of
        // the outbox must still be usable.
        let out = Outbox::new();
        {
            let out = Arc::clone(&out);
            std::thread::spawn(move || run_outbox(out));
        }

        let gate = std::sync::Arc::new((Mutex::new(false), std::sync::Condvar::new()));
        out.install(Box::new(BlockingWriter(std::sync::Arc::clone(&gate))));
        send(&out, &data(1, 0, 8));

        // Give the writer time to pick the frame up and block inside `write`.
        std::thread::sleep(std::time::Duration::from_millis(200));

        // Everything below must complete rather than block behind that write.
        let worker = {
            let out = Arc::clone(&out);
            std::thread::spawn(move || {
                send(&out, &data(2, 0, 8));
                out.detach();
                out.install(Box::new(std::io::sink()));
                send(&out, &data(3, 0, 8));
            })
        };

        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
        while !worker.is_finished() {
            assert!(
                std::time::Instant::now() < deadline,
                "the outbox wedged behind a blocked client write"
            );
            std::thread::sleep(std::time::Duration::from_millis(20));
        }
        worker.join().expect("worker");

        // Release the stuck write so the thread can retire.
        {
            let (lock, cv) = &*gate;
            *lock.lock().unwrap() = true;
            cv.notify_all();
        }
        out.shutdown();
    }

    #[test]
    fn one_flooding_channel_cannot_starve_the_others() {
        // The bug this exists for. Writing from each reader meant a slow client blocked
        // one pane's thread while it held the shared writer, stalling every other pane
        // — twenty agents, one streaming a build log, nineteen frozen.
        let out = attached_outbox();
        for index in 0..MAX_QUEUED_FRAMES_PER_CHANNEL {
            send(&out, &data(1, index as u64, 8));
        }
        send(&out, &data(2, 0, 8));
        send(&out, &data(3, 0, 8));

        let mut inner = out.inner.lock().unwrap();
        let batch = inner.take_batch();
        let served: Vec<ChannelId> = batch.iter().filter_map(frame_channel).collect();

        // One pass serves each waiting channel once, not one channel repeatedly.
        assert!(served.contains(&2), "quiet channel starved: {served:?}");
        assert!(served.contains(&3), "quiet channel starved: {served:?}");
        assert_eq!(
            served.iter().filter(|id| **id == 1).count(),
            1,
            "the flooding channel took more than its turn: {served:?}"
        );
    }

    #[test]
    fn a_full_queue_drops_the_oldest_output_and_counts_it() {
        // On a terminal the newest frame is the one worth having, so a pane that
        // outruns the client loses its stale output rather than its current screen.
        // Safe only because the log still holds every byte: the client sees a gap,
        // marks it, and the next attach replays or snapshots.
        let out = attached_outbox();
        for index in 0..(MAX_QUEUED_FRAMES_PER_CHANNEL + 10) {
            send(&out, &data(1, index as u64 * 8, 8));
        }

        let inner = out.inner.lock().unwrap();
        assert_eq!(
            inner.channels.get(&1).map(|queue| queue.len()),
            Some(MAX_QUEUED_FRAMES_PER_CHANNEL),
            "the queue must stay bounded"
        );
        // The newest frame survived; the oldest did not.
        let last = inner.channels.get(&1).and_then(|queue| queue.back());
        assert!(
            matches!(last, Some(FromHost::Data { from, .. }) if *from == (MAX_QUEUED_FRAMES_PER_CHANNEL as u64 + 9) * 8),
            "the newest frame must be kept"
        );
        drop(inner);
        assert_eq!(
            out.dropped_bytes(1),
            80,
            "dropped bytes must be attributable"
        );
    }

    #[test]
    fn a_resume_answer_is_never_dropped_to_make_room() {
        // Output can be lost and recovered; a Replay cannot. Dropping one would leave
        // the client waiting for an answer that never comes, on a pane the host knows
        // perfectly well how to resume.
        let out = attached_outbox();
        send(
            &out,
            &FromHost::Replay {
                channel: 1,
                from: 0,
                bytes: vec![b'r'; 4],
            },
        );
        for index in 0..(MAX_QUEUED_FRAMES_PER_CHANNEL * 2) {
            send(&out, &data(1, index as u64 * 8, 8));
        }

        let inner = out.inner.lock().unwrap();
        let queue = inner.channels.get(&1).expect("queue");
        assert!(
            queue
                .iter()
                .any(|message| matches!(message, FromHost::Replay { .. })),
            "the resume answer must survive a flood"
        );
        // And it is still in front of the output that follows it, or the client would
        // read that output as a gap.
        assert!(matches!(queue.front(), Some(FromHost::Replay { .. })));
    }

    #[test]
    fn spooled_bytes_extend_the_replay_window_without_a_seam() {
        // The point of the spool: an absence longer than memory still replays exactly.
        // The seam between file and ring is where this would go wrong, so the check is
        // byte-for-byte across it rather than merely "something came back".
        let mut log = log_with_spool(8, 1024, "seam");
        let produced: Vec<u8> = (0..64u8).collect();
        for chunk in produced.chunks(5) {
            log.append(chunk);
        }

        // Everything is still replayable even though memory holds only the last 8.
        assert!(
            log.start > 0,
            "the ring must have evicted for this to mean anything"
        );
        let replayed = log.since(0).expect("spool should cover the whole stream");
        assert_eq!(
            replayed, produced,
            "replay must match byte for byte across the seam"
        );

        // And from an offset that lands inside the spooled part.
        let from_ten = log.since(10).expect("mid-spool offset");
        assert_eq!(
            from_ten,
            produced[10..],
            "a mid-spool offset must line up exactly"
        );
    }

    #[test]
    fn an_offset_older_than_the_spool_is_still_unresumable() {
        // Widening the window does not remove its edge. Past the spool the answer must
        // still be "resync", never a partial stream — a hole is worse than a snapshot.
        let mut log = log_with_spool(4, 16, "edge");
        for chunk in (0..64u8).collect::<Vec<_>>().chunks(8) {
            log.append(chunk);
        }
        assert_eq!(log.since(0), None, "beyond the spool must be unresumable");
    }

    #[test]
    fn the_spool_file_does_not_outlive_the_channel() {
        // Raw PTY output is whatever the agent printed — tokens it echoed, contents of
        // files it opened. Leaving that on a host's disk after the pane is gone turns a
        // replay buffer into a durable copy of everything, on a machine herdr does not
        // own.
        let path;
        {
            let log = log_with_spool(4, 64, "cleanup");
            path = log.spool.as_ref().expect("spool").path.clone();
            assert!(
                path.exists(),
                "the file should exist while the channel does"
            );
        }
        assert!(
            !path.exists(),
            "the spool file must be removed with the channel"
        );
    }

    #[test]
    fn a_log_with_no_spool_behaves_exactly_as_before() {
        // Spooling is optional, and turning it off must not change the contract.
        let mut log = OutputLog::new(4);
        log.append(b"abcdefgh");
        assert_eq!(log.since(0), None);
        assert_eq!(log.since(4), Some(b"efgh".to_vec()));
    }

    #[test]
    fn every_schedule_delivers_the_stream_exactly_or_reports_the_hole() {
        // The invariant the whole resume design rests on, stated as sharply as it
        // can be: for ANY interleaving of production, disconnection and replay, the
        // bytes the parser received partition the delivered range into runs that
        // match what the PTY produced and runs that were reported as lost. Nothing
        // else. A third outcome — a hole nobody was told about — is permanent grid
        // corruption with no trace left to debug from.
        //
        // The log is deliberately tiny so overflow, and therefore Desync, is the
        // common case rather than a corner one.
        for seed in 1..=300u64 {
            let mut rng = Rng(seed.wrapping_mul(0x9E37_79B9_7F4A_7C15) | 1);
            let mut log = OutputLog::new(1 + rng.below(96) as usize);
            let mut produced: Vec<u8> = Vec::new();
            let mut parser = Parser::new();
            let mut attached = true;

            for _ in 0..40 {
                match rng.below(10) {
                    0..=5 => {
                        let (from, len) = produce(&mut rng, &mut log, &mut produced);
                        if attached {
                            parser.apply(&produced, from, len);
                        }
                    }
                    6..=7 => attached = false,
                    _ => {
                        if attached {
                            continue;
                        }
                        // Reattach. The daemon answers from the offset the client
                        // asked about, and live output keeps being produced while
                        // that answer is in flight — so the answer can land
                        // *between* two live frames and partly cover ground the
                        // client has already taken. That is the case the position on
                        // every frame exists for, so the schedule has to reach it:
                        // the racing frames are split either side of the answer
                        // rather than all placed before it, because putting them all
                        // first only ever produces an answer that is wholly behind.
                        let asked = parser.delivered;
                        let answer = log.since(asked);
                        let answer_covers = log.end;
                        attached = true;

                        let racing = rng.below(3);
                        let before = rng.below(racing + 1);
                        let mut pending = Vec::new();
                        for index in 0..racing {
                            let frame = produce(&mut rng, &mut log, &mut produced);
                            if index < before {
                                parser.apply(&produced, frame.0, frame.1);
                            } else {
                                pending.push(frame);
                            }
                        }

                        match answer {
                            Some(bytes) => parser.apply(&produced, asked, bytes.len()),
                            None => parser.desync(answer_covers),
                        }
                        for (from, len) in pending {
                            parser.apply(&produced, from, len);
                        }

                        // Whether by replay or by being told to resync, a reattach
                        // must leave the client fully caught up. Without this a
                        // replay that silently returns nothing looks like success:
                        // no gap is reported, no wrong byte is delivered, and the
                        // pane simply stops updating.
                        assert_eq!(
                            parser.delivered, log.end,
                            "seed {seed}: reattach left the client behind"
                        );
                    }
                }
            }

            // Every delivered byte is the byte the PTY produced there.
            let mut written = 0u64;
            for (offset, cell) in parser.seen.iter().enumerate() {
                if let Some(byte) = cell {
                    assert_eq!(
                        *byte, produced[offset],
                        "seed {seed}: wrong byte at offset {offset}"
                    );
                    written += 1;
                }
            }

            // Gaps are non-empty, ordered and disjoint.
            let mut previous_end = 0u64;
            let mut lost = 0u64;
            for (start, end) in &parser.gaps {
                assert!(end > start, "seed {seed}: empty gap {start}..{end}");
                assert!(
                    *start >= previous_end,
                    "seed {seed}: overlapping gaps at {start}"
                );
                previous_end = *end;
                lost += end - start;
            }

            // And the two account for the consumed range exactly. If this holds
            // there is no hole the user was not told about, and nothing was shown
            // twice.
            assert_eq!(
                written + lost,
                parser.delivered,
                "seed {seed}: {written} delivered + {lost} reported lost != {} consumed",
                parser.delivered
            );
        }
    }

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
