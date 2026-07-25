//! Putting a herdr binary on a host.
//!
//! Until a release contains `pty-host`, a host needs a binary built for its own
//! os/arch, and copying it by hand to every machine is the main friction in using
//! remote workspaces at all.
//!
//! Mirrors the prepare → stream → commit shape herdr already uses for
//! `--remote`, but standalone: that implementation is tied to its own ssh session
//! types, and reusing it would mean exposing them.

use std::io::Write;
use std::path::Path;

use sha2::{Digest, Sha256};

/// Where a host's herdr lives. Matches what `HostLink` looks for when PATH does
/// not have one.
const INSTALL_SUFFIX: &str = ".local/bin/herdr";

#[derive(Debug)]
pub struct Installed {
    pub destination: String,
    pub bytes: u64,
    /// `None` when the host had no sha256 tool to check with.
    pub verified_sha256: Option<String>,
}

/// Copy `local_binary` to `target` and put it in place atomically.
///
/// Written to a temporary file next to the destination and moved into position
/// only after the bytes are verified, so a half-transferred binary is never left
/// somewhere that a connection attempt would try to run.
pub fn install_binary(target: &str, local_binary: &Path) -> std::io::Result<Installed> {
    let bytes = std::fs::metadata(local_binary)?.len();
    if bytes == 0 {
        return Err(std::io::Error::other(format!(
            "{} is empty",
            local_binary.display()
        )));
    }
    let expected = file_sha256(local_binary)?;

    // One ssh invocation: create the directory, take the bytes on stdin, verify
    // them, chmod, prove the binary actually runs, and only then move into place.
    // Doing it in one command means there is no window where a partial file sits at
    // the destination.
    //
    // The checksum only proves the bytes arrived intact — it says nothing about
    // whether they are a working herdr for this machine. A truncated file, or one
    // built for the wrong architecture, transfers perfectly and then fails at
    // connect time with something that looks unrelated. So the temporary file must
    // run before it is allowed to replace a binary that may currently be fine.
    //
    // Single-quoted for the remote shell, because ssh joins its arguments and
    // re-parses them there.
    let script = format!(
        "sh -c 'set -eu; \
         dest=\"$HOME/{suffix}\"; \
         dir=\"${{dest%/*}}\"; \
         mkdir -p \"$dir\"; \
         tmp=\"$dest.tmp.$$\"; \
         cat > \"$tmp\"; \
         if command -v sha256sum >/dev/null 2>&1; then \
           got=$(sha256sum \"$tmp\" | cut -d\" \" -f1); \
         elif command -v shasum >/dev/null 2>&1; then \
           got=$(shasum -a 256 \"$tmp\" | cut -d\" \" -f1); \
         else \
           got=unavailable; \
         fi; \
         if [ \"$got\" != unavailable ] && [ \"$got\" != {expected} ]; then \
           rm -f \"$tmp\"; echo \"checksum-mismatch:$got\" >&2; exit 1; \
         fi; \
         chmod 755 \"$tmp\"; \
         if ! \"$tmp\" --version >/dev/null 2>&1; then \
           rm -f \"$tmp\"; echo \"not-runnable\" >&2; exit 1; \
         fi; \
         mv \"$tmp\" \"$dest\"; \
         printf \"%s\\n%s\\n\" \"$dest\" \"$got\"'",
        suffix = INSTALL_SUFFIX,
        expected = expected,
    );

    let mut child = std::process::Command::new("ssh")
        .arg("-o")
        .arg("BatchMode=yes")
        .arg("-o")
        .arg("ConnectTimeout=10")
        .arg("-T")
        .arg(target)
        .arg(script)
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()?;

    // Stream from a thread: the binary is tens of megabytes, far beyond a pipe
    // buffer, so writing it all before reading would deadlock against a host that
    // is talking back.
    let source = local_binary.to_path_buf();
    let mut stdin = child
        .stdin
        .take()
        .ok_or_else(|| std::io::Error::other("ssh produced no stdin"))?;
    let writer = std::thread::spawn(move || -> std::io::Result<()> {
        let mut file = std::fs::File::open(source)?;
        std::io::copy(&mut file, &mut stdin)?;
        stdin.flush()?;
        // Dropping stdin closes it, which is what ends the remote `cat`.
        Ok(())
    });

    let output = child.wait_with_output()?;
    writer
        .join()
        .map_err(|_| std::io::Error::other("failed to stream the binary"))??;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
        let detail = if stderr.contains("checksum-mismatch") {
            "the bytes that arrived did not match the local file".to_string()
        } else if stderr.contains("not-runnable") {
            "the binary transferred intact but will not run on that host — check it \
             is built for the host's os and architecture. The existing install was \
             left untouched."
                .to_string()
        } else if stderr.is_empty() {
            "no output from the host".to_string()
        } else {
            stderr
        };
        return Err(std::io::Error::other(format!(
            "could not install herdr on {target}: {detail}"
        )));
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    let mut lines = stdout.lines();
    let destination = lines.next().unwrap_or_default().trim().to_string();
    let reported = lines.next().unwrap_or_default().trim().to_string();
    if destination.is_empty() {
        return Err(std::io::Error::other(format!(
            "install on {target} reported no destination"
        )));
    }

    Ok(Installed {
        destination,
        bytes,
        verified_sha256: (reported != "unavailable" && !reported.is_empty()).then_some(reported),
    })
}

fn file_sha256(path: &Path) -> std::io::Result<String> {
    use std::io::Read;

    let mut file = std::fs::File::open(path)?;
    let mut hasher = Sha256::new();
    let mut buffer = [0u8; 64 * 1024];
    loop {
        let read = file.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
    }
    Ok(format!("{:x}", hasher.finalize()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sha256_matches_a_known_value() {
        let dir = std::env::temp_dir().join(format!("herdr-install-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("payload");
        std::fs::write(&path, b"abc").unwrap();

        // The published SHA-256 of "abc".
        assert_eq!(
            file_sha256(&path).unwrap(),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn an_empty_binary_is_refused_before_any_connection() {
        // Streaming nothing would happily install a zero-byte file and every later
        // connection would fail with something unrelated-looking.
        let dir = std::env::temp_dir().join(format!("herdr-empty-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("empty");
        std::fs::write(&path, b"").unwrap();

        let err = install_binary("host.invalid", &path).expect_err("should refuse");
        assert!(err.to_string().contains("is empty"), "{err}");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_missing_binary_is_reported_before_any_connection() {
        let err =
            install_binary("host.invalid", Path::new("/no/such/herdr")).expect_err("should fail");
        assert_eq!(err.kind(), std::io::ErrorKind::NotFound);
    }
}
