//! Running the I/O side of host discovery: reading ssh config files, invoking
//! user-configured discovery commands, and asking `ssh -G` what it can reach.
//!
//! Kept apart from [`super::discovery`], which is pure and exhaustively tested.
//! Everything here touches the filesystem or spawns a process, so it is thin on
//! purpose — it gathers bytes and hands them to the pure functions.

use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::Duration;

use super::discovery::{self, HostCandidate, HostOrigin};
use super::HostId;

/// Ceiling on how long a single external command may take. A wedged discovery
/// command must not hang workspace creation, and `ssh -G` does no network I/O so
/// it has no excuse to be slow.
const COMMAND_TIMEOUT: Duration = Duration::from_secs(5);

/// The user's ssh config, plus the system one. `Include` directives are not
/// followed; `ssh -G` is the authority on what actually resolves.
fn ssh_config_paths() -> Vec<PathBuf> {
    let mut paths = Vec::new();
    if let Some(home) = std::env::var_os("HOME").filter(|home| !home.is_empty()) {
        paths.push(Path::new(&home).join(".ssh").join("config"));
    }
    paths.push(PathBuf::from("/etc/ssh/ssh_config"));
    paths
}

/// Literal host names from the user's ssh config files.
pub fn names_from_ssh_config() -> Vec<String> {
    let mut names = Vec::new();
    for path in ssh_config_paths() {
        let Ok(contents) = std::fs::read_to_string(&path) else {
            continue;
        };
        names.extend(discovery::host_names_from_ssh_config(&contents));
    }
    names
}

/// Run a discovery command and read host names from its output.
///
/// A failure — missing binary, non-zero exit, timeout, unparseable output — is
/// reported as no names. Discovery is an optional convenience; a broken command
/// must never be the reason a user cannot open a workspace.
pub fn names_from_discovery_command(argv: &[String]) -> Vec<String> {
    let Some((program, rest)) = argv.split_first() else {
        return Vec::new();
    };

    // Only run a command that is actually present, so a missing tool is silent
    // rather than an error the user has to dismiss.
    let Ok(output) = run_with_timeout(Command::new(program).args(rest)) else {
        return Vec::new();
    };
    if !output.status.success() {
        return Vec::new();
    }

    discovery::host_names_from_discovery_output(&String::from_utf8_lossy(&output.stdout))
}

/// Ask ssh whether it knows how to reach `host`, without touching the network.
///
/// `ssh -G` expands wildcard stanzas and prints the effective configuration, so
/// this is what turns a discovered name into a name ssh can dial.
pub fn ssh_knows_host(host: &HostId) -> bool {
    let Ok(output) = run_with_timeout(Command::new("ssh").arg("-G").arg(host.as_str())) else {
        return false;
    };
    if !output.status.success() {
        return false;
    }
    discovery::ssh_config_describes_a_target(
        host.as_str(),
        &String::from_utf8_lossy(&output.stdout),
    )
}

/// Discovery commands herdr ships with, as data rather than logic.
///
/// A template is offered only when its program is already on `PATH`, so a user
/// with a supported workspace manager installed gets their machines in the list
/// having configured nothing, and everyone else sees no mention of it. Adding a
/// tool here is a data change; user configuration can add more.
const BUILTIN_DISCOVERY_TEMPLATES: &[&[&str]] = &[&["coder", "list", "-o", "json"]];

/// Built-in discovery commands whose program is present on this machine.
pub fn builtin_discovery_commands() -> Vec<Vec<String>> {
    BUILTIN_DISCOVERY_TEMPLATES
        .iter()
        .filter(|argv| argv.first().is_some_and(|program| program_exists(program)))
        .map(|argv| argv.iter().map(|arg| arg.to_string()).collect())
        .collect()
}

/// Whether a program can be found on `PATH`.
fn program_exists(program: &str) -> bool {
    let Some(path) = std::env::var_os("PATH") else {
        return false;
    };
    std::env::split_paths(&path).any(|dir| {
        let candidate = dir.join(program);
        std::fs::metadata(&candidate).is_ok_and(|meta| meta.is_file())
    })
}

/// Assemble the pickable host list.
///
/// `discovery_commands` come from user configuration; each is run only if its
/// program exists. Nothing here contacts a host: the list must render instantly,
/// so reachability is left to the moment the user actually connects.
pub fn gather(discovery_commands: &[Vec<String>], configured: &[HostId]) -> Vec<HostCandidate> {
    let wildcards = wildcard_patterns();

    let mut sources = vec![
        (HostOrigin::SshConfig, names_from_ssh_config()),
        (
            HostOrigin::Configured,
            configured
                .iter()
                .map(|host| host.as_str().to_string())
                .collect(),
        ),
    ];

    for argv in discovery_commands {
        let names: Vec<String> = names_from_discovery_command(argv)
            .into_iter()
            .map(|raw| resolve_ssh_target(&raw, &wildcards))
            .collect();
        if !names.is_empty() {
            sources.push((HostOrigin::Discovered, names));
        }
    }

    discovery::collect_candidates(sources)
}

/// Wildcard `Host` patterns from the user's ssh config files.
fn wildcard_patterns() -> Vec<String> {
    let mut patterns = Vec::new();
    for path in ssh_config_paths() {
        let Ok(contents) = std::fs::read_to_string(&path) else {
            continue;
        };
        for pattern in discovery::wildcard_patterns_from_ssh_config(&contents) {
            if !patterns.contains(&pattern) {
                patterns.push(pattern);
            }
        }
    }
    patterns
}

/// Spell a discovered name the way ssh can dial it.
///
/// A discovery tool reports its own identifier, which is often not an ssh target:
/// the machine is reached through a wildcard stanza carrying a `ProxyCommand`. So
/// each candidate spelling derived from the user's config is offered to `ssh -G`,
/// and the first one ssh recognises as a real target wins.
///
/// Falls back to the raw name when nothing resolves, so a name is never silently
/// dropped — it just shows as unresolved.
fn resolve_ssh_target(raw_name: &str, wildcards: &[String]) -> String {
    for form in discovery::candidate_name_forms(raw_name, wildcards) {
        let Some(id) = HostId::parse(&form) else {
            continue;
        };
        if ssh_knows_host(&id) {
            return form;
        }
    }
    raw_name.to_string()
}

/// Spawn a command, capture its output, and give up after [`COMMAND_TIMEOUT`].
///
/// `std::process` has no timeout, so this polls for completion and kills the
/// child on expiry. Without it a hung discovery command would block the caller
/// indefinitely.
fn run_with_timeout(command: &mut Command) -> std::io::Result<std::process::Output> {
    use std::io::Read;

    let mut child = command
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::null())
        .spawn()?;

    // stdout MUST be drained concurrently, not after the child exits. A pipe
    // buffer is tens of kilobytes; a command whose output exceeds it blocks
    // forever writing while we wait for an exit that can never come. A real
    // `list --json` producing ~90 KB deadlocked exactly this way.
    let pipe = child.stdout.take();
    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let mut buffer = Vec::new();
        if let Some(mut pipe) = pipe {
            let _ = pipe.read_to_end(&mut buffer);
        }
        let _ = tx.send(buffer);
    });

    // EOF on stdout means the child has finished writing, so its exit status
    // follows promptly.
    match rx.recv_timeout(COMMAND_TIMEOUT) {
        Ok(stdout) => Ok(std::process::Output {
            status: child.wait()?,
            stdout,
            stderr: Vec::new(),
        }),
        Err(_) => {
            let _ = child.kill();
            let _ = child.wait();
            Err(std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                "command timed out",
            ))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_missing_discovery_command_yields_no_names() {
        let names = names_from_discovery_command(&["herdr-no-such-command-xyz".to_string()]);
        assert!(names.is_empty());
    }

    #[test]
    fn an_empty_discovery_argv_yields_no_names() {
        assert!(names_from_discovery_command(&[]).is_empty());
    }

    #[test]
    fn a_failing_discovery_command_yields_no_names() {
        // Non-zero exit must not surface partial or error output as host names.
        let names = names_from_discovery_command(&[
            "sh".to_string(),
            "-c".to_string(),
            "echo box1; exit 1".to_string(),
        ]);
        assert!(names.is_empty());
    }

    #[test]
    fn a_successful_discovery_command_yields_its_names() {
        let names = names_from_discovery_command(&[
            "sh".to_string(),
            "-c".to_string(),
            "printf 'box1\\nbox2\\n'".to_string(),
        ]);
        assert_eq!(names, vec!["box1", "box2"]);
    }

    #[test]
    fn a_hanging_discovery_command_is_killed_rather_than_waited_on() {
        // Proves the timeout path works without making the test slow: the
        // command would otherwise outlive the whole test run.
        let start = std::time::Instant::now();
        let names = names_from_discovery_command(&[
            "sh".to_string(),
            "-c".to_string(),
            "sleep 60".to_string(),
        ]);
        assert!(names.is_empty());
        assert!(
            start.elapsed() < COMMAND_TIMEOUT + Duration::from_secs(3),
            "should have given up near the timeout, took {:?}",
            start.elapsed()
        );
    }

    #[test]
    fn gather_includes_configured_hosts_even_with_no_discovery() {
        let configured = vec![HostId::parse("explicitly-configured-box").unwrap()];
        let candidates = gather(&[], &configured);
        assert!(
            candidates.iter().any(
                |candidate| candidate.id.as_str() == "explicitly-configured-box"
                    && candidate.origin == HostOrigin::Configured
            ),
            "configured hosts must always appear"
        );
    }

    #[test]
    fn gather_drops_unsafe_names_from_a_discovery_command() {
        let candidates = gather(
            &[vec![
                "sh".to_string(),
                "-c".to_string(),
                "printf 'good-box\\nbad;rm -rf /\\n'".to_string(),
            ]],
            &[],
        );
        // Match on a substring, not equality: `gather` resolves a discovered
        // name against the real ssh config on this machine, so a wildcard
        // stanza may legitimately respell `good-box` as `good-box.<suffix>`.
        assert!(
            candidates
                .iter()
                .any(|candidate| candidate.id.as_str().contains("good-box")),
            "the safe discovered name should survive in some spelling: {candidates:?}"
        );
        assert!(
            !candidates
                .iter()
                .any(|candidate| candidate.id.as_str().contains(';')),
            "an unsafe discovered name must never become a candidate"
        );
    }
}
