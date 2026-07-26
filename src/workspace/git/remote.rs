//! Git facts about a repository that lives on another machine.
//!
//! Running git locally for a remote workspace is not merely unavailable, it is
//! actively wrong: if the same path happens to exist on this machine, the answer
//! describes a completely different repository, and a confidently wrong branch is
//! worse than a blank one. So these questions are asked of the machine the work is on.
//!
//! Deliberately separate from the local path rather than threaded through it. The
//! local implementation is built around a filesystem fingerprint cache — mtimes of
//! `.git` files on this machine — which describes nothing about a remote repository,
//! so reusing it would mean caching answers against a key that cannot invalidate them.

#[cfg(unix)]
use crate::host::link::HostLink;

/// What the host said about a repository.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct RemoteGitStatus {
    pub(crate) branch: Option<String>,
    pub(crate) ahead_behind: Option<(usize, usize)>,
}

/// Ask a host for the branch and upstream distance at `cwd`.
///
/// Returns whatever it managed to learn. A repository with no upstream has no
/// ahead/behind and that is a normal answer, not a failure — reporting nothing at all
/// because the second question had no answer would hide the branch too.
#[cfg(unix)]
pub(crate) fn remote_git_status(link: &HostLink, cwd: &str) -> RemoteGitStatus {
    let branch = link
        .exec(
            &[
                "git".into(),
                "-C".into(),
                cwd.into(),
                "rev-parse".into(),
                "--abbrev-ref".into(),
                "HEAD".into(),
            ],
            None,
        )
        .ok()
        .filter(|output| output.succeeded())
        .and_then(|output| parse_branch(&output.stdout));

    // Only worth asking once there is a branch: without one there is no repository
    // here, and the second call would just be a slower way to learn the same thing.
    let ahead_behind = branch.as_ref().and_then(|_| {
        link.exec(
            &[
                "git".into(),
                "-C".into(),
                cwd.into(),
                "rev-list".into(),
                "--left-right".into(),
                "--count".into(),
                "HEAD...@{upstream}".into(),
            ],
            None,
        )
        .ok()
        .filter(|output| output.succeeded())
        .and_then(|output| parse_ahead_behind(&output.stdout))
    });

    RemoteGitStatus {
        branch,
        ahead_behind,
    }
}

/// `HEAD` means a detached head, which is not a branch name and must not be shown as
/// one — it would look like a branch called "HEAD" on every detached checkout.
pub(crate) fn parse_branch(stdout: &[u8]) -> Option<String> {
    let branch = String::from_utf8_lossy(stdout).trim().to_string();
    (!branch.is_empty() && branch != "HEAD").then_some(branch)
}

/// `git rev-list --left-right --count` prints two tab-separated numbers.
pub(crate) fn parse_ahead_behind(stdout: &[u8]) -> Option<(usize, usize)> {
    let text = String::from_utf8_lossy(stdout);
    let mut parts = text.split_whitespace();
    let ahead = parts.next()?.parse().ok()?;
    let behind = parts.next()?.parse().ok()?;
    // A third number means this is not the output we think it is, and guessing which
    // two of three were wanted is how a wrong count gets shown confidently.
    parts.next().is_none().then_some((ahead, behind))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_detached_head_is_not_a_branch_name() {
        // Otherwise every detached checkout displays a branch called "HEAD".
        assert_eq!(parse_branch(b"HEAD\n"), None);
        assert_eq!(parse_branch(b"  \n"), None);
        assert_eq!(parse_branch(b"main\n"), Some("main".to_string()));
        assert_eq!(
            parse_branch(b"feature/some-thing\n"),
            Some("feature/some-thing".to_string())
        );
    }

    #[test]
    fn ahead_behind_reads_both_numbers_or_neither() {
        assert_eq!(parse_ahead_behind(b"2\t5\n"), Some((2, 5)));
        assert_eq!(parse_ahead_behind(b"0\t0\n"), Some((0, 0)));
        assert_eq!(parse_ahead_behind(b""), None);
        assert_eq!(parse_ahead_behind(b"3\n"), None);
        // Unexpected shape must not be guessed at: showing a confidently wrong count
        // is worse than showing none.
        assert_eq!(parse_ahead_behind(b"1\t2\t3\n"), None);
        assert_eq!(parse_ahead_behind(b"x\ty\n"), None);
    }
}
