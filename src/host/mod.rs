//! Host identity for workspaces whose processes run on another machine.
//!
//! A workspace is either entirely local or entirely bound to one host, so host
//! is a workspace attribute rather than part of any pane or terminal identity.
//! Public ids (`w1`, `w1:p1`, `w1:t1`) are unchanged by a host binding.

pub mod discovery;
// Stays cross-platform: a Windows local side talking to a Unix host is a
// plausible future, so the protocol is not Unix-gated. Nothing consumes it on
// Windows yet, hence the platform-scoped allow rather than a blanket one.
#[cfg_attr(windows, allow(dead_code))]
pub mod protocol;

/// The pty-host daemon owns real PTYs, and herdr's whole pty/remote/handoff path
/// is Unix-only today. Mirrors how `crate::remote` stubs out on Windows rather
/// than pretending to support it.
#[cfg(unix)]
pub mod pty_host;

#[cfg(windows)]
pub mod pty_host {
    pub fn run() -> std::io::Result<()> {
        Err(std::io::Error::other(
            "herdr pty-host is not supported on Windows yet",
        ))
    }
}
pub mod sources;

use std::fmt;

use serde::{Deserialize, Serialize};

/// Stable identity of a machine that can run a workspace's processes.
///
/// `None` on a workspace means the local machine.
///
/// Host names originate outside herdr — ssh config stanzas and the output of
/// user-configured discovery commands — and end up interpolated into ssh
/// invocations. So the charset is restricted at construction rather than at the
/// point of use: a name that cannot be parsed here can never reach a command
/// line. Anything with whitespace, quotes, or shell metacharacters is rejected.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct HostId(String);

/// Longest accepted host name. Generous for `user@host.example.com`-style
/// targets while still bounded.
const MAX_HOST_ID_LEN: usize = 128;

impl HostId {
    /// Parse a host name, rejecting anything unsafe to interpolate into a
    /// command line. Returns `None` for empty, over-long, or invalid names.
    pub fn parse(name: impl AsRef<str>) -> Option<Self> {
        let name = name.as_ref();
        if name.is_empty() || name.len() > MAX_HOST_ID_LEN {
            return None;
        }
        // Leading '-' would be read as an option by ssh.
        if name.starts_with('-') {
            return None;
        }
        if !name.chars().all(Self::is_allowed_char) {
            return None;
        }
        Some(Self(name.to_string()))
    }

    fn is_allowed_char(ch: char) -> bool {
        ch.is_ascii_alphanumeric() || matches!(ch, '-' | '_' | '.' | '@' | ':' | '+' | '/')
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for HostId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl TryFrom<String> for HostId {
    type Error = String;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        Self::parse(&value).ok_or_else(|| format!("invalid host id: {value:?}"))
    }
}

impl From<HostId> for String {
    fn from(value: HostId) -> Self {
        value.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_plain_and_qualified_names() {
        for name in [
            "box1",
            "coder.deep-b200-aws",
            "deep@build.example.com",
            "host_1",
            "10.0.0.4",
        ] {
            assert!(HostId::parse(name).is_some(), "should accept {name}");
            assert_eq!(HostId::parse(name).unwrap().as_str(), name);
        }
    }

    #[test]
    fn rejects_names_that_are_unsafe_on_a_command_line() {
        // These are the reason parsing is restrictive: host names reach ssh.
        for name in [
            "",
            " ",
            "box 1",
            "box;rm -rf /",
            "box$(whoami)",
            "box`id`",
            "box|tee",
            "box&",
            "box'quote",
            "box\"quote",
            "box\nnewline",
            "box\\slash",
            "box*glob",
            "-oProxyCommand=evil",
        ] {
            assert!(HostId::parse(name).is_none(), "should reject {name:?}");
        }
    }

    #[test]
    fn rejects_over_long_names() {
        assert!(HostId::parse("a".repeat(MAX_HOST_ID_LEN)).is_some());
        assert!(HostId::parse("a".repeat(MAX_HOST_ID_LEN + 1)).is_none());
    }

    #[test]
    fn round_trips_through_serde() {
        let host = HostId::parse("coder.box1").unwrap();
        let json = serde_json::to_string(&host).unwrap();
        assert_eq!(json, "\"coder.box1\"");
        assert_eq!(serde_json::from_str::<HostId>(&json).unwrap(), host);
    }

    #[test]
    fn deserializing_an_invalid_name_fails_rather_than_sanitizing() {
        // A persisted or API-supplied name must not be silently rewritten into
        // something that looks valid.
        assert!(serde_json::from_str::<HostId>("\"box;rm -rf /\"").is_err());
    }
}

#[cfg(test)]
mod workspace_binding_tests {
    #[test]
    fn a_new_workspace_is_local() {
        let ws = crate::workspace::Workspace::test_new("test");
        assert_eq!(
            ws.host, None,
            "workspaces must default to the local machine"
        );
    }
}
