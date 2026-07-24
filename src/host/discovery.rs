//! Finding hosts the user can actually connect to, without asking them to
//! write configuration first.
//!
//! Candidate names come from two places and are joined by ssh itself:
//!
//! - **ssh config** contributes literal `Host` stanzas.
//! - **Discovery commands** (user-configured, e.g. a workspace manager's CLI)
//!   contribute names that are not in ssh config at all.
//!
//! Neither source is sufficient alone. A config that reaches its machines
//! through a wildcard plus `ProxyCommand` — `Host coder.*` and friends — has no
//! literal stanza per machine, so ssh-config enumeration alone yields a nearly
//! empty list. Conversely a discovered name is only useful if ssh knows how to
//! reach it. `ssh -G <name>` resolves the wildcards and reports the effective
//! configuration offline, so it is the join between the two.

// The pure candidate-gathering logic lands before the code that runs `ssh -G`
// and renders the picker, so it has tests but no production caller yet. Kept
// separate deliberately: this is the part worth testing exhaustively, and it is
// testable precisely because it does no I/O.
#![allow(dead_code)]

use std::collections::BTreeSet;

use super::HostId;

/// Where a candidate host name came from. Shown in the picker so the user can
/// tell a configured machine from a discovered one.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum HostOrigin {
    /// A literal `Host` stanza in an ssh config file.
    SshConfig,
    /// Emitted by a user-configured discovery command.
    Discovered,
    /// Declared explicitly in herdr's own configuration.
    Configured,
}

/// A host the user could pick, before any network contact.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HostCandidate {
    pub id: HostId,
    pub origin: HostOrigin,
}

/// Extract usable host names from ssh config content.
///
/// Only literal names are returned. Patterns are skipped because they are not
/// connectable targets: `Host coder.*` describes how to reach a family of
/// machines, not a machine. Negated patterns (`!foo`) and `Match` blocks are
/// skipped for the same reason.
///
/// This is deliberately a lenient scanner rather than a full ssh config parser.
/// It never follows `Include`, so it sees only what it is given; the authority
/// on whether a name resolves is `ssh -G`, not this function.
pub fn host_names_from_ssh_config(contents: &str) -> Vec<String> {
    let mut names: BTreeSet<String> = BTreeSet::new();

    for line in contents.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }

        // `Host` and the keyword are case-insensitive in ssh config.
        let mut parts = line.split_whitespace();
        let Some(keyword) = parts.next() else {
            continue;
        };
        if !keyword.eq_ignore_ascii_case("host") {
            continue;
        }

        // One stanza may list several patterns: `Host a b *.c`.
        for token in parts {
            if token.starts_with('#') {
                break;
            }
            if is_pattern(token) {
                continue;
            }
            names.insert(token.to_string());
        }
    }

    names.into_iter().collect()
}

/// Wildcards, negations, and anything else that describes a set of hosts rather
/// than one host.
fn is_pattern(token: &str) -> bool {
    token.contains('*') || token.contains('?') || token.starts_with('!')
}

/// Turn raw candidate names into validated candidates, dropping anything that
/// cannot be a [`HostId`] and de-duplicating while keeping the strongest origin.
///
/// Origin precedence is `Configured` > `SshConfig` > `Discovered`: an explicit
/// declaration should win over an inferred one, because that is where a user
/// puts overrides.
pub fn collect_candidates(
    sources: impl IntoIterator<Item = (HostOrigin, Vec<String>)>,
) -> Vec<HostCandidate> {
    let mut best: std::collections::BTreeMap<String, HostOrigin> = Default::default();

    for (origin, names) in sources {
        for name in names {
            let Some(id) = HostId::parse(&name) else {
                continue;
            };
            let key = id.as_str().to_string();
            best.entry(key)
                .and_modify(|current| {
                    if origin_rank(origin) > origin_rank(*current) {
                        *current = origin;
                    }
                })
                .or_insert(origin);
        }
    }

    best.into_iter()
        .filter_map(|(name, origin)| HostId::parse(&name).map(|id| HostCandidate { id, origin }))
        .collect()
}

fn origin_rank(origin: HostOrigin) -> u8 {
    match origin {
        HostOrigin::Discovered => 0,
        HostOrigin::SshConfig => 1,
        HostOrigin::Configured => 2,
    }
}

/// Parse the output of a discovery command into candidate names.
///
/// Accepts either a JSON array (of strings, or of objects with a `name` field —
/// the common shape for a workspace manager's `list --json`) or one name per
/// line. Anything unparseable yields no names rather than an error: a broken
/// discovery command must not stop the user opening a workspace.
pub fn host_names_from_discovery_output(output: &str) -> Vec<String> {
    let trimmed = output.trim();
    if trimmed.is_empty() {
        return Vec::new();
    }

    // Valid JSON we do not understand is structured data, not a hostname list.
    // Falling through to the line reader here would turn `{"error":...}` into a
    // candidate named `{"error":...}`.
    if let Ok(value) = serde_json::from_str::<serde_json::Value>(trimmed) {
        return match value.as_array() {
            Some(array) => array
                .iter()
                .filter_map(|entry| match entry {
                    serde_json::Value::String(name) => Some(name.clone()),
                    serde_json::Value::Object(map) => map
                        .get("name")
                        .and_then(serde_json::Value::as_str)
                        .map(str::to_string),
                    _ => None,
                })
                .collect(),
            None => Vec::new(),
        };
    }

    trimmed
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty() && !line.starts_with('#'))
        .map(str::to_string)
        .collect()
}

/// Decide whether `ssh -G <name>` output describes a reachable target.
///
/// A name ssh knows nothing about still resolves — it just echoes the name back
/// as `hostname` with no proxy. A configured target either goes through a
/// `proxycommand` or has a `hostname` that differs from the requested name.
/// This is a heuristic for ordering and labelling the picker, never a
/// reachability guarantee; only connecting proves that.
pub fn ssh_config_describes_a_target(name: &str, ssh_g_output: &str) -> bool {
    let mut hostname: Option<&str> = None;

    for line in ssh_g_output.lines() {
        let line = line.trim();
        let Some((key, value)) = line.split_once(' ') else {
            continue;
        };
        match key.to_ascii_lowercase().as_str() {
            "proxycommand" | "proxyjump" if !value.trim().is_empty() => return true,
            "hostname" => hostname = Some(value.trim()),
            _ => {}
        }
    }

    hostname.is_some_and(|hostname| !hostname.eq_ignore_ascii_case(name))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Shape taken from a real machine whose workspaces are reached through
    /// wildcard stanzas: 8 `Host` lines, only one of them literal.
    const WILDCARD_HEAVY_CONFIG: &str = "\
Host github.com
  User git

Host *
  AddKeysToAgent yes

Host *.coder coder.*
  ForwardAgent no

Host coder-vscode.example.com--*
  ProxyCommand /usr/local/bin/coder vscodessh %h

Match host *.coder !exec \"coder connect exists %h\"
  ProxyCommand coder ssh --stdio %h
";

    #[test]
    fn ssh_config_yields_only_literal_hosts() {
        let names = host_names_from_ssh_config(WILDCARD_HEAVY_CONFIG);
        assert_eq!(names, vec!["github.com"]);
    }

    #[test]
    fn ssh_config_alone_is_not_enough_to_populate_a_picker() {
        // This is the reason discovery commands exist rather than being a
        // fallback: a wildcard-based config lists almost nothing usable.
        let names = host_names_from_ssh_config(WILDCARD_HEAVY_CONFIG);
        assert_eq!(
            names.len(),
            1,
            "a wildcard-heavy config must not appear to be a full host list"
        );
    }

    #[test]
    fn ssh_config_reads_multiple_names_per_stanza_and_ignores_comments() {
        let names = host_names_from_ssh_config(
            "# a comment\nHOST alpha beta *.gamma  # trailing\n  User x\nhost delta\n",
        );
        assert_eq!(names, vec!["alpha", "beta", "delta"]);
    }

    #[test]
    fn ssh_config_skips_patterns_and_negations() {
        for token in ["*", "*.coder", "coder.*", "we?rd", "!excluded"] {
            assert!(is_pattern(token), "{token} should be treated as a pattern");
        }
        assert!(!is_pattern("plain.host"));
    }

    #[test]
    fn discovery_output_reads_json_arrays_of_names_or_objects() {
        assert_eq!(
            host_names_from_discovery_output(r#"["box1","box2"]"#),
            vec!["box1", "box2"]
        );
        assert_eq!(
            host_names_from_discovery_output(r#"[{"name":"box1","status":"running"}]"#),
            vec!["box1"]
        );
    }

    #[test]
    fn discovery_output_reads_plain_lines() {
        assert_eq!(
            host_names_from_discovery_output("box1\n\n# note\nbox2\n"),
            vec!["box1", "box2"]
        );
    }

    #[test]
    fn broken_discovery_output_yields_nothing_rather_than_failing() {
        // A misconfigured discovery command must not block workspace creation.
        for output in ["", "   ", "{\"unexpected\":true}"] {
            assert!(
                host_names_from_discovery_output(output).is_empty(),
                "{output:?}"
            );
        }
    }

    #[test]
    fn candidates_drop_unsafe_names() {
        let candidates = collect_candidates([(
            HostOrigin::Discovered,
            vec!["ok-box".to_string(), "bad;rm -rf /".to_string()],
        )]);
        assert_eq!(candidates.len(), 1);
        assert_eq!(candidates[0].id.as_str(), "ok-box");
    }

    #[test]
    fn candidates_dedupe_and_prefer_the_strongest_origin() {
        let candidates = collect_candidates([
            (HostOrigin::Discovered, vec!["box1".to_string()]),
            (HostOrigin::SshConfig, vec!["box1".to_string()]),
            (HostOrigin::Configured, vec!["box2".to_string()]),
            (HostOrigin::Discovered, vec!["box2".to_string()]),
        ]);

        assert_eq!(candidates.len(), 2);
        assert_eq!(candidates[0].id.as_str(), "box1");
        assert_eq!(candidates[0].origin, HostOrigin::SshConfig);
        assert_eq!(candidates[1].id.as_str(), "box2");
        assert_eq!(
            candidates[1].origin,
            HostOrigin::Configured,
            "an explicit declaration must win over a discovered one"
        );
    }

    #[test]
    fn ssh_g_output_identifies_a_proxied_target() {
        // A discovered name that matches only a wildcard stanza still resolves
        // to a real ProxyCommand — this is the join that makes discovery work.
        let output =
            "host coder.box1\nhostname coder.box1\nproxycommand coder ssh --stdio %h\nuser deep\n";
        assert!(ssh_config_describes_a_target("coder.box1", output));
    }

    #[test]
    fn ssh_g_output_identifies_a_rewritten_hostname() {
        let output = "host shortname\nhostname real.example.com\n";
        assert!(ssh_config_describes_a_target("shortname", output));
    }

    #[test]
    fn ssh_g_output_for_an_unknown_name_is_not_a_target() {
        // ssh echoes an unknown name straight back with no proxy.
        let output = "host totally-not-a-host\nhostname totally-not-a-host\nport 22\n";
        assert!(!ssh_config_describes_a_target("totally-not-a-host", output));
    }

    #[test]
    fn ssh_g_hostname_comparison_ignores_case() {
        let output = "hostname TOTALLY-NOT-A-HOST\n";
        assert!(!ssh_config_describes_a_target("totally-not-a-host", output));
    }

    #[test]
    fn ssh_g_ignores_an_empty_proxycommand() {
        // `ProxyCommand none` is how a specific host opts out of an inherited
        // proxy; an empty value must not read as "configured".
        let output = "hostname box1\nproxycommand \n";
        assert!(!ssh_config_describes_a_target("box1", output));
    }
}
