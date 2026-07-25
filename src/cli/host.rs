//! `herdr host` — inspect the machines herdr can put a workspace on.
//!
//! Runs entirely locally: it reads ssh config, runs discovery commands, and asks
//! `ssh -G` what resolves. It deliberately does not contact any host, so it is
//! safe and fast to run even when everything is asleep.

use crate::host::sources;

pub(super) fn run_host_command(args: &[String]) -> std::io::Result<i32> {
    match args.first().map(|arg| arg.as_str()) {
        Some("list") => host_list(&args[1..]),
        #[cfg(unix)]
        Some("install") => host_install(&args[1..]),
        #[cfg(windows)]
        Some("install") => {
            eprintln!("herdr host install is not supported on Windows yet");
            Ok(2)
        }
        #[cfg(unix)]
        Some("probe") => host_probe(&args[1..]),
        #[cfg(windows)]
        Some("probe") => {
            eprintln!("herdr host probe is not supported on Windows yet");
            Ok(2)
        }
        Some("help") | Some("--help") | Some("-h") => {
            print_host_help();
            Ok(0)
        }
        _ => {
            print_host_help();
            Ok(2)
        }
    }
}

fn host_list(args: &[String]) -> std::io::Result<i32> {
    let mut json = false;
    for arg in args {
        match arg.as_str() {
            "--json" => json = true,
            other => {
                eprintln!("unknown option: {other}");
                print_host_help();
                return Ok(2);
            }
        }
    }

    let candidates = sources::gather(&sources::builtin_discovery_commands(), &[]);

    // A literal ssh config stanza is dialable by definition, so only a
    // discovered name needs asking about. That also avoids a process per
    // already-known host.
    let rows: Vec<(String, &'static str, bool)> = candidates
        .iter()
        .map(|candidate| {
            let dialable = match candidate.origin {
                crate::host::discovery::HostOrigin::SshConfig => true,
                _ => sources::ssh_knows_host(&candidate.id),
            };
            (
                candidate.id.as_str().to_string(),
                origin_label(candidate.origin),
                dialable,
            )
        })
        .collect();

    if json {
        let payload: Vec<serde_json::Value> = rows
            .iter()
            .map(|(name, origin, resolvable)| {
                serde_json::json!({
                    "name": name,
                    "origin": origin,
                    "dialable": resolvable,
                })
            })
            .collect();
        println!("{}", serde_json::to_string_pretty(&payload)?);
        return Ok(0);
    }

    if rows.is_empty() {
        println!("no hosts found");
        println!();
        println!("herdr looks for literal Host entries in your ssh config and runs any");
        println!("discovery commands whose tool is installed. Wildcard entries such as");
        println!("`Host build.*` are skipped because they name a family, not a machine.");
        return Ok(0);
    }

    let width = rows
        .iter()
        .map(|(name, _, _)| name.len())
        .max()
        .unwrap_or(4);
    println!(
        "{:<width$}  {:<10}  DIALABLE",
        "HOST",
        "ORIGIN",
        width = width
    );
    for (name, origin, resolvable) in &rows {
        println!(
            "{:<width$}  {:<10}  {}",
            name,
            origin,
            if *resolvable { "yes" } else { "no" },
            width = width
        );
    }

    Ok(0)
}

fn origin_label(origin: crate::host::discovery::HostOrigin) -> &'static str {
    match origin {
        crate::host::discovery::HostOrigin::SshConfig => "ssh-config",
        crate::host::discovery::HostOrigin::Discovered => "discovered",
        crate::host::discovery::HostOrigin::Configured => "configured",
    }
}

fn print_host_help() {
    println!("herdr host commands:");
    println!("  herdr host list [--json]");
    println!("  herdr host probe <host>");
    println!("  herdr host install <host> --from <binary>");
    println!();
    println!("DIALABLE means ssh knows how to reach the name — a literal Host stanza, or a");
    println!("discovered name that ssh -G resolves. It does not mean the machine is up.");
}

/// Verify a host end to end: connect over ssh, run a command there, read its
/// output back. Confirms the whole path a remote pane depends on, which is worth
/// more than a reachability check.
///
/// Unix-only for the same reason as the link and the daemon: it hands out a
/// socket fd.
#[cfg(unix)]
fn host_probe(args: &[String]) -> std::io::Result<i32> {
    let Some(name) = args.first() else {
        eprintln!("usage: herdr host probe <host>");
        return Ok(2);
    };
    let Some(host) = crate::host::HostId::parse(name) else {
        eprintln!("invalid host name `{name}`");
        return Ok(2);
    };

    let link = match crate::host::link::HostLink::connect_over_ssh(host.as_str()) {
        Ok(link) => link,
        Err(err) => {
            eprintln!("{err}");
            return Ok(1);
        }
    };
    println!(
        "connected to {host} (host protocol {}, link {:?})",
        link.peer_version(),
        link.status()
    );

    const MARKER: &str = "herdr-probe-ok";
    let (_channel, fd) = match link.open_channel(crate::host::protocol::SpawnSpec {
        argv: vec!["sh".into(), "-c".into(), format!("echo {MARKER}")],
        cwd: None,
        env: Vec::new(),
        rows: 24,
        cols: 80,
    }) {
        Ok(opened) => opened,
        Err(err) => {
            eprintln!("could not start a process on {host}: {err}");
            return Ok(1);
        }
    };

    // The channel fd is non-blocking, because the pane actor polls it. A reader
    // that treats WouldBlock as fatal sees nothing at all.
    let mut stream = std::os::unix::net::UnixStream::from(fd);

    let mut seen = String::new();
    let mut buffer = [0u8; 4096];
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(15);
    while std::time::Instant::now() < deadline {
        use std::io::Read;
        match stream.read(&mut buffer) {
            Ok(0) => break,
            Ok(n) => {
                seen.push_str(&String::from_utf8_lossy(&buffer[..n]));
                if seen.contains(MARKER) {
                    break;
                }
            }
            Err(ref err) if err.kind() == std::io::ErrorKind::WouldBlock => {
                std::thread::sleep(std::time::Duration::from_millis(50));
            }
            Err(_) => break,
        }
    }

    // Explicit rather than left to the drop, so the probe does not sit in a
    // redial backoff on its way out.
    link.close();

    if seen.contains(MARKER) {
        println!("ran a command on {host} and read its output back");
        Ok(0)
    } else {
        eprintln!("connected to {host} but never saw the probe output");
        Ok(1)
    }
}

/// Copy a herdr binary to a host.
///
/// A host needs a binary built for its own os/arch, and no release contains
/// `pty-host` yet, so this takes one you built and puts it where a connection will
/// look for it. Doing that by hand for every machine is the main friction in using
/// remote workspaces.
#[cfg(unix)]
fn host_install(args: &[String]) -> std::io::Result<i32> {
    let Some(name) = args.first() else {
        eprintln!("usage: herdr host install <host> --from <binary>");
        return Ok(2);
    };
    let Some(host) = crate::host::HostId::parse(name) else {
        eprintln!("invalid host name `{name}`");
        return Ok(2);
    };

    let mut source: Option<std::path::PathBuf> = None;
    let mut index = 1;
    while index < args.len() {
        match args[index].as_str() {
            "--from" => {
                let Some(value) = args.get(index + 1) else {
                    eprintln!("missing value for --from");
                    return Ok(2);
                };
                source = Some(std::path::PathBuf::from(value));
                index += 2;
            }
            other => {
                eprintln!("unknown option: {other}");
                return Ok(2);
            }
        }
    }

    let Some(source) = source else {
        eprintln!("usage: herdr host install <host> --from <binary>");
        eprintln!("the binary must be built for the host's os/arch, not this machine's");
        return Ok(2);
    };

    match crate::host::install::install_binary(host.as_str(), &source) {
        Ok(installed) => {
            println!(
                "installed {} bytes to {}:{}",
                installed.bytes, host, installed.destination
            );
            match installed.verified_sha256 {
                Some(sum) => println!("verified sha256 {sum}"),
                // Worth saying: silence here would read as a successful check.
                None => println!("host has no sha256 tool; contents were not verified"),
            }
            println!("run `herdr host probe {host}` to confirm it works");
            Ok(0)
        }
        Err(err) => {
            eprintln!("{err}");
            Ok(1)
        }
    }
}
