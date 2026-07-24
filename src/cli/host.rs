//! `herdr host` — inspect the machines herdr can put a workspace on.
//!
//! Runs entirely locally: it reads ssh config, runs discovery commands, and asks
//! `ssh -G` what resolves. It deliberately does not contact any host, so it is
//! safe and fast to run even when everything is asleep.

use crate::host::sources;

pub(super) fn run_host_command(args: &[String]) -> std::io::Result<i32> {
    match args.first().map(|arg| arg.as_str()) {
        Some("list") => host_list(&args[1..]),
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
    println!();
    println!("DIALABLE means ssh knows how to reach the name — a literal Host stanza, or a");
    println!("discovered name that ssh -G resolves. It does not mean the machine is up.");
}
