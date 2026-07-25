//! `herdr attention` — questions about the fleet rather than about one agent.
//!
//! Separate from `herdr agent` because the subject is different. Every `agent`
//! subcommand names a target; these deliberately do not, because the thing being
//! asked is *which* agent needs something. With twenty agents on five machines that
//! is the only question worth asking, and polling them one at a time cannot answer
//! it: you would need to know which one to watch, which is what you are trying to
//! find out.

use crate::api::schema::{AttentionWaitParams, Method, Request};

pub fn run_attention_command(args: &[String]) -> std::io::Result<i32> {
    match args.first().map(|arg| arg.as_str()) {
        Some("wait") => attention_wait(&args[1..]),
        Some("help") | Some("--help") | Some("-h") | None => {
            usage();
            Ok(0)
        }
        Some(other) => {
            eprintln!("unknown attention command: {other}");
            usage();
            Ok(2)
        }
    }
}

fn usage() {
    eprintln!(
        "usage: herdr attention wait [--status STATUS]... [--host HOST] [--count N] [--timeout MS]"
    );
    eprintln!();
    eprintln!("Blocks until an agent wants attention, on any machine unless --host says");
    eprintln!("otherwise. Defaults to `blocked` only: a finished agent is news, not a");
    eprintln!("demand, and including it would make this return almost immediately in a");
    eprintln!("fleet where something finishes every few minutes.");
    eprintln!();
    eprintln!("  --count N   wait for N at once, to be interrupted once instead of N times");
}

fn attention_wait(args: &[String]) -> std::io::Result<i32> {
    let mut until = Vec::new();
    let mut host = None;
    let mut count = None;
    let mut timeout_ms = None;

    let mut index = 0;
    while index < args.len() {
        match args[index].as_str() {
            // `--status`, not `--until`: this waits for a condition across a fleet
            // rather than for one agent to reach a state, and "until blocked" reads
            // as though a specific agent were being watched.
            "--status" | "--until" => {
                let Some(value) = args.get(index + 1) else {
                    eprintln!("--status requires a status");
                    return Ok(2);
                };
                match super::parse_agent_status(value) {
                    Ok(status) => until.push(status),
                    Err(err) => {
                        eprintln!("{err}");
                        return Ok(2);
                    }
                }
                index += 2;
            }
            "--host" => {
                let Some(value) = args.get(index + 1) else {
                    eprintln!("--host requires a name");
                    return Ok(2);
                };
                host = Some(value.clone());
                index += 2;
            }
            "--count" => {
                let Some(value) = args.get(index + 1) else {
                    eprintln!("--count requires a number");
                    return Ok(2);
                };
                match value.parse::<usize>() {
                    Ok(parsed) if parsed > 0 => count = Some(parsed),
                    // Zero would be satisfied before anything happened, which is
                    // never what anyone means by "wait".
                    _ => {
                        eprintln!("--count must be a positive number");
                        return Ok(2);
                    }
                }
                index += 2;
            }
            "--timeout" | "--timeout-ms" => {
                let Some(value) = args.get(index + 1) else {
                    eprintln!("--timeout requires a number of milliseconds");
                    return Ok(2);
                };
                match value.parse::<u64>() {
                    Ok(parsed) => timeout_ms = Some(parsed),
                    Err(_) => {
                        eprintln!("--timeout must be a number of milliseconds");
                        return Ok(2);
                    }
                }
                index += 2;
            }
            "help" | "--help" | "-h" => {
                usage();
                return Ok(0);
            }
            other => {
                eprintln!("unknown option: {other}");
                return Ok(2);
            }
        }
    }

    super::print_response(&super::send_request(&Request {
        id: "cli:attention:wait".into(),
        method: Method::AttentionWait(AttentionWaitParams {
            until,
            host,
            count,
            timeout_ms,
        }),
    })?)
}
