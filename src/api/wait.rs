use std::sync::atomic::AtomicBool;
use std::sync::Arc;

use regex::Regex;

use crate::api::schema::{
    ErrorBody, ErrorResponse, EventData, EventEnvelope, EventKind, EventMatch, EventsWaitParams,
    Method, Request, ResponseResult, Subscription, SubscriptionEventData,
    SubscriptionEventEnvelope, SuccessResponse,
};
use crate::api::server::{
    dispatch_to_app_with_timeout, should_stop_connection, APP_RESPONSE_TIMEOUT,
    CONNECTION_POLL_INTERVAL,
};
use crate::api::subscriptions::ActiveSubscription;
use crate::api::subscriptions::{match_output, output_match_read_source};
use crate::api::{ApiRequestSender, EventHub};
use crate::ipc::LocalStream;

const AGENT_PROMPT_EFFECT_TIMEOUT_MS: u64 = 5_000;

pub(super) fn wait_for_output(
    request_id: String,
    params: crate::api::schema::PaneWaitForOutputParams,
    stream: &mut LocalStream,
    api_tx: &ApiRequestSender,
    running: &Arc<AtomicBool>,
) -> std::io::Result<Option<String>> {
    crate::logging::api_wait_started(&request_id, &params.pane_id, params.timeout_ms);
    let deadline = params
        .timeout_ms
        .map(|ms| std::time::Instant::now() + std::time::Duration::from_millis(ms));

    let regex = match &params.r#match {
        crate::api::schema::OutputMatch::Regex { value } => match Regex::new(value) {
            Ok(regex) => Some(regex),
            Err(err) => {
                return Ok(Some(
                    serde_json::to_string(&ErrorResponse {
                        id: request_id,
                        error: ErrorBody {
                            code: "invalid_regex".into(),
                            message: err.to_string(),
                        },
                    })
                    .unwrap(),
                ));
            }
        },
        crate::api::schema::OutputMatch::Substring { .. } => None,
    };

    loop {
        if should_stop_connection(stream, running)? {
            crate::logging::api_wait_completed(&request_id, &params.pane_id, "client_disconnected");
            return Ok(None);
        }

        let read_request = Request {
            id: format!("{request_id}:read"),
            method: Method::PaneRead(crate::api::schema::PaneReadParams {
                pane_id: params.pane_id.clone(),
                source: output_match_read_source(&params.source),
                lines: params.lines,
                format: crate::api::schema::ReadFormat::Text,
                strip_ansi: params.strip_ansi,
            }),
        };
        let response =
            dispatch_to_app_with_timeout(read_request, api_tx, Some(APP_RESPONSE_TIMEOUT));
        let Ok(value) = serde_json::from_str::<serde_json::Value>(&response) else {
            return Ok(Some(response));
        };
        if value.get("error").is_some() {
            let mut value = value;
            value["id"] = serde_json::Value::String(request_id.clone());
            return Ok(Some(serde_json::to_string(&value).unwrap()));
        }

        let read_value = value["result"]["read"].clone();
        let Ok(read) = serde_json::from_value::<crate::api::schema::PaneReadResult>(read_value)
        else {
            return Ok(Some(
                serde_json::to_string(&ErrorResponse {
                    id: request_id,
                    error: ErrorBody {
                        code: "internal_error".into(),
                        message: "failed to decode pane read result".into(),
                    },
                })
                .unwrap(),
            ));
        };

        let matched_line = match_output(&read.text, &params.r#match, regex.as_ref());
        if matched_line.is_some() {
            let revision = read.revision;
            crate::logging::api_wait_completed(&request_id, &params.pane_id, "matched");
            return Ok(Some(
                serde_json::to_string(&SuccessResponse {
                    id: request_id,
                    result: ResponseResult::OutputMatched {
                        pane_id: read.pane_id.clone(),
                        revision,
                        matched_line,
                        read,
                    },
                })
                .unwrap(),
            ));
        }

        if deadline.is_some_and(|deadline| std::time::Instant::now() >= deadline) {
            crate::logging::api_wait_timed_out(&request_id, &params.pane_id);
            return Ok(Some(
                serde_json::to_string(&ErrorResponse {
                    id: request_id,
                    error: ErrorBody {
                        code: "timeout".into(),
                        message: "timed out waiting for output match".into(),
                    },
                })
                .unwrap(),
            ));
        }

        std::thread::sleep(CONNECTION_POLL_INTERVAL);
    }
}

pub(super) fn wait_for_agent(
    request_id: String,
    params: crate::api::schema::AgentWaitParams,
    stream: &mut LocalStream,
    api_tx: &ApiRequestSender,
    event_hub: &EventHub,
    running: &Arc<AtomicBool>,
) -> std::io::Result<Option<String>> {
    let last_event_sequence = event_hub.current_sequence();
    let initial = match agent_get(&request_id, &params.target, api_tx) {
        Ok(agent) => agent,
        Err(response) => {
            return serde_json::to_string(&response)
                .map(Some)
                .map_err(std::io::Error::other);
        }
    };
    let until = agent_wait_statuses(params.until);
    if agent_wait_matches(&initial, &until, None) {
        return agent_wait_success(request_id, initial).map(Some);
    }

    match wait_for_resolved_agent(
        request_id.clone(),
        ResolvedAgentWait {
            target: params.target,
            until,
            timeout_ms: params.timeout_ms,
            initial,
            last_event_sequence,
            after_state_change_seq: None,
            accept_transient_status: true,
            timeout_kind: AgentWaitTimeoutKind::Status,
        },
        stream,
        api_tx,
        event_hub,
        running,
    )? {
        Some(AgentWaitOutcome::Matched(agent)) => agent_wait_success(request_id, *agent).map(Some),
        Some(AgentWaitOutcome::Response(response)) => Ok(Some(response)),
        None => Ok(None),
    }
}

pub(super) fn prompt_agent(
    request_id: String,
    params: crate::api::schema::AgentPromptParams,
    stream: &mut LocalStream,
    api_tx: &ApiRequestSender,
    event_hub: &EventHub,
    running: &Arc<AtomicBool>,
) -> std::io::Result<Option<String>> {
    let Some(wait) = params.wait.clone() else {
        return Ok(Some(dispatch_to_app_with_timeout(
            Request {
                id: request_id,
                method: Method::AgentPrompt(params),
            },
            api_tx,
            None,
        )));
    };

    let last_event_sequence = event_hub.current_sequence();
    let before_prompt = match agent_get(&request_id, &params.target, api_tx) {
        Ok(agent) => agent,
        Err(response) => {
            return serde_json::to_string(&response)
                .map(Some)
                .map_err(std::io::Error::other);
        }
    };
    let target = params.target.clone();
    let prompt_response = dispatch_to_app_with_timeout(
        Request {
            id: request_id.clone(),
            method: Method::AgentPrompt(params),
        },
        api_tx,
        None,
    );
    let Ok(prompted) = agent_from_response(&request_id, &prompt_response) else {
        return Ok(Some(prompt_response));
    };
    if !agent_wait_identity_matches(
        &prompted,
        &before_prompt.terminal_id,
        before_prompt.name.as_deref().filter(|name| *name == target),
        before_prompt.agent.as_deref(),
    ) {
        return agent_wait_not_running(request_id).map(Some);
    }

    let wait_started = std::time::Instant::now();
    let prompt_state_change_seq = prompted.state_change_seq;
    let until = agent_wait_statuses(wait.until);
    let mut initial = prompted;
    let mut after_state_change_seq = Some(prompt_state_change_seq);

    if initial.agent_status != crate::api::schema::AgentStatus::Working {
        let effect_timeout_ms = wait
            .timeout_ms
            .map_or(AGENT_PROMPT_EFFECT_TIMEOUT_MS, |timeout_ms| {
                timeout_ms.min(AGENT_PROMPT_EFFECT_TIMEOUT_MS)
            });
        let timeout_kind = if wait
            .timeout_ms
            .is_some_and(|timeout_ms| timeout_ms <= AGENT_PROMPT_EFFECT_TIMEOUT_MS)
        {
            AgentWaitTimeoutKind::Status
        } else {
            AgentWaitTimeoutKind::PromptStalled {
                baseline: prompt_state_change_seq,
                timeout_ms: effect_timeout_ms,
            }
        };
        let Some(outcome) = wait_for_resolved_agent(
            request_id.clone(),
            ResolvedAgentWait {
                target: target.clone(),
                until: all_agent_statuses(),
                timeout_ms: Some(effect_timeout_ms),
                initial,
                last_event_sequence,
                after_state_change_seq,
                accept_transient_status: false,
                timeout_kind,
            },
            stream,
            api_tx,
            event_hub,
            running,
        )?
        else {
            return Ok(None);
        };
        initial = match outcome {
            AgentWaitOutcome::Matched(agent) => *agent,
            AgentWaitOutcome::Response(response) => return Ok(Some(response)),
        };
        after_state_change_seq = None;
        if agent_wait_matches(&initial, &until, None) {
            return agent_prompt_success(request_id, initial).map(Some);
        }
    }

    let Some(outcome) = wait_for_resolved_agent(
        request_id.clone(),
        ResolvedAgentWait {
            target,
            until,
            timeout_ms: remaining_timeout_ms(wait.timeout_ms, wait_started),
            initial,
            // Replay from before submission so terminal lifecycle events consumed by
            // the activity gate still terminate this settled-state wait.
            last_event_sequence,
            after_state_change_seq,
            accept_transient_status: false,
            timeout_kind: AgentWaitTimeoutKind::Status,
        },
        stream,
        api_tx,
        event_hub,
        running,
    )?
    else {
        return Ok(None);
    };
    let agent = match outcome {
        AgentWaitOutcome::Matched(agent) => *agent,
        AgentWaitOutcome::Response(response) => return Ok(Some(response)),
    };
    agent_prompt_success(request_id, agent).map(Some)
}

fn remaining_timeout_ms(total_ms: Option<u64>, started: std::time::Instant) -> Option<u64> {
    total_ms.map(|total_ms| {
        let elapsed_ms = started.elapsed().as_millis().min(u128::from(u64::MAX)) as u64;
        total_ms.saturating_sub(elapsed_ms)
    })
}

fn agent_prompt_success(
    request_id: String,
    agent: crate::api::schema::AgentInfo,
) -> std::io::Result<String> {
    serde_json::to_string(&SuccessResponse {
        id: request_id,
        result: ResponseResult::AgentPrompted { agent },
    })
    .map_err(std::io::Error::other)
}

struct ResolvedAgentWait {
    target: String,
    until: Vec<crate::api::schema::AgentStatus>,
    timeout_ms: Option<u64>,
    initial: crate::api::schema::AgentInfo,
    last_event_sequence: u64,
    after_state_change_seq: Option<u64>,
    accept_transient_status: bool,
    timeout_kind: AgentWaitTimeoutKind,
}

#[derive(Clone, Copy)]
enum AgentWaitTimeoutKind {
    Status,
    PromptStalled { baseline: u64, timeout_ms: u64 },
}

enum AgentWaitOutcome {
    Matched(Box<crate::api::schema::AgentInfo>),
    Response(String),
}

fn wait_for_resolved_agent(
    request_id: String,
    wait: ResolvedAgentWait,
    stream: &mut LocalStream,
    api_tx: &ApiRequestSender,
    event_hub: &EventHub,
    running: &Arc<AtomicBool>,
) -> std::io::Result<Option<AgentWaitOutcome>> {
    let deadline = wait
        .timeout_ms
        .map(|ms| std::time::Instant::now() + std::time::Duration::from_millis(ms));
    let expected_terminal_id = wait.initial.terminal_id.clone();
    let expected_name = wait
        .initial
        .name
        .as_ref()
        .filter(|name| name.as_str() == wait.target)
        .cloned();
    let expected_agent = wait.initial.agent.clone();
    let pane_id = wait.initial.pane_id.clone();
    let mut last_event_sequence = wait.last_event_sequence;

    loop {
        if should_stop_connection(stream, running)? {
            return Ok(None);
        }

        let mut should_probe = false;
        let mut matched_event_status = None;
        for (sequence, event) in event_hub.events_after(last_event_sequence) {
            last_event_sequence = sequence;
            match event.data {
                EventData::PaneAgentDetected {
                    pane_id: event_pane,
                    agent,
                    released,
                    final_status,
                    ..
                } if event_pane == pane_id => {
                    if released {
                        if let Some(status) = final_status
                            .filter(|status| wait.until.contains(status))
                            .or(matched_event_status)
                        {
                            let mut matched = wait.initial.clone();
                            matched.agent_status = status;
                            return Ok(Some(AgentWaitOutcome::Matched(Box::new(matched))));
                        }
                        return agent_wait_not_running(request_id)
                            .map(AgentWaitOutcome::Response)
                            .map(Some);
                    }
                    if agent.is_some() && expected_agent.is_some() && agent != expected_agent {
                        return agent_wait_not_running(request_id)
                            .map(AgentWaitOutcome::Response)
                            .map(Some);
                    }
                    should_probe = true;
                }
                EventData::PaneAgentStatusChanged {
                    pane_id: event_pane,
                    agent_status,
                    ..
                } if event_pane == pane_id => {
                    if wait.accept_transient_status && wait.until.contains(&agent_status) {
                        matched_event_status = Some(agent_status);
                    }
                    should_probe = true;
                }
                EventData::PaneUpdated { pane } if pane.pane_id == pane_id => should_probe = true,
                EventData::PaneMoved {
                    previous_pane_id, ..
                } if previous_pane_id == pane_id => {
                    return agent_wait_not_running(request_id)
                        .map(AgentWaitOutcome::Response)
                        .map(Some);
                }
                EventData::PaneClosed {
                    pane_id: event_pane,
                    ..
                }
                | EventData::PaneExited {
                    pane_id: event_pane,
                    ..
                } if event_pane == pane_id => {
                    return agent_wait_not_running(request_id)
                        .map(AgentWaitOutcome::Response)
                        .map(Some);
                }
                _ => {}
            }
        }

        if should_probe {
            let current = match agent_get(&request_id, &wait.target, api_tx) {
                Ok(agent) => agent,
                Err(response) => {
                    return agent_wait_probe_error(response)
                        .map(AgentWaitOutcome::Response)
                        .map(Some);
                }
            };
            if !agent_wait_identity_matches(
                &current,
                &expected_terminal_id,
                expected_name.as_deref(),
                expected_agent.as_deref(),
            ) {
                return agent_wait_not_running(request_id)
                    .map(AgentWaitOutcome::Response)
                    .map(Some);
            }
            if let Some(status) = matched_event_status {
                let mut matched = current;
                matched.agent_status = status;
                return Ok(Some(AgentWaitOutcome::Matched(Box::new(matched))));
            }
            if agent_wait_matches(&current, &wait.until, wait.after_state_change_seq) {
                return Ok(Some(AgentWaitOutcome::Matched(Box::new(current))));
            }
        }

        if deadline.is_some_and(|deadline| std::time::Instant::now() >= deadline) {
            let current = match agent_get(&request_id, &wait.target, api_tx) {
                Ok(agent) => agent,
                Err(response) => {
                    return agent_wait_probe_error(response)
                        .map(AgentWaitOutcome::Response)
                        .map(Some);
                }
            };
            if !agent_wait_identity_matches(
                &current,
                &expected_terminal_id,
                expected_name.as_deref(),
                expected_agent.as_deref(),
            ) {
                return agent_wait_not_running(request_id)
                    .map(AgentWaitOutcome::Response)
                    .map(Some);
            }
            if agent_wait_matches(&current, &wait.until, wait.after_state_change_seq) {
                return Ok(Some(AgentWaitOutcome::Matched(Box::new(current))));
            }
            return agent_wait_timeout(request_id, wait.timeout_kind, &current)
                .map(AgentWaitOutcome::Response)
                .map(Some);
        }
        std::thread::sleep(CONNECTION_POLL_INTERVAL);
    }
}

fn all_agent_statuses() -> Vec<crate::api::schema::AgentStatus> {
    // Keep this exhaustive: every status is evidence that the sequence advanced.
    vec![
        crate::api::schema::AgentStatus::Idle,
        crate::api::schema::AgentStatus::Working,
        crate::api::schema::AgentStatus::Blocked,
        crate::api::schema::AgentStatus::Done,
        crate::api::schema::AgentStatus::Unknown,
    ]
}

/// Statuses that count as wanting attention when the caller does not say.
///
/// Just `Blocked`, deliberately narrower than `agent.wait`'s default. This call exists
/// to answer "does anything need me right now", and a finished agent does not: it is
/// news, not a demand. Defaulting to include it would make the common invocation fire
/// constantly in a fleet where something finishes every few minutes, and a wait that
/// always returns immediately is worse than no wait at all.
fn attention_wait_statuses(
    until: Vec<crate::api::schema::AgentStatus>,
) -> Vec<crate::api::schema::AgentStatus> {
    if until.is_empty() {
        vec![crate::api::schema::AgentStatus::Blocked]
    } else {
        until
    }
}

/// Whether one agent satisfies an attention wait.
///
/// Pure, so the matching rules can be tested without a server. `launch_pending` agents
/// are excluded: an agent that has not started yet can report a status that is about
/// its absence rather than about anything a person could act on.
pub(crate) fn attention_match(
    agent: &crate::api::schema::AgentInfo,
    until: &[crate::api::schema::AgentStatus],
    host: Option<&str>,
    blocker: &[crate::api::schema::BlockerKind],
) -> bool {
    if agent.launch_pending {
        return false;
    }
    if !blocker.is_empty() {
        // An unknown kind never matches. Treating it as "might be the one you asked
        // for" would send someone to a question they asked not to be given.
        match agent.blocker {
            Some(kind) if blocker.contains(&kind) => {}
            _ => return false,
        }
    }
    if let Some(host) = host {
        // Absent means local, which no host filter should match: asking for a machine
        // by name and being handed a local pane would be actively misleading.
        if agent.host.as_deref() != Some(host) {
            return false;
        }
    }
    until.contains(&agent.agent_status)
}

/// Block until `count` agents want attention, on any machine or one named machine.
pub(super) fn wait_for_attention(
    request_id: String,
    params: crate::api::schema::AttentionWaitParams,
    stream: &mut LocalStream,
    api_tx: &ApiRequestSender,
    _event_hub: &EventHub,
    running: &Arc<AtomicBool>,
) -> std::io::Result<Option<String>> {
    let until = attention_wait_statuses(params.until);
    let host = params.host.clone();
    let blocker = params.blocker.clone();
    // Zero would match before anything happened, which is never what a caller means.
    let want = params.count.unwrap_or(1).max(1);
    let deadline = params
        .timeout_ms
        .map(|ms| std::time::Instant::now() + std::time::Duration::from_millis(ms));

    loop {
        match attention_matches(&request_id, &until, host.as_deref(), &blocker, api_tx) {
            Ok(matched) if matched.len() >= want => {
                return serde_json::to_string(&SuccessResponse {
                    id: request_id,
                    result: ResponseResult::AttentionMatched { agents: matched },
                })
                .map(Some)
                .map_err(std::io::Error::other);
            }
            Ok(_) => {}
            Err(response) => {
                return serde_json::to_string(&response)
                    .map(Some)
                    .map_err(std::io::Error::other);
            }
        }

        if deadline.is_some_and(|deadline| std::time::Instant::now() >= deadline) {
            return serde_json::to_string(&ErrorResponse {
                id: request_id,
                error: ErrorBody {
                    code: "timeout".into(),
                    message: "timed out waiting for an agent to want attention".into(),
                },
            })
            .map(Some)
            .map_err(std::io::Error::other);
        }

        // The client going away has to end this: a fleet-wide wait is the call most
        // likely to be left running for hours, so a leaked poll loop per abandoned
        // client would accumulate where it is least visible.
        if should_stop_connection(stream, running)? {
            return Ok(None);
        }

        std::thread::sleep(CONNECTION_POLL_INTERVAL);
    }
}

/// Rank an agent for ordering. Unclassifiable ones sort last rather than being dropped:
/// the caller asked for these statuses explicitly, so they belong in the answer even
/// when they are not a demand in their own right.
fn agent_demand_class(agent: &crate::api::schema::AgentInfo) -> (u8, u8) {
    use crate::api::schema::{AgentStatus, BlockerKind};
    let state = match agent.agent_status {
        AgentStatus::Blocked => crate::detect::AgentState::Blocked,
        AgentStatus::Working => crate::detect::AgentState::Working,
        AgentStatus::Idle | AgentStatus::Done => crate::detect::AgentState::Idle,
        AgentStatus::Unknown => crate::detect::AgentState::Unknown,
    };
    let blocker = match agent.blocker {
        Some(BlockerKind::Permission) => crate::detect::BlockerKind::Permission,
        Some(BlockerKind::Question) => crate::detect::BlockerKind::Question,
        Some(BlockerKind::Selection) => crate::detect::BlockerKind::Selection,
        Some(BlockerKind::Unknown) | None => crate::detect::BlockerKind::Unknown,
    };
    // `seen` is not carried on AgentInfo; a finished agent surfaced by a wait is by
    // definition one the caller has not looked at yet.
    match crate::attention::demand_class(state, blocker, false, agent.host_stopped) {
        Some(class) => (0, class as u8),
        None => (1, 0),
    }
}

fn attention_matches(
    request_id: &str,
    until: &[crate::api::schema::AgentStatus],
    host: Option<&str>,
    blocker: &[crate::api::schema::BlockerKind],
    api_tx: &ApiRequestSender,
) -> Result<Vec<crate::api::schema::AgentInfo>, ErrorResponse> {
    let response = dispatch_to_app_with_timeout(
        Request {
            id: format!("{request_id}:agents"),
            method: Method::AgentList(crate::api::schema::EmptyParams {}),
        },
        api_tx,
        Some(APP_RESPONSE_TIMEOUT),
    );
    let value: serde_json::Value = serde_json::from_str(&response).map_err(|_| ErrorResponse {
        id: request_id.into(),
        error: ErrorBody {
            code: "internal_error".into(),
            message: "could not read the agent list".into(),
        },
    })?;
    let agents = value
        .get("result")
        .and_then(|result| result.get("agents"))
        .cloned()
        .unwrap_or(serde_json::Value::Null);
    let agents: Vec<crate::api::schema::AgentInfo> =
        serde_json::from_value(agents).unwrap_or_default();

    let mut matched: Vec<crate::api::schema::AgentInfo> = agents
        .into_iter()
        .filter(|agent| attention_match(agent, until, host, blocker))
        .collect();
    // Most urgent first, and cheap-to-clear before expensive within that. Returning
    // them in whatever order the agent list happened to be in would leave the caller
    // to re-derive a ranking that herdr already knows.
    matched.sort_by_key(|agent| {
        (
            agent_demand_class(agent),
            // Stable within a class, so repeated calls do not shuffle.
            agent.terminal_id.clone(),
        )
    });
    Ok(matched)
}

fn agent_wait_statuses(
    until: Vec<crate::api::schema::AgentStatus>,
) -> Vec<crate::api::schema::AgentStatus> {
    if until.is_empty() {
        vec![
            crate::api::schema::AgentStatus::Idle,
            crate::api::schema::AgentStatus::Done,
            crate::api::schema::AgentStatus::Blocked,
        ]
    } else {
        until
    }
}

fn agent_wait_identity_matches(
    agent: &crate::api::schema::AgentInfo,
    expected_terminal_id: &str,
    expected_name: Option<&str>,
    expected_agent: Option<&str>,
) -> bool {
    agent.terminal_id == expected_terminal_id
        && expected_name.is_none_or(|name| agent.name.as_deref() == Some(name))
        && match (expected_agent, agent.agent.as_deref()) {
            (Some(expected), Some(current)) => expected == current,
            (Some(_), None) => agent.name.is_some(),
            (None, _) => true,
        }
}

fn agent_wait_matches(
    agent: &crate::api::schema::AgentInfo,
    until: &[crate::api::schema::AgentStatus],
    after_state_change_seq: Option<u64>,
) -> bool {
    until.contains(&agent.agent_status)
        && after_state_change_seq.is_none_or(|baseline| agent.state_change_seq > baseline)
}

fn agent_get(
    request_id: &str,
    target: &str,
    api_tx: &ApiRequestSender,
) -> Result<crate::api::schema::AgentInfo, ErrorResponse> {
    let response = dispatch_to_app_with_timeout(
        Request {
            id: format!("{request_id}:agent"),
            method: Method::AgentGet(crate::api::schema::AgentTarget {
                target: target.to_string(),
            }),
        },
        api_tx,
        Some(APP_RESPONSE_TIMEOUT),
    );
    agent_from_response(request_id, &response)
}

fn agent_from_response(
    request_id: &str,
    response: &str,
) -> Result<crate::api::schema::AgentInfo, ErrorResponse> {
    let value: serde_json::Value = serde_json::from_str(response).map_err(|_| ErrorResponse {
        id: request_id.into(),
        error: ErrorBody {
            code: "internal_error".into(),
            message: "failed to decode agent response".into(),
        },
    })?;
    if value.get("error").is_some() {
        let error = serde_json::from_value(value["error"].clone()).map_err(|_| ErrorResponse {
            id: request_id.into(),
            error: ErrorBody {
                code: "internal_error".into(),
                message: "failed to decode agent error".into(),
            },
        })?;
        return Err(ErrorResponse {
            id: request_id.into(),
            error,
        });
    }
    serde_json::from_value(value["result"]["agent"].clone()).map_err(|_| ErrorResponse {
        id: request_id.into(),
        error: ErrorBody {
            code: "internal_error".into(),
            message: "failed to decode agent result".into(),
        },
    })
}

fn agent_wait_success(
    request_id: String,
    agent: crate::api::schema::AgentInfo,
) -> std::io::Result<String> {
    serde_json::to_string(&SuccessResponse {
        id: request_id,
        result: ResponseResult::AgentInfo { agent },
    })
    .map_err(std::io::Error::other)
}

fn agent_wait_timeout(
    request_id: String,
    kind: AgentWaitTimeoutKind,
    current: &crate::api::schema::AgentInfo,
) -> std::io::Result<String> {
    let (code, message) = match kind {
        AgentWaitTimeoutKind::Status => {
            ("timeout", "timed out waiting for agent status".to_string())
        }
        AgentWaitTimeoutKind::PromptStalled {
            baseline,
            timeout_ms,
        } => {
            let status = format!("{:?}", current.agent_status).to_ascii_lowercase();
            (
                "agent_prompt_stalled",
                format!(
                    "agent prompt produced no observed state change within {timeout_ms} ms; status is {status} and state_change_seq remained {baseline}"
                ),
            )
        }
    };
    serde_json::to_string(&ErrorResponse {
        id: request_id,
        error: ErrorBody {
            code: code.into(),
            message,
        },
    })
    .map_err(std::io::Error::other)
}

fn agent_wait_not_running(request_id: String) -> std::io::Result<String> {
    serde_json::to_string(&ErrorResponse {
        id: request_id,
        error: ErrorBody {
            code: "agent_not_running".into(),
            message: "agent is no longer running in the target pane".into(),
        },
    })
    .map_err(std::io::Error::other)
}

fn agent_wait_probe_error(response: ErrorResponse) -> std::io::Result<String> {
    if response.error.code == "agent_not_found" {
        return agent_wait_not_running(response.id);
    }
    serde_json::to_string(&response).map_err(std::io::Error::other)
}

pub(super) fn wait_for_event(
    request_id: String,
    params: EventsWaitParams,
    stream: &mut LocalStream,
    api_tx: &ApiRequestSender,
    event_hub: &EventHub,
    running: &Arc<AtomicBool>,
) -> std::io::Result<Option<String>> {
    let deadline = params
        .timeout_ms
        .map(|ms| std::time::Instant::now() + std::time::Duration::from_millis(ms));

    let subscription = match event_match_subscription(&request_id, params.match_event) {
        Ok(subscription) => subscription,
        Err(response) => return Ok(Some(serde_json::to_string(&response).unwrap())),
    };
    let mut active = match ActiveSubscription::new(subscription, &request_id, 0, api_tx, event_hub)
    {
        Ok(active) => active,
        Err(response) => return Ok(Some(serde_json::to_string(&response).unwrap())),
    };

    loop {
        if should_stop_connection(stream, running)? {
            return Ok(None);
        }

        match active.poll_for_wait(api_tx, event_hub) {
            Ok(Some(event)) => return Ok(Some(wait_matched_response(&request_id, event))),
            Ok(None) => {}
            Err(mut response) if response.error.code == "pane_not_found" => {
                response.id = request_id;
                return serde_json::to_string(&response)
                    .map(Some)
                    .map_err(std::io::Error::other);
            }
            Err(_) => {}
        }

        if deadline.is_some_and(|deadline| std::time::Instant::now() >= deadline) {
            return Ok(Some(
                serde_json::to_string(&ErrorResponse {
                    id: request_id,
                    error: ErrorBody {
                        code: "timeout".into(),
                        message: "timed out waiting for event match".into(),
                    },
                })
                .unwrap(),
            ));
        }

        std::thread::sleep(CONNECTION_POLL_INTERVAL);
    }
}

fn event_match_subscription(
    request_id: &str,
    match_event: EventMatch,
) -> Result<Subscription, ErrorResponse> {
    match match_event {
        EventMatch::PaneAgentStatusChanged {
            pane_id,
            agent_status,
        } => Ok(Subscription::PaneAgentStatusChanged {
            pane_id,
            agent_status: Some(agent_status),
        }),
        _ => Err(ErrorResponse {
            id: request_id.into(),
            error: ErrorBody {
                code: "unsupported_event_wait_match".into(),
                message: "events.wait currently supports pane agent status matches".into(),
            },
        }),
    }
}

fn wait_matched_response(request_id: &str, event: serde_json::Value) -> String {
    let Ok(event) = serde_json::from_value::<SubscriptionEventEnvelope>(event) else {
        return serde_json::to_string(&ErrorResponse {
            id: request_id.into(),
            error: ErrorBody {
                code: "internal_error".into(),
                message: "failed to decode matched event".into(),
            },
        })
        .unwrap();
    };

    let SubscriptionEventData::PaneAgentStatusChanged(data) = event.data else {
        return serde_json::to_string(&ErrorResponse {
            id: request_id.into(),
            error: ErrorBody {
                code: "unsupported_event_wait_match".into(),
                message: "events.wait currently supports pane agent status matches".into(),
            },
        })
        .unwrap();
    };

    serde_json::to_string(&SuccessResponse {
        id: request_id.into(),
        result: ResponseResult::WaitMatched {
            event: EventEnvelope {
                event: EventKind::PaneAgentStatusChanged,
                data: EventData::PaneAgentStatusChanged {
                    pane_id: data.pane_id,
                    workspace_id: data.workspace_id,
                    agent_status: data.agent_status,
                    agent: data.agent,
                    title: data.title,
                    display_agent: data.display_agent,
                    state_labels: data.state_labels,
                },
            },
        },
    })
    .unwrap()
}

#[cfg(test)]
mod attention_tests {
    use super::attention_match;
    use crate::api::schema::{AgentInfo, AgentStatus, BlockerKind};

    fn agent(status: AgentStatus, host: Option<&str>) -> AgentInfo {
        AgentInfo {
            terminal_id: "t1".into(),
            host: host.map(str::to_string),
            message: None,
            name: None,
            agent: None,
            title: None,
            terminal_title: None,
            terminal_title_stripped: None,
            display_agent: None,
            agent_status: status,
            blocker: None,
            host_stopped: false,
            screen_detection_skipped: false,
            state_labels: Default::default(),
            tokens: Default::default(),
            agent_session: None,
            workspace_id: "w1".into(),
            tab_id: "w1:t1".into(),
            pane_id: "w1:p1".into(),
            focused: false,
            launch_pending: false,
            interactive_ready: true,
            state_change_seq: 0,
            cwd: None,
            foreground_cwd: None,
            revision: 1,
        }
    }

    #[test]
    fn the_default_is_blocked_alone() {
        // A product decision, pinned directly because it is not observable end to end:
        // a session with no agents times out whatever the default set is, so widening
        // it silently breaks nothing until a real fleet is attached and the call starts
        // returning instantly. `Idle` and `Unknown` are the dangerous ones — most agents
        // are in one of them most of the time.
        assert_eq!(
            super::attention_wait_statuses(Vec::new()),
            vec![AgentStatus::Blocked]
        );
        // An explicit request is honoured exactly, never widened.
        assert_eq!(
            super::attention_wait_statuses(vec![AgentStatus::Done]),
            vec![AgentStatus::Done]
        );
    }

    #[test]
    fn only_the_requested_statuses_wake_a_wait() {
        let until = [AgentStatus::Blocked];
        assert!(attention_match(
            &agent(AgentStatus::Blocked, None),
            &until,
            None,
            &[]
        ));
        for status in [
            AgentStatus::Working,
            AgentStatus::Idle,
            AgentStatus::Done,
            AgentStatus::Unknown,
        ] {
            assert!(
                !attention_match(&agent(status, None), &until, None, &[]),
                "{status:?} should not wake a wait for blocked"
            );
        }
    }

    #[test]
    fn a_host_filter_excludes_other_hosts_and_local_panes() {
        let until = [AgentStatus::Blocked];
        assert!(attention_match(
            &agent(AgentStatus::Blocked, Some("box1")),
            &until,
            Some("box1"),
            &[],
        ));
        assert!(!attention_match(
            &agent(AgentStatus::Blocked, Some("box2")),
            &until,
            Some("box1"),
            &[],
        ));
        // A local pane has no host. Asking for a machine by name and being handed a
        // local pane would be actively misleading — the caller is about to act on
        // something they believe is elsewhere.
        assert!(!attention_match(
            &agent(AgentStatus::Blocked, None),
            &until,
            Some("box1"),
            &[]
        ));
    }

    #[test]
    fn no_host_filter_spans_every_machine_including_local() {
        // The whole reason this call exists: one wait covering the fleet.
        let until = [AgentStatus::Blocked];
        for host in [None, Some("box1"), Some("box2")] {
            assert!(attention_match(
                &agent(AgentStatus::Blocked, host),
                &until,
                None,
                &[]
            ));
        }
    }

    #[test]
    fn an_agent_that_has_not_launched_yet_does_not_count() {
        // Its status describes its absence, not anything a person could act on, so
        // waking someone for it wastes the one thing this is meant to protect.
        let mut pending = agent(AgentStatus::Blocked, None);
        pending.launch_pending = true;
        assert!(!attention_match(
            &pending,
            &[AgentStatus::Blocked],
            None,
            &[]
        ));
    }

    #[test]
    fn a_blocker_filter_narrows_within_blocked() {
        // The reason the kind is tracked at all: batching cheap approvals without
        // being pulled into a question that needs thinking about.
        let until = [AgentStatus::Blocked];
        let mut permission = agent(AgentStatus::Blocked, None);
        permission.blocker = Some(BlockerKind::Permission);
        let mut question = agent(AgentStatus::Blocked, None);
        question.blocker = Some(BlockerKind::Question);

        assert!(attention_match(
            &permission,
            &until,
            None,
            &[BlockerKind::Permission]
        ));
        assert!(!attention_match(
            &question,
            &until,
            None,
            &[BlockerKind::Permission]
        ));
        // No filter means every blocked agent, whatever kind.
        assert!(attention_match(&question, &until, None, &[]));
    }

    #[test]
    fn an_unknown_blocker_kind_never_matches_a_filter() {
        // Guessing would defeat the point. A question answered as if it were a quick
        // approval costs exactly the attention the filter exists to protect, so an
        // agent whose kind the rule did not say is left out rather than included on
        // the chance it might be the one asked for.
        let until = [AgentStatus::Blocked];
        let mut unspecified = agent(AgentStatus::Blocked, None);
        unspecified.blocker = None;
        assert!(!attention_match(
            &unspecified,
            &until,
            None,
            &[BlockerKind::Permission]
        ));
        // And it still matches when no kind was asked for.
        assert!(attention_match(&unspecified, &until, None, &[]));
    }

    #[test]
    fn several_statuses_can_be_requested_at_once() {
        let until = [AgentStatus::Blocked, AgentStatus::Done];
        assert!(attention_match(
            &agent(AgentStatus::Blocked, None),
            &until,
            None,
            &[]
        ));
        assert!(attention_match(
            &agent(AgentStatus::Done, None),
            &until,
            None,
            &[]
        ));
        assert!(!attention_match(
            &agent(AgentStatus::Working, None),
            &until,
            None,
            &[]
        ));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn agent_wait_probe_only_translates_agent_disappearance() {
        let disappeared = agent_wait_probe_error(ErrorResponse {
            id: "wait".into(),
            error: ErrorBody {
                code: "agent_not_found".into(),
                message: "missing".into(),
            },
        })
        .unwrap();
        let disappeared: ErrorResponse = serde_json::from_str(&disappeared).unwrap();
        assert_eq!(disappeared.id, "wait");
        assert_eq!(disappeared.error.code, "agent_not_running");

        let unavailable = agent_wait_probe_error(ErrorResponse {
            id: "wait".into(),
            error: ErrorBody {
                code: "server_unavailable".into(),
                message: "timed out waiting for app response".into(),
            },
        })
        .unwrap();
        let unavailable: ErrorResponse = serde_json::from_str(&unavailable).unwrap();
        assert_eq!(unavailable.id, "wait");
        assert_eq!(unavailable.error.code, "server_unavailable");
    }
}
