//! How much a pane, tab, or workspace wants a human's attention.
//!
//! This ranking was previously duplicated three times — in the sidebar, in the API
//! helpers, and in workspace aggregation — under three different names. The copies
//! happened to agree, but nothing made them agree, so any change to one would
//! silently disagree with the others and a tab would rank differently from the
//! workspace containing it.
//!
//! Pure and free of PTY or app state, so the ordering can be tested directly.

use crate::detect::{AgentState, BlockerKind};

/// How expensive the attention an agent wants is, ranked.
///
/// The flat priority answers "who is waiting"; this answers "what will it cost me",
/// which is the question that matters once the list is long. A permission prompt is a
/// two-second keystroke and an open question is a two-minute think, so ranking them
/// together makes a queue of twenty blocked agents impossible to work down
/// efficiently — you cannot tell which five you could clear on the way to lunch.
///
/// Ordered most urgent first, via `Ord` on the declaration order.
///
/// `Working` has no class on purpose: it is not waiting for anybody, and putting it in
/// a queue of things that want a person would bury the ones that do.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum DemandClass {
    /// The agent cannot continue for a reason a person must resolve elsewhere — a
    /// usage limit, a dead host. Ranked first because nothing else recovers on its
    /// own, and unlike a prompt it is not even visible unless something says so.
    Fault,
    /// Blocked on approving or denying something. Cheap to clear, so it comes before
    /// the expensive kinds: clearing it unblocks work immediately.
    BlockedDecision,
    /// Blocked on a question or a choice that needs thought.
    BlockedQuestion,
    /// Blocked, but the rule did not say how. Ranked after the known kinds rather than
    /// guessed into one of them.
    BlockedUnknown,
    /// Finished and not yet looked at. A result nobody has seen is the thing most
    /// likely to be forgotten, but it is news rather than a demand.
    Done,
}

/// Classify what an agent wants, or `None` if it wants nothing.
///
/// `host_stopped` outranks the agent's last known state: a pane whose machine went away
/// may well have been `Idle` when the link died, and reporting that would present lost
/// work as finished work.
pub fn demand_class(
    state: AgentState,
    blocker: BlockerKind,
    seen: bool,
    fault: bool,
    host_stopped: bool,
) -> Option<DemandClass> {
    // Both outrank the agent's own reported state, and for the same reason: a stuck or
    // lost agent frequently *looks* idle, so trusting the state would file it with the
    // work that finished.
    if fault || host_stopped {
        return Some(DemandClass::Fault);
    }
    match state {
        AgentState::Blocked => Some(match blocker {
            BlockerKind::Permission => DemandClass::BlockedDecision,
            BlockerKind::Question | BlockerKind::Selection => DemandClass::BlockedQuestion,
            BlockerKind::Unknown => DemandClass::BlockedUnknown,
        }),
        // Only unseen: once it has been looked at, a finished agent is capacity rather
        // than something owed.
        AgentState::Idle if !seen => Some(DemandClass::Done),
        AgentState::Idle | AgentState::Working | AgentState::Unknown => None,
    }
}

/// Rank a pane's state by how much attention it wants. Higher wants more.
///
/// The order is the product decision, not an implementation detail:
///
/// - **Blocked** outranks everything: the agent has stopped and cannot continue
///   without a human.
/// - **Finished but unseen** (`Idle` with `seen == false`) outranks working,
///   because a result nobody has looked at is the thing most likely to be
///   forgotten.
/// - **Working** outranks a seen idle pane: it may still need something later,
///   whereas a seen idle pane is done and acknowledged.
/// - **Seen idle** is capacity rather than demand.
/// - **Unknown** ranks last: herdr does not know there is an agent there at all,
///   so promoting it would push real demand down the list.
pub fn pane_attention_priority(state: AgentState, seen: bool) -> u8 {
    match (state, seen) {
        (AgentState::Blocked, _) => 4,
        (AgentState::Idle, false) => 3,
        (AgentState::Working, _) => 2,
        (AgentState::Idle, true) => 1,
        (AgentState::Unknown, _) => 0,
    }
}

#[cfg(test)]
mod demand_tests {
    use super::*;

    #[test]
    fn cheap_attention_outranks_expensive_attention() {
        // The reason this exists at all. Twenty blocked agents are unworkable if you
        // cannot tell which ones you could clear on the way past.
        assert!(
            demand_class(
                AgentState::Blocked,
                BlockerKind::Permission,
                false,
                false,
                false
            ) < demand_class(
                AgentState::Blocked,
                BlockerKind::Question,
                false,
                false,
                false
            )
        );
    }

    #[test]
    fn a_lost_host_outranks_everything_and_ignores_the_last_known_state() {
        // A pane whose machine went away may well have been Idle when the link died.
        // Reporting that would present lost work as finished work.
        for state in [
            AgentState::Idle,
            AgentState::Working,
            AgentState::Blocked,
            AgentState::Unknown,
        ] {
            assert_eq!(
                demand_class(state, BlockerKind::Unknown, true, false, true),
                Some(DemandClass::Fault),
                "{state:?} on a stopped host must rank as a fault"
            );
        }
        assert!(Some(DemandClass::Fault) < Some(DemandClass::BlockedDecision));
    }

    #[test]
    fn a_fault_outranks_everything_and_ignores_the_reported_state() {
        // The screens that mean "out of quota" read as idle. Trusting the state would
        // file a stopped agent with the ones that finished, which is how hours go
        // missing without anybody looking.
        for state in [
            AgentState::Idle,
            AgentState::Working,
            AgentState::Blocked,
            AgentState::Unknown,
        ] {
            assert_eq!(
                demand_class(state, BlockerKind::Unknown, false, true, false),
                Some(DemandClass::Fault),
                "{state:?} with a fault must rank as a fault"
            );
        }
        assert!(Some(DemandClass::Fault) < Some(DemandClass::BlockedDecision));
    }

    #[test]
    fn working_is_not_a_demand() {
        // It is not waiting for anybody, and queueing it would bury the ones that are.
        assert_eq!(
            demand_class(
                AgentState::Working,
                BlockerKind::Unknown,
                false,
                false,
                false
            ),
            None
        );
    }

    #[test]
    fn a_finished_agent_stops_being_a_demand_once_it_has_been_seen() {
        assert_eq!(
            demand_class(AgentState::Idle, BlockerKind::Unknown, false, false, false),
            Some(DemandClass::Done)
        );
        assert_eq!(
            demand_class(AgentState::Idle, BlockerKind::Unknown, true, false, false),
            None
        );
    }

    #[test]
    fn an_unknown_blocker_ranks_after_the_known_kinds_rather_than_guessing() {
        // Guessing it into `permission` would send someone to a question expecting a
        // keystroke, which costs exactly the attention this ordering protects.
        assert!(
            demand_class(
                AgentState::Blocked,
                BlockerKind::Question,
                false,
                false,
                false
            ) < demand_class(
                AgentState::Blocked,
                BlockerKind::Unknown,
                false,
                false,
                false
            )
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Characterization tests: these pin the ranking that the three former copies
    // implemented, so consolidating them cannot quietly change how anything sorts.

    #[test]
    fn every_state_keeps_its_established_rank() {
        assert_eq!(pane_attention_priority(AgentState::Blocked, false), 4);
        assert_eq!(pane_attention_priority(AgentState::Blocked, true), 4);
        assert_eq!(pane_attention_priority(AgentState::Idle, false), 3);
        assert_eq!(pane_attention_priority(AgentState::Working, false), 2);
        assert_eq!(pane_attention_priority(AgentState::Working, true), 2);
        assert_eq!(pane_attention_priority(AgentState::Idle, true), 1);
        assert_eq!(pane_attention_priority(AgentState::Unknown, false), 0);
        assert_eq!(pane_attention_priority(AgentState::Unknown, true), 0);
    }

    #[test]
    fn blocked_outranks_everything_else() {
        let blocked = pane_attention_priority(AgentState::Blocked, false);
        for (state, seen) in [
            (AgentState::Idle, false),
            (AgentState::Idle, true),
            (AgentState::Working, false),
            (AgentState::Unknown, false),
        ] {
            assert!(
                blocked > pane_attention_priority(state, seen),
                "blocked should outrank {state:?}/{seen}"
            );
        }
    }

    #[test]
    fn a_finished_but_unseen_pane_outranks_one_still_working() {
        // A result nobody has looked at is the thing most likely to be forgotten.
        assert!(
            pane_attention_priority(AgentState::Idle, false)
                > pane_attention_priority(AgentState::Working, false)
        );
    }

    #[test]
    fn seeing_a_finished_pane_drops_it_below_working() {
        // Acknowledging a result turns demand into capacity.
        assert!(
            pane_attention_priority(AgentState::Idle, true)
                < pane_attention_priority(AgentState::Working, true)
        );
    }

    #[test]
    fn unknown_never_outranks_a_real_agent_state() {
        let unknown = pane_attention_priority(AgentState::Unknown, false);
        for (state, seen) in [
            (AgentState::Idle, true),
            (AgentState::Working, false),
            (AgentState::Idle, false),
            (AgentState::Blocked, false),
        ] {
            assert!(
                unknown < pane_attention_priority(state, seen),
                "unknown should not outrank {state:?}/{seen}"
            );
        }
    }

    #[test]
    fn seen_only_matters_for_idle() {
        // Blocked and working panes rank the same whether or not they have been
        // looked at; only a finished pane changes rank on being seen.
        for state in [
            AgentState::Blocked,
            AgentState::Working,
            AgentState::Unknown,
        ] {
            assert_eq!(
                pane_attention_priority(state, false),
                pane_attention_priority(state, true),
                "{state:?} should not depend on seen"
            );
        }
        assert_ne!(
            pane_attention_priority(AgentState::Idle, false),
            pane_attention_priority(AgentState::Idle, true)
        );
    }
}
