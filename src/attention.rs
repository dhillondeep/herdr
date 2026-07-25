//! How much a pane, tab, or workspace wants a human's attention.
//!
//! This ranking was previously duplicated three times — in the sidebar, in the API
//! helpers, and in workspace aggregation — under three different names. The copies
//! happened to agree, but nothing made them agree, so any change to one would
//! silently disagree with the others and a tab would rank differently from the
//! workspace containing it.
//!
//! Pure and free of PTY or app state, so the ordering can be tested directly.

use crate::detect::AgentState;

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
