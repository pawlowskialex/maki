//! The bridge from the host's hooks ([`maki_agent::tools::hook`] and
//! [`maki_agent::agent::hook`]) to the slot chains plugins register.
//! Everything here is a hop: the agent asks, the Lua thread answers, and
//! nothing decides anything on the way.

use std::sync::Arc;
use std::time::Instant;

use flume::Sender;
use maki_agent::agent::{AgentCall, AgentHook, AgentSlot};
use maki_agent::tools::hook::{
    Authority, Decision, HookCall, HookStage, PermissionCall, PermissionHook, ToolHook, Verdict,
};
use maki_agent::tools::registry::BoxFuture;
use serde_json::{Value, json};

use crate::api::slot::{ANY_TOOL, DECIDE_SLOT, LayeredTools, host_slot_name};
use crate::runtime::{HookRun, Request};

/// Every `agent.*` slot steers what the agent does next: the prompt it
/// answers, whether it stops, what it remembers after a compaction. No
/// narrower price would be honest. `permission.decide` hands out the permission
/// the user would have granted, which is every tool there is.
const UNBOUNDED_SLOT_AUTHORITY: Authority = Authority::Unbounded;

/// Fields of the decision table a [`PermissionHook`] layer answers with.
const DECIDE_EFFECT: &str = "effect";
const DECIDE_REASON: &str = "reason";
const EFFECT_ALLOW: &str = "allow";
const EFFECT_DENY: &str = "deny";
const EFFECT_PROMPT: &str = "prompt";

pub(crate) struct SlotHook {
    pub(crate) tx: Sender<Request>,
    pub(crate) layered: Arc<LayeredTools>,
}

fn deadline_ms(deadline: Instant) -> u64 {
    deadline
        .saturating_duration_since(Instant::now())
        .as_millis() as u64
}

impl SlotHook {
    /// A runtime that is gone, or one that drops the request on the way
    /// down, leaves the value as it found it. A missing opinion is not a
    /// failure of whatever asked for it.
    fn send(&self, run: HookRun) -> BoxFuture<'_, Verdict> {
        let (reply, answer) = flume::bounded(1);
        let request = Request::RunHook { run, reply };
        Box::pin(async move {
            if self.tx.send_async(request).await.is_err() {
                return Verdict::Unchanged;
            }
            answer.recv_async().await.unwrap_or(Verdict::Unchanged)
        })
    }
}

impl ToolHook for SlotHook {
    fn wraps(&self, tool: &str, stage: HookStage) -> bool {
        self.layered.wraps(tool, stage)
    }

    fn run<'a>(
        &'a self,
        stage: HookStage,
        value: Value,
        call: &'a HookCall<'a>,
    ) -> BoxFuture<'a, Verdict> {
        self.send(HookRun {
            slots: vec![
                host_slot_name(call.tool, stage),
                host_slot_name(ANY_TOOL, stage),
            ],
            authority: call.authority,
            cancel: call.cancel.clone(),
            deadline: call.deadline,
            value,
            // The `ctx` table a layer receives.
            call: json!({
                "tool": call.tool,
                "tool_id": call.tool_id,
                "tool_kind": call.tool_kind,
                "input": call.input,
                "session_id": call.session_id,
                "origin": call.origin.as_str(),
                "deadline_ms": deadline_ms(call.deadline),
            }),
            may_ask: stage == HookStage::Input,
        })
    }
}

impl AgentHook for SlotHook {
    fn wraps(&self, slot: AgentSlot) -> bool {
        self.layered.layers_surface(slot.name())
    }

    fn run<'a>(
        &'a self,
        slot: AgentSlot,
        value: Value,
        call: &'a AgentCall<'a>,
    ) -> BoxFuture<'a, Verdict> {
        self.send(HookRun {
            slots: vec![slot.name().to_owned()],
            authority: UNBOUNDED_SLOT_AUTHORITY,
            cancel: call.cancel.clone(),
            deadline: call.deadline,
            value,
            call: json!({
                "session_id": call.session_id,
                "task_id": call.task_id,
                "model": call.model,
                "context_size": call.context_size,
                "context_window": call.context_window,
                "deadline_ms": deadline_ms(call.deadline),
            }),
            may_ask: false,
        })
    }
}

impl PermissionHook for SlotHook {
    fn wraps(&self) -> bool {
        self.layered.layers_surface(DECIDE_SLOT)
    }

    fn run<'a>(&'a self, call: &'a PermissionCall<'a>) -> BoxFuture<'a, Decision> {
        let answer = self.send(HookRun {
            slots: vec![DECIDE_SLOT.to_owned()],
            authority: UNBOUNDED_SLOT_AUTHORITY,
            cancel: call.cancel.clone(),
            deadline: call.deadline,
            // The value is the decision itself, so a layer passing it down with
            // `prev` reads as "no opinion" without having to know what maki
            // would have done.
            value: json!({ DECIDE_EFFECT: EFFECT_PROMPT }),
            call: json!({
                "tool": call.tool,
                "scopes": call.scopes,
                "mode": call.mode,
                "auto_calls": call.auto_calls,
                "max_auto_calls": call.max_auto_calls,
                "deadline_ms": deadline_ms(call.deadline),
            }),
            may_ask: false,
        });
        Box::pin(async move { decision(answer.await) })
    }
}

/// A layer that answers with nothing maki understands leaves the prompt where
/// it was: the user is the fallback for every unreadable answer.
fn decision(verdict: Verdict) -> Decision {
    let value = match verdict {
        Verdict::Unchanged => return Decision::Fallthrough,
        Verdict::Denied(reason) | Verdict::Ask { reason, .. } => {
            return Decision::Deny(Some(reason));
        }
        Verdict::Replaced(value) => value,
    };
    let reason = || {
        value
            .get(DECIDE_REASON)
            .and_then(Value::as_str)
            .map(str::to_owned)
    };
    match value.get(DECIDE_EFFECT).and_then(Value::as_str) {
        Some(EFFECT_ALLOW) => Decision::Allow,
        Some(EFFECT_DENY) => Decision::Deny(reason()),
        Some(EFFECT_PROMPT) => Decision::Prompt(reason()),
        other => {
            tracing::warn!(
                effect = ?other,
                "a {DECIDE_SLOT} layer answered with no readable `{DECIDE_EFFECT}`, asking the user"
            );
            Decision::Fallthrough
        }
    }
}

#[cfg(test)]
mod tests {
    use test_case::test_case;

    use super::*;

    const REASON: &str = "not in this repo";

    #[test_case(Verdict::Unchanged => Decision::Fallthrough ; "no_opinion_asks_the_user")]
    #[test_case(Verdict::Replaced(json!({ DECIDE_EFFECT: EFFECT_ALLOW })) => Decision::Allow ; "allow")]
    #[test_case(Verdict::Replaced(json!({ DECIDE_EFFECT: EFFECT_PROMPT })) => Decision::Prompt(None) ; "prompt")]
    #[test_case(
        Verdict::Replaced(json!({ DECIDE_EFFECT: EFFECT_DENY, DECIDE_REASON: REASON }))
        => Decision::Deny(Some(REASON.to_owned())) ; "deny_carries_its_reason"
    )]
    #[test_case(Verdict::Denied(REASON.to_owned()) => Decision::Deny(Some(REASON.to_owned())) ; "stopping_the_chain_denies")]
    // A table maki cannot read is not a grant: the user is the fallback for
    // every answer that does not say what it wants.
    #[test_case(Verdict::Replaced(json!({ DECIDE_EFFECT: "maybe" })) => Decision::Fallthrough ; "an_unknown_effect_asks_the_user")]
    #[test_case(Verdict::Replaced(json!({})) => Decision::Fallthrough ; "so_does_an_empty_table")]
    fn a_layers_answer_becomes_a_decision(verdict: Verdict) -> Decision {
        decision(verdict)
    }
}
