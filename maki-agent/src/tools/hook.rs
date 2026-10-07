//! One interception point for tool calls, shared by every route dispatch
//! knows: registry tools, MCP tools, and host (ACP client) tools alike.
//!
//! It lives on the [`ToolRegistry`](super::registry::ToolRegistry) rather than
//! on the [`Tool`](super::Tool) trait, so a tool is hookable because dispatch
//! reached it, not because whoever wrote it remembered to ask.

use std::path::Path;
use std::time::Instant;

use serde_json::Value;

use super::CallOrigin;
use super::registry::BoxFuture;
use crate::cancel::CancelToken;
use maki_config::Permission;

/// Fields of the value a [`HookStage::Output`] hook sees and returns.
pub const OUTPUT_TEXT: &str = "text";
pub const OUTPUT_IS_ERROR: &str = "is_error";

/// The effects a [`Decision`] goes by, wherever it is spelled out.
pub const EFFECT_ALLOW: &str = "allow";
pub const EFFECT_DENY: &str = "deny";
pub const EFFECT_PROMPT: &str = "prompt";

#[derive(Clone, Copy, PartialEq, Eq, Debug, Hash)]
pub enum HookStage {
    /// Before the input is parsed and before permission rules resolve, so
    /// rules judge the call as the hook left it. Any later and a hook could
    /// smuggle in an argument the rules never approved.
    Input,
    /// After the call finished, on the text it produced (failures included),
    /// before that text becomes history.
    Output,
}

impl HookStage {
    /// Order matters: stages index array slots via `as usize`.
    pub const ALL: [Self; 2] = [Self::Input, Self::Output];

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Input => "input",
            Self::Output => "output",
        }
    }
}

/// What hooking a call would hand whoever wrote the hook. Rewriting an input
/// decides what the tool then does, so the host prices that before it lets
/// untrusted code near it.
///
/// There is no "free" variant on purpose. A tool declaring no capability has
/// not told us it exercises none, only that nothing asks: `batch`, `task` and
/// `code_execution` declare nothing and reach every other tool. So a tool
/// landing tomorrow is never silently free to layer.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Authority {
    /// Exactly the capability the tool declares; a layer needs that one.
    Capability(Permission),
    /// Reach nobody declared: a tool naming no capability, an MCP server tool,
    /// an ACP client tool, search. A layer needs every capability, because no
    /// narrower answer would be honest.
    Unbounded,
}

pub struct HookCall<'a> {
    pub tool: &'a str,
    pub tool_id: &'a str,
    /// The group the tool files itself under (`read`, `edit`, `execute`,
    /// ...), so a layer wrapping every tool can skip the harmless ones.
    pub tool_kind: Option<&'a str>,
    /// Only set for [`HookStage::Output`], so a layer judging a result never
    /// has to stash the call that produced it.
    pub input: Option<&'a Value>,
    pub session_id: Option<&'a str>,
    pub origin: CallOrigin,
    pub authority: Authority,
    /// The call's own cancellation, so a hook that runs elsewhere (the Lua
    /// thread) dies with the call rather than outliving the reply channel.
    pub cancel: &'a CancelToken,
    /// When the chain has to be dead by, whatever it is waiting on.
    pub deadline: Instant,
}

/// How a hook answered. `Unchanged` also covers every way a hook can fail: a
/// hook is an opinion about a call, never a precondition for making it, so a
/// broken one costs exactly what no hook costs.
#[derive(Debug)]
pub enum Verdict {
    Unchanged,
    Replaced(Value),
    Denied(String),
    /// Show the call to the user whatever the rules and the active mode say,
    /// with `reason` on the prompt. It can only make things stricter, so a deny
    /// rule still wins. `input` is a rewrite that came along, if any. Only
    /// [`HookStage::Input`] may ask, and everywhere else this reads as
    /// [`Verdict::Unchanged`].
    Ask {
        reason: String,
        input: Option<Value>,
    },
}

/// What a [`PermissionHook`] answered. It stands in for the prompt, so it is
/// asked only about a call the rules left for the user, and only when no layer
/// escalated that call: an escalation is someone asking for the human, which no
/// decider may answer on their behalf.
#[derive(Debug, Default, PartialEq, Eq)]
pub enum Decision {
    /// Nobody had an opinion. The user is asked, as they would have been.
    #[default]
    Fallthrough,
    /// Good for this one call only: nothing is remembered, so the next call
    /// is judged on its own.
    Allow(Rationale),
    Deny(Rationale),
    /// Ask the user, with the rationale on the prompt.
    Prompt(Rationale),
}

/// Why a decider answered the way it did. `reason` is prose for whoever reads
/// the outcome (the model on a deny, the user on a prompt), `code` a stable
/// label for the audit log, so a misjudged call can be found without
/// reproducing it.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct Rationale {
    pub reason: Option<String>,
    pub code: Option<String>,
}

impl Decision {
    /// The effect and why, or `None` when nobody had an opinion.
    pub fn answered(&self) -> Option<(&'static str, &Rationale)> {
        match self {
            Self::Fallthrough => None,
            Self::Allow(why) => Some((EFFECT_ALLOW, why)),
            Self::Deny(why) => Some((EFFECT_DENY, why)),
            Self::Prompt(why) => Some((EFFECT_PROMPT, why)),
        }
    }
}

impl Rationale {
    /// What a reader is shown: the prose, or the code when that is all there is.
    pub fn shown(self) -> Option<String> {
        self.reason.or(self.code)
    }
}

pub struct PermissionCall<'a> {
    pub tool: &'a str,
    pub scopes: &'a [String],
    /// The input the tool was parsed from and will run with, so a decider
    /// judges the call itself rather than what the scopes kept of it. `None`
    /// when the gate was not reached from a tool call.
    pub input: Option<&'a Value>,
    pub cwd: &'a Path,
    pub project_root: &'a Path,
    pub trusted: bool,
    /// The permission mode that was active, if any.
    pub mode: Option<&'a str>,
    /// Calls the mode has waved through this turn, and its ceiling.
    pub auto_calls: u32,
    pub max_auto_calls: Option<u32>,
    pub cancel: &'a CancelToken,
    pub deadline: Instant,
}

/// Whoever may answer a permission prompt in the user's place. Granting is a
/// privilege no input layer has, which is why this is a stage of its own with
/// a price of its own: see [`Authority::Unbounded`].
pub trait PermissionHook: Send + Sync + 'static {
    /// Sync and allocation free: a chain nobody wrapped costs one lookup, and
    /// every gated call asks.
    fn wraps(&self) -> bool;

    fn run<'a>(&'a self, call: &'a PermissionCall<'a>) -> BoxFuture<'a, Decision>;
}

pub trait ToolHook: Send + Sync + 'static {
    /// Synchronous and allocation free, because dispatch asks it for every
    /// call: a stage nobody wrapped never leaves the calling thread.
    fn wraps(&self, tool: &str, stage: HookStage) -> bool;

    /// `value` is the call's input at [`HookStage::Input`], and
    /// `{ [OUTPUT_TEXT]: string, [OUTPUT_IS_ERROR]: bool }` at
    /// [`HookStage::Output`].
    fn run<'a>(
        &'a self,
        stage: HookStage,
        value: Value,
        call: &'a HookCall<'a>,
    ) -> BoxFuture<'a, Verdict>;
}
