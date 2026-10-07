use std::collections::{HashMap, HashSet};
use std::path::{Component, Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use maki_config::{
    BUILTIN_MODE_YOLO, DefaultEffect, Effect, FILE_WRITE_TOOLS, MODE_OFF, ModeExpiry,
    PermissionMode, PermissionRule, PermissionTarget, PermissionsConfig, ProjectConfig, ToolKey,
    append_permission_rule,
};
use serde_json::Value;
use thiserror::Error;
use tracing::{info, warn};

use crate::tools::hook::{Decision, PermissionCall};
use crate::tools::registry::InstalledPermissionHook;
use crate::{AgentEvent, EventSender};

pub const DEFAULT_DENY_GUIDANCE: &str =
    "Do not retry. Try a different approach or ask the user for guidance.";

/// Tests assert on this exact prefix; a wording tweak here updates them in one place.
pub const PERMISSION_DENIED_PREFIX: &str = "Permission denied for";

/// Values for the `source` attribute on `maki.tool_decision` events.
pub const DECISION_SOURCE_RULE: &str = "rule";
pub const DECISION_SOURCE_YOLO: &str = "yolo";
pub const DECISION_SOURCE_MODE: &str = "mode";
pub const DECISION_SOURCE_PLAN: &str = "plan";
pub const DECISION_SOURCE_DEFAULT: &str = "default";
pub const DECISION_SOURCE_DECIDE: &str = "decide";
pub const DECISION_SOURCE_USER_ONCE: &str = "user_once";
pub const DECISION_SOURCE_USER_SESSION: &str = "user_session";
pub const DECISION_SOURCE_USER_ALWAYS: &str = "user_always";
pub const DECISION_SOURCE_USER_ABORT: &str = "user_abort";

/// A decider may read a file or run a job before it answers, but the user is
/// waiting on it. Past this the prompt goes up as if nobody had an opinion.
const DECIDE_CHAIN_MAX: Duration = Duration::from_secs(30);

const TASK_TOOL: &str = "task";
const BASH_TOOL: &str = "bash";

/// Splits the ask id from the encoded answer on the answer channel. A control
/// character cannot appear in a tool-use id, and the answer is the tail, so
/// deny guidance holding one still round-trips.
const ANSWER_ID_SEPARATOR: char = '\u{1f}';

/// Words that open a block the bash plugin keeps as one scope. Their first
/// token names no program, so wildcarding it would cover every command the
/// block can hold. See [`generalize_bash_segment`].
const SHELL_KEYWORDS: [&str; 15] = [
    "if", "then", "elif", "else", "fi", "for", "while", "until", "do", "done", "case", "esac",
    "select", "function", "time",
];

fn builtin_rules(cwd: &Path) -> Vec<PermissionRule> {
    let cwd_glob = format!(
        "{}/**",
        maki_storage::paths::canonicalize_clean(cwd).display()
    );
    let allow = |tool: &str, scope: &str| PermissionRule {
        tool: ToolKey::native(tool),
        scope: Some(scope.into()),
        effect: Effect::Allow,
    };
    let mut rules: Vec<PermissionRule> = FILE_WRITE_TOOLS
        .iter()
        .map(|tool| allow(tool, &cwd_glob))
        .collect();
    rules.push(allow(TASK_TOOL, "*"));
    rules
}

pub const BOUNDARY_UNVERIFIABLE_PREFIX: &str = "Cannot verify project boundary for";

/// Whether the builtin defaults treat `tool` specially. File write tools get
/// the cwd allow and the plan mode allow, `task` gets a blanket allow, and an
/// "allow always" for `bash` is stored under the first word of the command.
/// Rules are keyed by name alone, so a plugin taking one of these names
/// inherits all of it.
pub fn carries_builtin_defaults(tool: &str) -> bool {
    FILE_WRITE_TOOLS.contains(&tool) || matches!(tool, TASK_TOOL | BASH_TOOL)
}

/// What settled an allow. The mode budget is spent by exactly the calls the
/// mode waved through, so the answer has to name its source rather than be
/// guessed at afterwards from whatever flags happen to be set.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AllowSource {
    /// A rule, from any layer but the active mode.
    Rule,
    Mode,
    /// The write that drafts the plan, in plan mode.
    Plan,
    /// A `default` that is not the mode's own.
    Default,
    /// A plugin answering the prompt in the user's place.
    Decide,
}

impl AllowSource {
    fn as_str(self) -> &'static str {
        match self {
            Self::Rule => DECISION_SOURCE_RULE,
            Self::Mode => DECISION_SOURCE_MODE,
            Self::Plan => DECISION_SOURCE_PLAN,
            Self::Default => DECISION_SOURCE_DEFAULT,
            Self::Decide => DECISION_SOURCE_DECIDE,
        }
    }
}

#[derive(Debug)]
pub enum PermissionCheck {
    Allowed(AllowSource),
    Denied,
    NeedsPrompt {
        tool: ToolKey,
        scopes: Vec<String>,
        force_prompt: bool,
    },
}

#[derive(Debug, Error)]
pub struct PermissionError {
    tool: String,
    scope: String,
    guidance: Option<String>,
}

impl std::fmt::Display for PermissionError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{} `{}` ({}).",
            PERMISSION_DENIED_PREFIX, self.tool, self.scope
        )?;
        if let Some(g) = &self.guidance {
            write!(f, " User guidance: {}", g)
        } else {
            write!(f, " {}", DEFAULT_DENY_GUIDANCE)
        }
    }
}

impl PermissionError {
    fn new(tool: &str, scope: &str) -> Self {
        Self {
            tool: tool.to_string(),
            scope: scope.to_string(),
            guidance: None,
        }
    }

    fn with_guidance(tool: &str, scope: &str, guidance: String) -> Self {
        Self {
            tool: tool.to_string(),
            scope: scope.to_string(),
            guidance: Some(guidance),
        }
    }
}

/// Everything the gate needs that is not the call itself.
pub struct Gate<'a> {
    pub event_tx: &'a EventSender,
    pub user_response_rx: Option<&'a async_lock::Mutex<flume::Receiver<String>>>,
    pub request_id: &'a str,
    pub cancel: &'a crate::CancelToken,
    pub plan_path: Option<&'a Path>,
    /// The input the call runs with, handed to the decider as is.
    pub input: Option<&'a Value>,
    /// A plugin's reason to show this call to the user whatever the rules say.
    /// See [`PermissionManager::check_escalated`].
    pub ask: Option<&'a str>,
    /// Whoever may answer the prompt in the user's place, when nothing
    /// escalated the call. `None` when no plugin layers the decide slot.
    pub decider: Option<InstalledPermissionHook>,
}

/// How squarely an approval names the tool being checked. Every source of
/// approval has to say which one it is, so the question cannot be skipped by a
/// source added later.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Approval {
    /// A rule naming this tool. The user answered about this tool.
    ForThisTool,
    /// Yolo, a default, a `*` rule, a whole-server rule. It covers this tool
    /// along with others and says nothing about this one in particular.
    Standing,
}

/// Whether an approval counts for the tool at hand. An MCP tool is opaque, so
/// nothing here tells a repo search from a commit, and plan mode only stays
/// read-only while a standing yes never speaks for one. Native tools are known
/// quantities and keep every approval they had.
#[derive(Clone, Copy)]
struct ApprovalGate {
    opaque_under_plan_mode: bool,
}

impl ApprovalGate {
    fn new(tool: &ToolKey, plan_path: Option<&Path>) -> Self {
        Self {
            opaque_under_plan_mode: plan_path.is_some() && tool.is_mcp(),
        }
    }

    fn accepts(self, approval: Approval) -> bool {
        !self.opaque_under_plan_mode || approval == Approval::ForThisTool
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PermissionAnswer {
    AllowOnce,
    AllowSession,
    AllowAlwaysProject,
    AllowAlwaysGlobal,
    Deny,
    DenyWithGuidance(String),
    DenyAlwaysProject,
    DenyAlwaysGlobal,
}

impl PermissionAnswer {
    pub fn decision_source(&self) -> &'static str {
        match self {
            Self::AllowOnce | Self::Deny | Self::DenyWithGuidance(_) => DECISION_SOURCE_USER_ONCE,
            Self::AllowSession => DECISION_SOURCE_USER_SESSION,
            Self::AllowAlwaysProject
            | Self::AllowAlwaysGlobal
            | Self::DenyAlwaysProject
            | Self::DenyAlwaysGlobal => DECISION_SOURCE_USER_ALWAYS,
        }
    }

    pub fn is_allow(&self) -> bool {
        matches!(
            self,
            Self::AllowOnce
                | Self::AllowSession
                | Self::AllowAlwaysProject
                | Self::AllowAlwaysGlobal
        )
    }

    pub fn encode(&self) -> String {
        match self {
            Self::AllowOnce => "allow".to_string(),
            Self::AllowSession => "allow_session".to_string(),
            Self::AllowAlwaysProject => "allow_always_project".to_string(),
            Self::AllowAlwaysGlobal => "allow_always_global".to_string(),
            Self::Deny => "deny".to_string(),
            Self::DenyWithGuidance(g) => format!("deny:{g}"),
            Self::DenyAlwaysProject => "deny_always_project".to_string(),
            Self::DenyAlwaysGlobal => "deny_always_global".to_string(),
        }
    }

    pub fn decode(s: &str) -> Option<Self> {
        match s {
            "allow" => Some(Self::AllowOnce),
            "allow_session" => Some(Self::AllowSession),
            "allow_always_project" => Some(Self::AllowAlwaysProject),
            "allow_always_global" => Some(Self::AllowAlwaysGlobal),
            "deny" => Some(Self::Deny),
            "deny_always_project" => Some(Self::DenyAlwaysProject),
            "deny_always_global" => Some(Self::DenyAlwaysGlobal),
            _ if s.starts_with("deny:") => {
                let guidance = s.strip_prefix("deny:").unwrap();
                if guidance.is_empty() {
                    Some(Self::Deny)
                } else {
                    Some(Self::DenyWithGuidance(guidance.to_string()))
                }
            }
            _ => None,
        }
    }

    pub fn guidance(&self) -> Option<&str> {
        match self {
            Self::DenyWithGuidance(g) => Some(g),
            _ => None,
        }
    }
}

/// An answer together with the id of the ask it answers.
///
/// The name is what makes a late answer harmless. The answer channel is a
/// queue with no receiver parked between turns, so an answer to a cancelled
/// turn's ask can sit there until the next turn's first permission wait pops
/// it. Untagged, that stale answer is applied to a different tool and scope,
/// and an `allow_always_*` then installs a rule for something the user never
/// saw. Tagged, the waiter can tell it apart and drop it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TaggedAnswer {
    pub request_id: String,
    pub answer: PermissionAnswer,
}

impl TaggedAnswer {
    pub fn new(request_id: impl Into<String>, answer: PermissionAnswer) -> Self {
        Self {
            request_id: request_id.into(),
            answer,
        }
    }

    pub fn encode(&self) -> String {
        format!(
            "{}{ANSWER_ID_SEPARATOR}{}",
            self.request_id,
            self.answer.encode()
        )
    }

    pub fn decode(raw: &str) -> Option<Self> {
        let (request_id, answer) = raw.split_once(ANSWER_ID_SEPARATOR)?;
        Some(Self::new(request_id, PermissionAnswer::decode(answer)?))
    }
}

/// Permission rules declared by Lua plugins via
/// `maki.api.register_permission_rule`, keyed by plugin name. Shared between
/// the Lua runtime (writer, on plugin load/unload) and every
/// [`PermissionManager`] (reader).
#[derive(Default)]
pub struct PluginRuleStore(Mutex<HashMap<Arc<str>, Vec<PermissionRule>>>);

impl PluginRuleStore {
    fn lock(&self) -> std::sync::MutexGuard<'_, HashMap<Arc<str>, Vec<PermissionRule>>> {
        self.0.lock().unwrap_or_else(|e| {
            warn!("plugin rule mutex was poisoned, recovering");
            e.into_inner()
        })
    }

    /// An empty `rules` removes the entry, so a reload that registers
    /// nothing clears the stale rules.
    pub fn replace(&self, plugin: &str, rules: Vec<PermissionRule>) {
        let mut map = self.lock();
        if rules.is_empty() {
            map.remove(plugin);
        } else {
            map.insert(Arc::from(plugin), rules);
        }
    }

    pub fn remove(&self, plugin: &str) {
        self.lock().remove(plugin);
    }

    pub fn snapshot(&self) -> Vec<PermissionRule> {
        self.lock().values().flatten().cloned().collect()
    }
}

/// The mode the user switched on, with what it has spent of its budget. The
/// count is per turn, because that is the unit the user watches go by.
struct ActiveMode {
    mode: Arc<PermissionMode>,
    auto_calls: u32,
}

impl ActiveMode {
    fn new(mode: Arc<PermissionMode>) -> Self {
        Self {
            mode,
            auto_calls: 0,
        }
    }

    /// Whether the mode may still wave a call through. A spent budget silences
    /// only its allows: a mode that denies or asks goes on doing so, since
    /// running out of rope is no reason to loosen it.
    fn may_allow(&self) -> bool {
        self.mode
            .max_auto_calls
            .is_none_or(|max| self.auto_calls < max)
    }
}

#[derive(Debug, Error)]
#[error("no permission mode named '{0}'")]
pub struct UnknownMode(pub String);

pub struct PermissionManager {
    session_rules: Mutex<Vec<PermissionRule>>,
    config_rules: Vec<PermissionRule>,
    builtin_rules: Vec<PermissionRule>,
    default: DefaultEffect,
    tool_defaults: HashMap<ToolKey, DefaultEffect>,
    cwd: PathBuf,
    project_config: ProjectConfig,
    plugin_rules: Arc<PluginRuleStore>,
    /// Every mode the config defines, sorted by name: what `/permission` lists
    /// and what cycling walks.
    modes: Vec<Arc<PermissionMode>>,
    active_mode: Mutex<Option<ActiveMode>>,
    /// What `--permission-mode` / `always_permission_mode` asked for. A session
    /// that never said anything about modes falls back to it, which is what
    /// keeps the flag a property of the invocation rather than of the log.
    seed_mode: Option<Arc<PermissionMode>>,
    /// Whether the user switched modes in this session themselves, which is
    /// what makes the answer worth storing.
    mode_explicit: AtomicBool,
}

impl PermissionManager {
    pub fn new(
        config: PermissionsConfig,
        cwd: PathBuf,
        project_config: ProjectConfig,
        plugin_rules: Arc<PluginRuleStore>,
    ) -> Self {
        let config_rules = config.rules;
        let builtin_rules = builtin_rules(&cwd);
        let seed_mode = config
            .initial_mode
            .as_deref()
            .and_then(|name| config.modes.iter().find(|mode| mode.name == name))
            .cloned();

        // Warn if wildcard deny is present — it blocks ALL tools including builtins.
        let has_wildcard_deny = config_rules
            .iter()
            .any(|r| matches!(r.tool, ToolKey::Wildcard) && r.effect == Effect::Deny);
        if has_wildcard_deny {
            warn!(
                "wildcard deny detected — this blocks ALL tools including \
                 builtins (write/edit/multiedit/task). Use per-tool rules \
                 instead if you want selective access."
            );
        }
        // Warn if wildcard allow is present — it permits ALL tools including write/edit/task.
        let has_wildcard_allow = config_rules
            .iter()
            .any(|r| matches!(r.tool, ToolKey::Wildcard) && r.effect == Effect::Allow);
        if has_wildcard_allow {
            warn!(
                "wildcard allow detected — this permits ALL tools including \
                 write/edit/multiedit/task. Use per-tool rules \
                 instead if you want selective access."
            );
        }

        Self {
            builtin_rules,
            session_rules: Mutex::new(Vec::new()),
            config_rules,
            default: config.default,
            tool_defaults: config.tool_defaults,
            cwd,
            project_config,
            plugin_rules,
            active_mode: Mutex::new(seed_mode.clone().map(ActiveMode::new)),
            seed_mode,
            mode_explicit: AtomicBool::new(false),
            modes: config.modes,
        }
    }

    /// Fresh manager for a new session runtime: shares config and builtin
    /// rules plus the active mode, but owns empty session rules so restoring
    /// one session never clobbers another's grants.
    pub fn fork(&self) -> Self {
        Self {
            session_rules: Mutex::new(Vec::new()),
            modes: self.modes.clone(),
            // The mode carries over, its spending does not: a budget is per
            // turn, and the forked session is about to run turns of its own.
            active_mode: Mutex::new(self.active_mode().map(ActiveMode::new)),
            seed_mode: self.seed_mode.clone(),
            mode_explicit: AtomicBool::new(self.mode_explicit.load(Ordering::Relaxed)),
            config_rules: self.config_rules.clone(),
            builtin_rules: self.builtin_rules.clone(),
            default: self.default,
            tool_defaults: self.tool_defaults.clone(),
            cwd: self.cwd.clone(),
            project_config: self.project_config.clone(),
            plugin_rules: Arc::clone(&self.plugin_rules),
        }
    }

    fn active(&self) -> std::sync::MutexGuard<'_, Option<ActiveMode>> {
        self.active_mode.lock().unwrap_or_else(|e| {
            warn!("permission mode mutex was poisoned, recovering");
            e.into_inner()
        })
    }

    /// Every mode the config defines, in the order `/permission` lists them.
    pub fn modes(&self) -> &[Arc<PermissionMode>] {
        &self.modes
    }

    pub fn active_mode(&self) -> Option<Arc<PermissionMode>> {
        self.active().as_ref().map(|a| Arc::clone(&a.mode))
    }

    pub fn active_mode_name(&self) -> Option<String> {
        self.active_mode().map(|mode| mode.name.clone())
    }

    /// `None` switches every mode off. A name nobody defined is refused rather
    /// than ignored, so a typo in a flag or a config does not read as "off".
    pub fn set_mode(&self, name: Option<&str>) -> Result<Option<Arc<PermissionMode>>, UnknownMode> {
        let mode = match name {
            None => None,
            Some(name) => Some(
                self.modes
                    .iter()
                    .find(|m| m.name == name)
                    .ok_or_else(|| UnknownMode(name.to_owned()))?,
            ),
        };
        self.mode_explicit.store(true, Ordering::Relaxed);
        let mode = self.install(mode.cloned());
        info!(mode = ?mode.as_ref().map(|m| &m.name), "permission mode set");
        Ok(mode)
    }

    /// What a session stores about its mode: the name it was switched to, the
    /// off sentinel when the user switched it off, and nothing at all when they
    /// never touched it, so the seed still speaks for the next session.
    pub fn persisted_mode(&self) -> Option<String> {
        if !self.mode_explicit.load(Ordering::Relaxed) {
            return None;
        }
        Some(
            self.active_mode_name()
                .unwrap_or_else(|| MODE_OFF.to_owned()),
        )
    }

    /// Hands a session's stored answer back. `None` is "this session never
    /// said", which falls back to the seed rather than to off.
    pub fn set_session_mode(&self, stored: Option<&str>) -> Result<(), UnknownMode> {
        match stored {
            None => {
                self.mode_explicit.store(false, Ordering::Relaxed);
                self.install(self.seed_mode.clone());
                Ok(())
            }
            Some(MODE_OFF) => {
                self.set_mode(None)?;
                Ok(())
            }
            Some(name) => self.set_mode(Some(name)).map(|_| ()),
        }
    }

    /// The one writer of the active mode, so a switch cannot forget to reset
    /// the budget the new mode starts with.
    fn install(&self, mode: Option<Arc<PermissionMode>>) -> Option<Arc<PermissionMode>> {
        let active = mode.map(ActiveMode::new);
        let mode = active.as_ref().map(|a| Arc::clone(&a.mode));
        *self.active() = active;
        mode
    }

    /// The next mode in the list, wrapping through "no mode" so cycling can
    /// always get back to prompting for everything.
    pub fn cycle_mode(&self) -> Option<Arc<PermissionMode>> {
        let next = match self.active_mode_name() {
            None => self.modes.first(),
            Some(current) => self
                .modes
                .iter()
                .position(|m| m.name == current)
                .and_then(|i| self.modes.get(i + 1)),
        };
        self.mode_explicit.store(true, Ordering::Relaxed);
        self.install(next.cloned())
    }

    /// What the mode has waved through this turn, and its ceiling.
    pub fn mode_spend(&self) -> (u32, Option<u32>) {
        match self.active().as_ref() {
            Some(active) => (active.auto_calls, active.mode.max_auto_calls),
            None => (0, None),
        }
    }

    /// A fresh budget for a new turn. Nothing else about the mode resets.
    pub fn begin_turn(&self) {
        if let Some(active) = self.active().as_mut() {
            active.auto_calls = 0;
        }
    }

    /// Drops a mode that was only meant to last the turn.
    pub fn end_turn(&self) {
        let mut active = self.active();
        if active
            .as_ref()
            .is_some_and(|a| a.mode.expires == ModeExpiry::Turn)
        {
            info!(mode = ?active.as_ref().map(|a| &a.mode.name), "permission mode expired with the turn");
            *active = None;
        }
    }

    fn charge_mode(&self) {
        if let Some(active) = self.active().as_mut() {
            active.auto_calls = active.auto_calls.saturating_add(1);
        }
    }

    /// The user said no while a mode was on. A mode that asked to be dropped
    /// over that is dropped: the human just contradicted the standing grant.
    fn note_user_deny(&self) {
        let mut active = self.active();
        if active.as_ref().is_some_and(|a| a.mode.revert_on_deny) {
            info!(mode = ?active.as_ref().map(|a| &a.mode.name), "permission mode reverted on a denial");
            *active = None;
        }
    }

    fn session_rules(&self) -> std::sync::MutexGuard<'_, Vec<PermissionRule>> {
        self.session_rules.lock().unwrap_or_else(|e| {
            warn!("permission mutex was poisoned, recovering");
            e.into_inner()
        })
    }

    /// The order of the checks below is the policy itself, not an accident of
    /// how it was written: denies first, then explicit allows, the plan file
    /// write, and last the defaults. Moving one moves the rules. Yolo is a mode
    /// whose one rule allows everything, so it lands in the allow pass with the
    /// rest rather than in a step of its own.
    /// Every approval among them goes through [`ApprovalGate`], which is what
    /// keeps plan mode's hold from depending on which one happens to run first.
    fn check_inner(
        &self,
        tool: &ToolKey,
        scopes: &[&str],
        force_prompt: bool,
        plan_path: Option<&Path>,
    ) -> PermissionCheck {
        let session = self.session_rules();
        let plugin = self.plugin_rules.snapshot();
        // Taken as a snapshot: the mode can be switched off while a call waits
        // on the prompt, and a call has to be judged by one policy throughout.
        let mode = self
            .active()
            .as_ref()
            .map(|active| (Arc::clone(&active.mode), active.may_allow()));
        let (mode_rules, mode_may_allow) = match &mode {
            Some((mode, may_allow)) => (mode.rules.as_slice(), *may_allow),
            None => ([].as_slice(), false),
        };

        let gate = ApprovalGate::new(tool, plan_path);

        // Any matching deny wins, however broadly it was aimed. Only approvals
        // are ranked by how squarely they name the tool, and only plan mode
        // reads that rank.
        let mut unclaimed_scopes: Vec<&str> = if force_prompt {
            Vec::new()
        } else {
            Vec::with_capacity(scopes.len())
        };

        // Only set when the mode is the reason a scope passed, so a mode riding
        // along with rules that already allowed the call spends nothing.
        let mut mode_allowed = false;
        for scope in scopes {
            let mut has_allow = false;
            for (r, from_mode) in session
                .iter()
                .chain(&self.config_rules)
                .chain(&self.builtin_rules)
                .chain(&plugin)
                .map(|r| (r, false))
                .chain(mode_rules.iter().map(|r| (r, true)))
            {
                let Some(approval) = rule_reach(&r.tool, tool) else {
                    continue;
                };
                if !rule_matches_scope(r, scope) {
                    continue;
                }
                match r.effect {
                    Effect::Deny => {
                        info!(tool = %tool, scope = %scope, from_mode, "permission denied");
                        return PermissionCheck::Denied;
                    }
                    // A mode allow counts only while the budget lasts, and
                    // only when nothing else covered the scope already, since
                    // what the mode did not decide it does not pay for.
                    Effect::Allow if from_mode => {
                        if mode_may_allow && !has_allow && gate.accepts(approval) {
                            has_allow = true;
                            mode_allowed = true;
                        }
                    }
                    Effect::Allow => has_allow |= gate.accepts(approval),
                }
            }

            if has_allow {
                // allow wins for this scope (no deny matched)
            } else if !force_prompt {
                unclaimed_scopes.push(scope);
            }
            // force_prompt: all scopes will be prompted anyway
        }

        let pending: Vec<&str> = if force_prompt {
            scopes.to_vec()
        } else {
            unclaimed_scopes
        };

        if pending.is_empty() {
            return PermissionCheck::Allowed(if mode_allowed {
                AllowSource::Mode
            } else {
                AllowSource::Rule
            });
        }

        // Plan file auto-allow: fires AFTER deny rules have been evaluated.
        // Only triggers if ALL pending scopes match the plan file path.
        // A single non-plan scope means we must prompt for the rest.
        // Compared the way the write lands: `link/../plan.md` is the plan
        // file lexically but somewhere else once `link` is followed.
        if !force_prompt && !pending.is_empty() {
            let is_plan_write = plan_path.is_some_and(|pp| {
                matches!(tool, ToolKey::Native(name) if FILE_WRITE_TOOLS.contains(&name.as_ref()))
                    && {
                        let plan = normalize_scope_prefix(pp);
                        pending.iter().all(|s| normalize_scope_prefix(s) == plan)
                    }
            });
            if is_plan_write {
                return PermissionCheck::Allowed(AllowSource::Plan);
            }
        }

        // Specific beats general, whoever wrote it: a mode's own per-tool
        // default outranks the file's, and the file's per-tool default outranks
        // the mode's blanket one. So switching on a mode that allows by default
        // cannot quietly undo a `[bash] default = "deny"`.
        let mode = mode.map(|(mode, _)| mode);
        // A spent budget passes the mode's allows by and leaves its denies in
        // place, the same way it treats the mode's rules.
        let usable = |eff: &DefaultEffect| mode_may_allow || *eff != DefaultEffect::Allow;
        let (eff, from_mode) = mode
            .as_deref()
            .and_then(|m| lookup_default(&m.tool_defaults, tool))
            .filter(usable)
            .map(|eff| (eff, true))
            .or_else(|| lookup_default(&self.tool_defaults, tool).map(|eff| (eff, false)))
            .or_else(|| {
                mode.as_deref()?
                    .default
                    .filter(usable)
                    .map(|eff| (eff, true))
            })
            .unwrap_or((self.default, false));
        match eff {
            DefaultEffect::Deny => {
                info!(tool = %tool, from_mode, "denied by default");
                PermissionCheck::Denied
            }
            DefaultEffect::Allow if gate.accepts(Approval::Standing) => {
                PermissionCheck::Allowed(if from_mode {
                    AllowSource::Mode
                } else {
                    AllowSource::Default
                })
            }
            DefaultEffect::Allow | DefaultEffect::Prompt => PermissionCheck::NeedsPrompt {
                tool: tool.clone(),
                scopes: pending.into_iter().map(|s| s.to_string()).collect(),
                force_prompt,
            },
        }
    }

    pub fn check(&self, tool: &ToolKey, scope: &str, plan_path: Option<&Path>) -> PermissionCheck {
        self.check_inner(tool, &[scope], false, plan_path)
    }

    pub fn check_multi(
        &self,
        tool: &ToolKey,
        scopes: &[&str],
        force_prompt: bool,
        plan_path: Option<&Path>,
    ) -> PermissionCheck {
        self.check_inner(tool, scopes, force_prompt, plan_path)
    }

    pub fn add_session_rule(&self, rule: PermissionRule) {
        let mut rules = self.session_rules();
        let exists = rules
            .iter()
            .any(|r| r.tool == rule.tool && r.scope == rule.scope && r.effect == rule.effect);
        if !exists {
            rules.push(rule);
        }
    }

    /// `/yolo` is the one-key gesture for the mode of the same name: on when it
    /// is not active, off when it is. Returns whether it ended up on.
    pub fn toggle_yolo(&self) -> bool {
        let on = self.active_mode_name().as_deref() != Some(BUILTIN_MODE_YOLO);
        let wanted = on.then_some(BUILTIN_MODE_YOLO);
        match self.set_mode(wanted) {
            Ok(_) => on,
            // Only a config that redefined the built-in away can land here, and
            // a gesture that cannot grant anything leaves the gate as it was.
            Err(e) => {
                warn!(error = %e, "nothing to toggle: no mode named {BUILTIN_MODE_YOLO}");
                !on
            }
        }
    }

    pub fn is_yolo(&self) -> bool {
        self.active_mode_name().as_deref() == Some(BUILTIN_MODE_YOLO)
    }

    pub fn boundary_block_reason(&self, path: &Path) -> Option<String> {
        match physical_boundary_check(&self.cwd, path) {
            Some(_) => None,
            None => Some(format!(
                "{BOUNDARY_UNVERIFIABLE_PREFIX} {} \
                 (project root could not be resolved)",
                path.display()
            )),
        }
    }

    pub fn session_rules_snapshot(&self) -> Vec<PermissionRule> {
        self.session_rules().clone()
    }

    pub fn load_session_rules(&self, rules: Vec<PermissionRule>) {
        *self.session_rules() = rules;
    }

    pub fn project_is_trusted(&self) -> bool {
        self.project_config.is_trusted()
    }

    /// Where an always-answer gets written, or `None` when it only holds for
    /// this session. An untrusted folder gets nothing, for a different reason
    /// on each side. An allow saved there is stripped on the next start, so it
    /// would only look forgotten. A deny would survive, because an untrusted
    /// project still contributes its deny scopes, but saving it means Maki
    /// writing `.maki/permissions.toml` into a checkout the user declined to
    /// trust, and the next start would then ask them about a gated file Maki
    /// created itself. The durable deny is the global one, which lands in the
    /// user's own config and no repository can touch.
    fn persist_target(&self, answer: &PermissionAnswer) -> Option<PermissionTarget> {
        match answer {
            PermissionAnswer::AllowAlwaysProject | PermissionAnswer::DenyAlwaysProject => self
                .project_config
                .is_trusted()
                .then(|| PermissionTarget::Project(self.project_config.clone())),
            _ => Some(PermissionTarget::Global),
        }
    }

    pub fn apply_decision(&self, tool: &ToolKey, scopes: &[String], answer: &PermissionAnswer) {
        let resolved = if answer.is_allow() || tool.is_mcp() {
            // MCP scopes are always wildcarded — both allow and deny generalize to "*".
            // This makes session and persisted rules consistent: a deny on an MCP tool
            // blocks the tool entirely, not just the specific input that triggered it.
            generalized_scopes(tool, scopes)
        } else {
            scopes.to_vec()
        };

        match answer {
            PermissionAnswer::AllowOnce
            | PermissionAnswer::Deny
            | PermissionAnswer::DenyWithGuidance(_) => {}
            PermissionAnswer::AllowSession => {
                for s in &resolved {
                    self.add_session_rule(PermissionRule {
                        tool: tool.clone(),
                        scope: Some(s.clone()),
                        effect: Effect::Allow,
                    });
                }
            }
            PermissionAnswer::AllowAlwaysProject
            | PermissionAnswer::AllowAlwaysGlobal
            | PermissionAnswer::DenyAlwaysProject
            | PermissionAnswer::DenyAlwaysGlobal => {
                let effect = if answer.is_allow() {
                    Effect::Allow
                } else {
                    Effect::Deny
                };
                let target = self.persist_target(answer);
                if target.is_none() {
                    info!(
                        tool = %tool,
                        "project answer stays in this session because the folder is not trusted, the global answer is the one that lasts"
                    );
                }
                for s in &resolved {
                    self.add_session_rule(PermissionRule {
                        tool: tool.clone(),
                        scope: Some(s.clone()),
                        effect,
                    });
                    if let Some(target) = &target
                        && let Err(e) = append_permission_rule(tool, Some(s), effect, target)
                    {
                        tracing::warn!(error = %e, "failed to persist permission rule");
                    }
                }
            }
        }
    }

    /// For a call a plugin escalated. Every allow there is, rules and modes and
    /// defaults alike, turns into a question for the user. Only a deny still
    /// answers on its own, so escalating can make a call harder to run but
    /// never easier.
    fn check_escalated(
        &self,
        tool: &ToolKey,
        scopes: &[&str],
        plan_path: Option<&Path>,
    ) -> PermissionCheck {
        match self.check_inner(tool, scopes, true, plan_path) {
            PermissionCheck::Denied => PermissionCheck::Denied,
            PermissionCheck::Allowed(_) | PermissionCheck::NeedsPrompt { .. } => {
                PermissionCheck::NeedsPrompt {
                    tool: tool.clone(),
                    scopes: scopes.iter().map(|s| s.to_string()).collect(),
                    force_prompt: true,
                }
            }
        }
    }

    /// Reported and charged in one place, so what the caller gets, what
    /// telemetry says, and what the mode budget spent cannot drift apart.
    fn allowed_by(&self, tool: &str, source: AllowSource) -> Result<(), PermissionError> {
        let mut reported = source.as_str();
        if source == AllowSource::Mode {
            self.charge_mode();
            // Yolo is a mode now, and still reports under its own name so the
            // series that watched for it does not go quiet.
            if self.is_yolo() {
                reported = DECISION_SOURCE_YOLO;
            }
        }
        maki_otel::emit::tool_decision(tool, maki_otel::emit::DECISION_ACCEPT, reported);
        Ok(())
    }

    /// The gate every tool call passes: resolve the rules, let a decider stand
    /// in for the user if one is installed, and otherwise ask.
    pub async fn enforce(
        &self,
        tool: &ToolKey,
        scopes: &crate::tools::PermissionScopes,
        gate: Gate<'_>,
    ) -> Result<(), PermissionError> {
        let Gate {
            event_tx,
            user_response_rx,
            request_id,
            cancel,
            plan_path,
            input,
            ask,
            decider,
        } = gate;
        let check = |tool: &ToolKey, scopes: &[&str], force_prompt: bool| match ask {
            Some(_) => self.check_escalated(tool, scopes, plan_path),
            None => self.check_inner(tool, scopes, force_prompt, plan_path),
        };
        let scope_refs: Vec<&str> = scopes.scopes.iter().map(|s| s.as_str()).collect();
        let tool_string = tool.to_string();
        let scope_display = || scopes.scopes.join("; ");
        // Every deny is built here and every approval passes through
        // `allowed_by`, so reporting cannot drift from what the caller gets.
        let deny = |source: &'static str, guidance: Option<String>| {
            maki_otel::emit::tool_decision(&tool_string, maki_otel::emit::DECISION_REJECT, source);
            match guidance {
                Some(g) => PermissionError::with_guidance(&tool_string, &scope_display(), g),
                None => PermissionError::new(&tool_string, &scope_display()),
            }
        };

        let (pt, ps, force_prompt) = match check(tool, &scope_refs, scopes.force_prompt) {
            PermissionCheck::Allowed(source) => return self.allowed_by(&tool_string, source),
            PermissionCheck::Denied => return Err(deny(DECISION_SOURCE_RULE, None)),
            PermissionCheck::NeedsPrompt {
                tool,
                scopes,
                force_prompt,
            } => (tool, scopes, force_prompt),
        };

        // Asked before the response channel is taken: a decider that shells out
        // would otherwise hold every other call's prompt behind it, and most
        // answers here never need the channel at all.
        let decided = match decider {
            Some(hook) if ask.is_none() => {
                self.decide(&hook, &tool_string, &ps, input, cancel).await
            }
            _ => Decision::Fallthrough,
        };
        let reason = match decided {
            Decision::Allow(_) => return self.allowed_by(&tool_string, AllowSource::Decide),
            Decision::Deny(why) => return Err(deny(DECISION_SOURCE_DECIDE, why.shown())),
            Decision::Prompt(why) => why.shown(),
            Decision::Fallthrough => None,
        };

        let Some(rx) = user_response_rx else {
            warn!(tool = %tool, scope = %scope_display(), "no permission response channel");
            return Err(deny(DECISION_SOURCE_USER_ABORT, None));
        };

        let guard = rx.lock().await;
        let refs: Vec<&str> = ps.iter().map(|s| s.as_str()).collect();
        let (t2, s2) = match check(&pt, &refs, force_prompt) {
            PermissionCheck::Allowed(source) => return self.allowed_by(&tool_string, source),
            PermissionCheck::Denied => return Err(deny(DECISION_SOURCE_RULE, None)),
            PermissionCheck::NeedsPrompt { tool, scopes, .. } => (tool, scopes),
        };

        let _ = event_tx.send(AgentEvent::PermissionRequest {
            id: request_id.to_owned(),
            tool: t2.clone(),
            scopes: s2.clone(),
            reason: ask.map(str::to_owned).or(reason),
        });
        // Only the answer naming this ask may be applied. Anything else is a
        // leftover from a cancelled or reassigned ask, so it is dropped and the
        // wait continues: consuming it would approve or deny this tool on a
        // decision the user made about another one.
        let answer = loop {
            let response = cancel.race(guard.recv_async()).await;
            match response {
                Ok(Ok(raw)) => match TaggedAnswer::decode(&raw) {
                    Some(tagged) if tagged.request_id == request_id => break tagged.answer,
                    tagged => warn!(
                        tool = %tool,
                        scope = %scope_display(),
                        request_id,
                        answered = tagged.map(|t| t.request_id).unwrap_or_default(),
                        "discarding a permission answer that does not name this request"
                    ),
                },
                Ok(Err(_)) => {
                    drop(guard);
                    warn!(tool = %tool, scope = %scope_display(), "permission channel closed");
                    return Err(deny(DECISION_SOURCE_USER_ABORT, None));
                }
                Err(_) => {
                    drop(guard);
                    return Err(deny(DECISION_SOURCE_USER_ABORT, None));
                }
            }
        };
        drop(guard);

        self.apply_decision(&t2, &s2, &answer);
        let source = answer.decision_source();
        if answer.is_allow() {
            maki_otel::emit::tool_decision(&tool_string, maki_otel::emit::DECISION_ACCEPT, source);
            Ok(())
        } else {
            self.note_user_deny();
            Err(deny(source, answer.guidance().map(String::from)))
        }
    }

    /// Hands the call to whoever is layering the decide slot. A decider that
    /// throws, times out, or answers nothing leaves the prompt where it was.
    /// Every answer is logged with its code but never the input, which may
    /// carry whatever the model put in a command.
    async fn decide(
        &self,
        hook: &InstalledPermissionHook,
        tool: &str,
        scopes: &[String],
        input: Option<&Value>,
        cancel: &crate::CancelToken,
    ) -> Decision {
        let (auto_calls, max_auto_calls) = self.mode_spend();
        let mode = self.active_mode_name();
        let cwd = maki_storage::paths::canonicalize_clean(&self.cwd);
        let call = PermissionCall {
            tool,
            scopes,
            input,
            cwd: &cwd,
            project_root: self.project_config.config_root(),
            trusted: self.project_config.is_trusted(),
            mode: mode.as_deref(),
            auto_calls,
            max_auto_calls,
            cancel,
            deadline: Instant::now() + DECIDE_CHAIN_MAX,
        };
        let decision = hook.run(&call).await;
        let Some((effect, why)) = decision.answered() else {
            return decision;
        };
        info!(
            tool,
            effect,
            reason_code = why.code.as_deref(),
            reason = why.reason.as_deref(),
            mode = mode.as_deref(),
            trusted = call.trusted,
            "permission decider answered"
        );
        decision
    }
}

/// The default written for this tool, falling back to the one written for its
/// MCP server. `None` when neither names it.
fn lookup_default(
    defaults: &HashMap<ToolKey, DefaultEffect>,
    tool: &ToolKey,
) -> Option<DefaultEffect> {
    if let Some(eff) = defaults.get(tool).copied() {
        return Some(eff);
    }
    let ToolKey::McpTool { server, .. } = tool else {
        return None;
    };
    defaults
        .get(&ToolKey::McpServer {
            server: server.clone(),
        })
        .copied()
}

/// Whether a rule reaches this tool, and how narrowly it was aimed if it does.
/// Both questions get answered by the one match, because a rule that reaches a
/// tool without saying how squarely is what let a `*` allow walk past plan mode.
fn rule_reach(rule_key: &ToolKey, actual: &ToolKey) -> Option<Approval> {
    match (rule_key, actual) {
        (ToolKey::Wildcard, _) => Some(Approval::Standing),
        (ToolKey::McpServer { server: rs }, ToolKey::McpTool { server: as_, .. }) => {
            (rs == as_).then_some(Approval::Standing)
        }
        (ToolKey::Native(a), ToolKey::Native(b)) => (a == b).then_some(Approval::ForThisTool),
        (ToolKey::McpServer { server: rs }, ToolKey::McpServer { server: as_ }) => {
            (rs == as_).then_some(Approval::ForThisTool)
        }
        (
            ToolKey::McpTool {
                server: rs,
                tool: rt,
            },
            ToolKey::McpTool {
                server: as_,
                tool: at,
            },
        ) => (rs == as_ && rt == at).then_some(Approval::ForThisTool),
        _ => None,
    }
}

/// A deny fails closed: a pattern refused as a blanket allow also denies
/// every scope, even where [`scope_matches`] reads it as a narrower subtree.
fn rule_matches_scope(rule: &PermissionRule, scope: &str) -> bool {
    match &rule.scope {
        None => true,
        Some(pattern) => {
            (rule.effect == Effect::Deny && is_universal_scope(pattern))
                || scope_matches(pattern, scope)
        }
    }
}

/// A rule and the path it is matched against have to agree on what file they
/// name, including for a relative rule like `dist/**` written before the dir
/// exists — both are `canonical_key`'s job.
fn normalize_scope_prefix(path: impl AsRef<Path>) -> PathBuf {
    maki_storage::paths::canonical_key(path.as_ref())
}

/// Whether a pattern might cover every scope, the question behind refusing a
/// plugin allow. `*`, `**`, `/*` and `/**` do by their text. A `/**` prefix
/// counts when either reading of it is the root: the canonical one
/// (`canonical_key`: expands `~`, follows symlinks), which is how
/// [`scope_matches`] grants, or the lexical one (`normalize_path`: collapses
/// `.` and `..` textually), which catches `//**`, `/./**` and `/tmp/../**`
/// even where `/tmp` is a symlink and the canonical reading lands elsewhere.
///
/// Refusing is the safe direction, so this reads broadly on purpose. The
/// invariant is one way: a pattern [`scope_matches`] treats as matching
/// everything is always universal here, a pattern universal here need not
/// match everything there.
pub fn is_universal_scope(pattern: &str) -> bool {
    match pattern.strip_suffix("/**") {
        Some(prefix) => {
            is_root(&normalize_scope_prefix(prefix))
                || is_root(&maki_storage::paths::normalize_path(Path::new(prefix)))
        }
        None => {
            let stem = pattern.trim_end_matches('*');
            stem.len() < pattern.len() && matches!(stem, "" | "/")
        }
    }
}

fn is_root(path: &Path) -> bool {
    path.parent().is_none()
}

/// Glob matcher for permission scopes. The boundary suffixes (`/**`, `" *"`)
/// must be tried before the bare `*`, otherwise a plain prefix would swallow
/// them. `" *"` is the bash form `<command> *`: it has to match the bare
/// command too (`pwd *` covers `pwd` and `pwd -L`, but not `pwdx`).
///
/// For the `/**` path pattern, `Path::starts_with` is used to compare
/// components rather than characters, which handles both `/` and `\`
/// transparently on all platforms.
///
/// A `/**` prefix is read one way only, canonically, the way the write tools
/// follow symlinks. A lexical root like `link/../../**` is the subtree the
/// filesystem resolves it to here, never everything; [`is_universal_scope`]
/// still refuses it.
pub fn scope_matches(pattern: &str, value: &str) -> bool {
    if let Some(prefix) = pattern.strip_suffix("/**") {
        let norm_prefix = normalize_scope_prefix(prefix);
        // A root prefix covers every scope, bash commands included. Those are
        // not paths, so a plain prefix test would miss them.
        return is_root(&norm_prefix) || normalize_scope_prefix(value).starts_with(&norm_prefix);
    }
    if is_universal_scope(pattern) {
        return true;
    }
    if let Some(prefix) = pattern.strip_suffix(" *") {
        return value == prefix || value.starts_with(&format!("{prefix} "));
    }
    if let Some(prefix) = pattern.strip_suffix('*') {
        return value.starts_with(prefix);
    }
    pattern == value
}

/// Check whether `child` is physically inside `parent`, following symlinks.
///
/// Uses incremental left-to-right canonicalization: each component is
/// resolved through the filesystem (including symlinks) *before* any
/// subsequent `..` component can act on it. This prevents symlink-based
/// boundary escapes where a symlink followed by `..` resolves to a
/// location outside the parent.
///
/// Returns `true` only when the resolved filesystem location of `child`
/// is under `parent`. Returns `None` if the parent itself cannot be resolved.
pub fn physical_boundary_check(parent: &Path, child: &Path) -> Option<bool> {
    let parent_canon = maki_storage::paths::incremental_canonicalize(parent)?;
    let child_canon =
        maki_storage::paths::incremental_canonicalize(child).unwrap_or_else(|| child.to_path_buf());
    Some(child_canon.starts_with(&parent_canon))
}

/// A `<cmd> *` rule is only safe when `<cmd>` names one program. The bash
/// plugin keeps block forms whole on purpose, so `for f in *.rs; do wc -l $f;
/// done` arrives as one scope and its first token is `for`; wildcarding that
/// hands out every loop the model can write. Same for a bodiless `> log`,
/// whose first token is the redirect. Those scopes stay literal: remembering
/// one exact command is worth little, but it is never a blank cheque.
fn generalize_bash_segment(segment: &str) -> String {
    let first_token = segment.split_whitespace().next().unwrap_or(segment);
    let is_command_word = !first_token.is_empty()
        && first_token
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || "_.:/@+-".contains(c))
        && !SHELL_KEYWORDS.contains(&first_token);
    if is_command_word {
        format!("{first_token} *")
    } else {
        segment.to_string()
    }
}

pub fn generalized_scopes(tool: &ToolKey, scopes: &[String]) -> Vec<String> {
    let mut seen = HashSet::new();
    scopes
        .iter()
        .map(|s| generalize_scope(tool, s))
        .filter(|g| seen.insert(g.clone()))
        .collect()
}

fn generalize_scope(tool: &ToolKey, scope: &str) -> String {
    match tool {
        ToolKey::Native(name) if name.as_ref() == BASH_TOOL => generalize_bash_segment(scope),
        ToolKey::Native(name) if FILE_WRITE_TOOLS.contains(&name.as_ref()) => {
            format!("{}/**", write_rule_dir(scope).display())
        }
        // MCP tool calls have a scope equal to the JSON-stringified input.
        // "Allow always" should whitelist the tool regardless of its arguments,
        // so generalize the scope to `*`. The rule's `tool` field still gates
        // which MCP tool it applies to, keeping distinct tools distinct.
        ToolKey::McpTool { .. } | ToolKey::McpServer { .. } => "*".to_string(),
        _ => scope.to_string(),
    }
}

/// The directory a write rule names: where the write lands, resolved the way
/// [`scope_matches`] resolves it, so the rule never holds `..` for the lexical
/// reading to collapse into something wider. The path as the model spelled it
/// is kept when its parent already names that directory, so ordinary rules
/// stay readable (`node_modules/react/**`, relative or through a symlink).
fn write_rule_dir(scope: &str) -> PathBuf {
    let landing = normalize_scope_prefix(scope);
    let landing_dir = landing.parent().unwrap_or(&landing);
    match Path::new(scope).parent() {
        Some(spelled)
            if !spelled.as_os_str().is_empty()
                && !spelled.components().any(|c| c == Component::ParentDir)
                && normalize_scope_prefix(spelled) == landing_dir =>
        {
            spelled.to_path_buf()
        }
        _ => landing_dir.to_path_buf(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::AtomicUsize;

    use serde_json::json;
    use test_case::test_case;

    use crate::tools::hook::Rationale;

    const PLAN_FILE: &str = "/home/user/.local/state/maki/plans/test.md";
    const TEST_CWD: &str = "/tmp";
    const MCP_SERVER: &str = "deepwiki";
    const MCP_TOOL: &str = "deepwiki.search";
    const MCP_ARGS: &str = "{\"q\":\"maki\"}";
    const READ_TOOL: &str = "read";
    const READ_SCOPE: &str = "/home/user/project/src/main.rs";
    const TAGGED_REQUEST_ID: &str = "toolu_1";
    /// Guidance is free text and may hold the separator itself.
    const TAGGED_GUIDANCE: &str = "no\u{1f}way";

    const ALLOWED: &str = "allowed";
    const DENIED: &str = "denied";
    const PROMPTS: &str = "prompts";
    const PROJECT_DIR: &str = ".maki";
    const PROJECT_PERMISSIONS: &str = ".maki/permissions.toml";
    #[cfg(unix)]
    const OUTSIDE_WRITES: [&str; 2] = ["/etc/passwd", "~/.bashrc"];
    const OUTSIDE_SCOPES: [&str; 3] = ["/etc/passwd", "~/.bashrc", "cargo test"];

    fn outcome(check: PermissionCheck) -> &'static str {
        match check {
            PermissionCheck::Allowed(_) => ALLOWED,
            PermissionCheck::Denied => DENIED,
            PermissionCheck::NeedsPrompt { .. } => PROMPTS,
        }
    }

    fn mcp_tool_key() -> ToolKey {
        ToolKey::parse(MCP_TOOL).expect("test tool key parses")
    }

    fn native_key() -> ToolKey {
        ToolKey::Native(READ_TOOL.into())
    }

    fn mcp_server_key() -> ToolKey {
        ToolKey::McpServer {
            server: MCP_SERVER.into(),
        }
    }

    fn make_config(rules: Vec<PermissionRule>) -> PermissionsConfig {
        PermissionsConfig {
            rules,
            ..Default::default()
        }
    }

    fn allow_rule(scope: &str) -> PermissionRule {
        PermissionRule {
            tool: ToolKey::native("bash"),
            scope: Some(scope.into()),
            effect: Effect::Allow,
        }
    }

    fn deny_rule(scope: &str) -> PermissionRule {
        PermissionRule {
            tool: ToolKey::native("bash"),
            scope: Some(scope.into()),
            effect: Effect::Deny,
        }
    }

    fn mgr_with(config: PermissionsConfig, cwd: PathBuf) -> PermissionManager {
        let project_config = ProjectConfig::for_project(&cwd);
        PermissionManager::new(config, cwd, project_config, Arc::default())
    }

    fn default_mgr() -> PermissionManager {
        mgr_with(PermissionsConfig::default(), PathBuf::from("/tmp"))
    }

    const MODE_NAME: &str = "auto";
    const OTHER_MODE: &str = "review";
    const CARGO_CMD: &str = "cargo test";
    const CARGO_SCOPE: &str = "cargo *";

    fn mode(name: &str, rules: Vec<PermissionRule>) -> Arc<PermissionMode> {
        Arc::new(PermissionMode {
            name: name.to_owned(),
            rules,
            ..Default::default()
        })
    }

    /// A manager with `modes` defined and `on` switched on, which is the state
    /// every mode test starts from.
    fn mgr_in_mode(modes: Vec<Arc<PermissionMode>>, on: &str) -> PermissionManager {
        let mgr = mgr_with(
            PermissionsConfig {
                modes,
                initial_mode: Some(on.to_owned()),
                ..Default::default()
            },
            PathBuf::from("/tmp"),
        );
        assert_eq!(mgr.active_mode_name().as_deref(), Some(on));
        mgr
    }

    fn bash_check(mgr: &PermissionManager) -> PermissionCheck {
        mgr.check(&ToolKey::native(BASH_TOOL), CARGO_CMD, None)
    }

    fn allow_source(check: PermissionCheck) -> Option<AllowSource> {
        match check {
            PermissionCheck::Allowed(source) => Some(source),
            _ => None,
        }
    }

    fn plugin_edit_rule(scope: &str, effect: Effect) -> PermissionRule {
        PermissionRule {
            tool: ToolKey::native("edit"),
            scope: Some(scope.into()),
            effect,
        }
    }

    #[test_case("*", "anything" => true ; "star")]
    #[test_case("cargo *", "cargo test" => true ; "prefix")]
    #[test_case("cargo *", "git push" => false ; "prefix_no_match")]
    #[test_case("pwd *", "pwd" => true ; "space_star_matches_bare_command")]
    #[test_case("pwd *", "pwd -L" => true ; "space_star_matches_with_args")]
    #[test_case("pwd *", "pwdx" => false ; "space_star_no_partial_token")]
    #[test_case("src/**", "src/main.rs" => true ; "glob")]
    #[test_case("src/**", "src/deep/nested/file.rs" => true ; "glob_deep_nested")]
    #[test_case("src/**", "src" => true ; "glob_exact_prefix")]
    #[test_case("src/**", "srcfoo" => false ; "glob_no_bare_prefix")]
    #[test_case("src/**", "other/src/main.rs" => false ; "glob_no_inner_match")]
    fn scope_match(pattern: &str, value: &str) -> bool {
        scope_matches(pattern, value)
    }

    /// A pattern is universal only when the trailing glob is all it says.
    #[test_case("*" => true ; "star")]
    #[test_case("**" => true ; "double_star")]
    #[test_case("/*" => true ; "root_star")]
    #[test_case("/**" => true ; "root_double_star")]
    #[test_case("//**" => true ; "doubled_root_slash")]
    #[test_case("/./**" => true ; "root_dot")]
    #[test_case("/tmp/../**" => true ; "root_by_parent")]
    #[test_case("/tmp/**" => false ; "directory_subtree")]
    #[test_case("cargo *" => false ; "bash_command")]
    #[test_case("/" => false ; "root_without_glob")]
    #[test_case("" => false ; "empty")]
    fn universal_scope(pattern: &str) -> bool {
        is_universal_scope(pattern)
    }

    /// The canonical half of `prefix_is_universal`. Lexically the prefix is just
    /// a tempdir; only resolving the symlink reaches the root. A `~/../..`
    /// spelling would prove the same branch but assumes `$HOME` is set and
    /// exactly two levels deep.
    #[test]
    #[cfg(unix)]
    fn universal_scope_through_symlink_to_root() {
        let dir = tempfile::tempdir().unwrap();
        let link = dir.path().join("root");
        std::os::unix::fs::symlink("/", &link).unwrap();
        assert!(is_universal_scope(&format!("{}/**", link.display())));
        assert_universal_invariant(&format!("{}/**", link.display()));
    }

    fn matches_everything(pattern: &str) -> bool {
        OUTSIDE_SCOPES.iter().all(|s| scope_matches(pattern, s))
    }

    fn assert_universal_invariant(pattern: &str) {
        assert!(
            !matches_everything(pattern) || is_universal_scope(pattern),
            "{pattern:?} matches everything but a plugin allow for it would not be refused"
        );
    }

    #[cfg(unix)]
    fn normal_depth(path: &Path) -> usize {
        path.components()
            .filter(|c| matches!(c, Component::Normal(_)))
            .count()
    }

    /// Enough `..` after `path` to reach the root lexically, whatever the
    /// filesystem makes of them.
    #[cfg(unix)]
    fn climb_to_lexical_root(path: &Path) -> String {
        format!("{}{}", path.display(), "/..".repeat(normal_depth(path)))
    }

    #[test_case("*" ; "star")]
    #[test_case("**" ; "double_star")]
    #[test_case("/*" ; "root_star")]
    #[test_case("/**" ; "root_double_star")]
    #[test_case("//**" ; "doubled_root_slash")]
    #[test_case("/./**" ; "root_dot")]
    #[test_case("/tmp/../**" ; "root_by_parent")]
    #[test_case("/etc/../../**" ; "parent_past_root")]
    #[test_case("~/**" ; "home")]
    #[test_case("~/../../../../../../../../**" ; "home_climbed_past_root")]
    #[test_case("../../../../../../../../../../../../**" ; "relative_climbed_past_root")]
    #[test_case("/tmp/**" ; "directory_subtree")]
    #[test_case("cargo *" ; "bash_command")]
    fn universal_scope_invariant(pattern: &str) {
        assert_universal_invariant(pattern);
    }

    /// `link` points four levels deeper, so the `..` that reach the root
    /// lexically stop inside the tempdir once the symlink is followed. Allowing
    /// it grants only that subtree, denying it still denies everything.
    #[test]
    #[cfg(unix)]
    fn lexical_root_through_symlink_is_refused_but_grants_only_its_subtree() {
        let dir = tempfile::tempdir().unwrap();
        let real = dir.path().join("a/b/c/d");
        std::fs::create_dir_all(&real).unwrap();
        let link = dir.path().join("link");
        std::os::unix::fs::symlink(&real, &link).unwrap();
        let pattern = format!("{}/**", climb_to_lexical_root(&link));

        assert!(is_universal_scope(&pattern), "{pattern}");
        for scope in OUTSIDE_SCOPES {
            assert!(!scope_matches(&pattern, scope), "{pattern} matched {scope}");
        }
        for (rule, expected) in [
            (allow_rule(&pattern), PROMPTS),
            (deny_rule(&pattern), DENIED),
        ] {
            let mgr = mgr_with(make_config(vec![rule]), dir.path().to_path_buf());
            assert_eq!(
                outcome(mgr.check(&ToolKey::native(BASH_TOOL), "cargo test", None)),
                expected
            );
        }
    }

    /// The pnpm layout from the bug: `node_modules/react` links deeper into the
    /// store, so a write path climbing to the root lexically lands inside the
    /// project. The session rule has to name that directory, not the root.
    #[test]
    #[cfg(unix)]
    fn write_rule_through_pnpm_symlink_stays_in_landing_dir() {
        let project = tempfile::tempdir().unwrap();
        let link = project.path().join("node_modules/react");
        let store = project
            .path()
            .join(".pnpm/react@18/node_modules/react")
            .join("pad/".repeat(normal_depth(&link).saturating_sub(4)));
        std::fs::create_dir_all(&store).unwrap();
        std::fs::create_dir(link.parent().unwrap()).unwrap();
        std::os::unix::fs::symlink(&store, &link).unwrap();
        let scope = format!("{}/x", climb_to_lexical_root(&link));
        let write = ToolKey::native("write");

        let rule = generalized_scopes(&write, std::slice::from_ref(&scope)).remove(0);
        let rule_dir = rule.strip_suffix("/**").unwrap();
        assert!(
            !Path::new(rule_dir)
                .components()
                .any(|c| c == Component::ParentDir),
            "{rule}"
        );
        assert!(
            normalize_scope_prefix(rule_dir).starts_with(normalize_scope_prefix(project.path())),
            "{rule}"
        );
        assert!(scope_matches(&rule, &scope), "{rule} misses {scope}");

        let mgr = mgr_with(PermissionsConfig::default(), project.path().to_path_buf());
        mgr.apply_decision(&write, &[scope], &PermissionAnswer::AllowSession);
        for outside in OUTSIDE_WRITES {
            assert_eq!(
                outcome(mgr.check(&write, outside, None)),
                PROMPTS,
                "{outside}"
            );
        }
    }

    #[test_case(vec!["cd /tmp", "cargo test"], vec!["cd *", "cargo *"], true ; "all_allowed")]
    #[test_case(vec!["cd /tmp", "cargo test"], vec!["cargo *"], false ; "missing_rule")]
    fn compound_check(scopes: Vec<&str>, rules: Vec<&str>, expect_allowed: bool) {
        let mgr = mgr_with(
            make_config(rules.into_iter().map(allow_rule).collect()),
            PathBuf::from("/tmp"),
        );
        let check = mgr.check_multi(&ToolKey::native("bash"), &scopes, false, None);
        assert_eq!(matches!(check, PermissionCheck::Allowed(_)), expect_allowed);
    }

    #[test]
    fn compound_denied_if_any_segment_denied() {
        let mgr = mgr_with(
            make_config(vec![
                allow_rule("cd *"),
                allow_rule("cargo *"),
                deny_rule("rm *"),
            ]),
            PathBuf::from("/tmp"),
        );
        assert!(matches!(
            mgr.check_multi(
                &ToolKey::native("bash"),
                &["cd /tmp", "cargo test", "rm -rf /"],
                false,
                None
            ),
            PermissionCheck::Denied
        ));
    }

    #[test]
    fn complex_constructs_force_prompt_even_with_allow_star() {
        let mgr = mgr_with(make_config(vec![allow_rule("*")]), PathBuf::from("/tmp"));
        assert!(matches!(
            mgr.check_multi(&ToolKey::native("bash"), &["echo $(whoami)"], true, None),
            PermissionCheck::NeedsPrompt { .. }
        ));
    }

    #[test_case("write", "/tmp/file.txt" => true ; "write_in_cwd")]
    #[test_case("write", "/etc/passwd" => false ; "write_outside_cwd")]
    #[test_case("task", "task:research" => true ; "task_allowed")]
    #[test_case("bash", "cargo test" => false ; "bash_prompts")]
    fn builtin_check(tool: &str, scope: &str) -> bool {
        matches!(
            default_mgr().check(&ToolKey::native(tool), scope, None),
            PermissionCheck::Allowed(_)
        )
    }

    #[test]
    #[cfg(unix)]
    fn scope_matches_resolves_symlinked_parent() {
        let tmp = std::env::temp_dir();
        let real = tmp.join("__maki_test_scope_symlink_real");
        let link = tmp.join("__maki_test_scope_symlink_link");
        let _ = std::fs::remove_dir_all(&real);
        let _ = std::fs::remove_file(&link);
        std::fs::create_dir_all(&real).unwrap();
        std::os::unix::fs::symlink(&real, &link).unwrap();

        let pattern = format!("{}/**", real.display());
        let value = format!("{}/new_file.txt", link.display());
        assert!(
            scope_matches(&pattern, &value),
            "symlinked parent should resolve: pattern={pattern}, value={value}"
        );

        let _ = std::fs::remove_dir_all(&real);
        let _ = std::fs::remove_file(&link);
    }

    #[test]
    fn scope_matches_relative_pattern_before_dir_exists() {
        // A relative rule like `dist/**` must match an absolute value even
        // before the directory exists.
        let cwd = std::env::current_dir().unwrap();
        let value = cwd.join("__maki_nonexistent_dist/file.txt");
        assert!(!value.exists(), "test dir must not exist");
        assert!(
            scope_matches("__maki_nonexistent_dist/**", &value.to_string_lossy()),
            "relative pattern should match absolute value: value={}",
            value.display()
        );
    }

    #[test]
    #[cfg(unix)]
    fn scope_matches_symlinked_parent_with_nonexistent_tail() {
        // Regression: symlinked leading component plus a non-existent tail
        // (`proj`). Both sides must resolve the symlink before appending the
        // lexical tail, else the prefix stays lexical and this returns false.
        let tmp = std::env::temp_dir();
        let real = tmp.join("__maki_test_scope_symlink_tail_real");
        let link = tmp.join("__maki_test_scope_symlink_tail_link");
        let _ = std::fs::remove_dir_all(&real);
        let _ = std::fs::remove_file(&link);
        std::fs::create_dir_all(&real).unwrap();
        std::os::unix::fs::symlink(&real, &link).unwrap();

        // `proj` under the symlink does not exist.
        let pattern = format!("{}/proj/**", link.display());
        let value = format!("{}/proj/file.txt", link.display());
        assert!(
            scope_matches(&pattern, &value),
            "symlinked parent with non-existent tail should match: pattern={pattern}, value={value}"
        );

        let _ = std::fs::remove_dir_all(&real);
        let _ = std::fs::remove_file(&link);
    }

    #[test]
    fn path_traversal_prompts() {
        assert!(matches!(
            default_mgr().check(&ToolKey::native("write"), "/tmp/../etc/passwd", None),
            PermissionCheck::NeedsPrompt { .. }
        ));
    }

    #[test]
    fn session_rule_overrides_config() {
        let mgr = mgr_with(
            make_config(vec![allow_rule("cargo *")]),
            PathBuf::from("/tmp"),
        );
        mgr.add_session_rule(deny_rule("cargo *"));
        assert!(matches!(
            mgr.check(&ToolKey::native("bash"), "cargo test", None),
            PermissionCheck::Denied
        ));
    }

    #[test]
    fn deny_overrides_default_allow() {
        let mgr = mgr_with(
            PermissionsConfig {
                default: DefaultEffect::Allow,
                rules: vec![deny_rule("rm *")],
                ..Default::default()
            },
            PathBuf::from("/tmp"),
        );
        assert!(matches!(
            mgr.check(&ToolKey::native("bash"), "rm -rf /", None),
            PermissionCheck::Denied
        ));
    }

    // When you allow "cargo test", we generalize to "cargo *" for convenience.
    // But denies stay exact, you probably have a good reason to block that specific thing.
    #[test]
    fn allow_decision_generalizes() {
        let mgr = default_mgr();
        mgr.apply_decision(
            &ToolKey::native("bash"),
            &["cargo test --all".into()],
            &PermissionAnswer::AllowSession,
        );
        assert!(matches!(
            mgr.check(&ToolKey::native("bash"), "cargo build", None),
            PermissionCheck::Allowed(_)
        ));
    }

    #[test]
    fn deny_decision_uses_exact() {
        let project = tempfile::tempdir().unwrap();
        let mgr = mgr_with(PermissionsConfig::default(), project.path().to_path_buf());
        mgr.apply_decision(
            &ToolKey::native("bash"),
            &["cargo test".into()],
            &PermissionAnswer::DenyAlwaysProject,
        );
        assert!(matches!(
            mgr.check(&ToolKey::native("bash"), "cargo test", None),
            PermissionCheck::Denied
        ));
        assert!(matches!(
            mgr.check(&ToolKey::native("bash"), "cargo build", None),
            PermissionCheck::NeedsPrompt { .. }
        ));
    }

    /// A trusted folder collects the answer in `.maki/permissions.toml`. An
    /// untrusted one keeps it for the session and gets no `.maki` directory,
    /// for deny as much as for allow, because declining to trust a checkout
    /// has to leave nothing behind in it. The deny that lasts is the global
    /// one.
    #[test_case(PermissionAnswer::AllowAlwaysProject, true, true ; "allow_is_written_when_trusted")]
    #[test_case(PermissionAnswer::DenyAlwaysProject, false, true ; "deny_is_written_when_trusted")]
    #[test_case(PermissionAnswer::AllowAlwaysProject, true, false ; "allow_stays_in_the_session_when_untrusted")]
    #[test_case(PermissionAnswer::DenyAlwaysProject, false, false ; "deny_stays_in_the_session_when_untrusted")]
    fn project_answer_is_written_only_in_a_trusted_folder(
        answer: PermissionAnswer,
        allowed: bool,
        trusted: bool,
    ) {
        let project = tempfile::tempdir().unwrap();
        let mgr = PermissionManager::new(
            PermissionsConfig::default(),
            project.path().to_path_buf(),
            if trusted {
                ProjectConfig::for_project(project.path())
            } else {
                ProjectConfig::discover(project.path())
            },
            Arc::default(),
        );

        mgr.apply_decision(&ToolKey::native("bash"), &["cargo test".into()], &answer);

        assert_eq!(mgr.session_rules_snapshot().len(), 1);
        assert_eq!(project.path().join(PROJECT_DIR).exists(), trusted);
        assert_eq!(project.path().join(PROJECT_PERMISSIONS).is_file(), trusted);
        let check = mgr.check(&ToolKey::native("bash"), "cargo test", None);
        assert_eq!(matches!(check, PermissionCheck::Allowed(_)), allowed);
        assert_eq!(matches!(check, PermissionCheck::Denied), !allowed);
    }
    #[test]
    fn boundary_inside_proceeds() {
        let tmp = std::env::temp_dir();
        let mgr = mgr_with(PermissionsConfig::default(), tmp.clone());
        assert!(
            mgr.boundary_block_reason(&tmp.join("some_file.txt"))
                .is_none()
        );
    }

    #[test]
    fn boundary_outside_proceeds_via_prompt() {
        let tmp = std::env::temp_dir();
        let mgr = mgr_with(PermissionsConfig::default(), tmp);
        #[cfg(unix)]
        let outside = Path::new("/etc/hosts");
        #[cfg(windows)]
        let outside = Path::new(r"C:\Windows\System32\drivers\etc\hosts");
        assert!(mgr.boundary_block_reason(outside).is_none());
    }

    #[test]
    fn boundary_dotdot_smuggling_proceeds_via_prompt() {
        let tmp = std::env::temp_dir();
        let sub = tmp.join("__maki_test_boundary");
        std::fs::create_dir_all(&sub).unwrap();
        #[cfg(unix)]
        let attack = sub
            .join("x")
            .join("..")
            .join("..")
            .join("..")
            .join("etc")
            .join("passwd");
        #[cfg(windows)]
        let attack = sub
            .join("x")
            .join("..")
            .join("..")
            .join("..")
            .join("Windows")
            .join("System32");
        let mgr = mgr_with(PermissionsConfig::default(), sub.clone());
        assert!(
            mgr.boundary_block_reason(&attack).is_none(),
            "outside-cwd dotdot path should prompt, not hard-block: {}",
            attack.display()
        );
        let _ = std::fs::remove_dir_all(&sub);
    }

    #[test]
    #[cfg(unix)]
    fn boundary_symlink_escape_proceeds_via_prompt() {
        // Lexical normalization resolves this inside (/project/escape), but
        // incremental canonicalization follows the symlink first, so `..`
        // escapes outside. The permission prompt catches it, not this function.
        let tmp = std::env::temp_dir();
        let project = tmp.join("__maki_test_symlink_escape");
        let _ = std::fs::remove_dir_all(&project);
        std::fs::create_dir_all(&project).unwrap();
        let link = project.join("link");
        let _ = std::os::unix::fs::symlink(&tmp, &link);

        let attack = link.join("..").join("escape_target");
        let mgr = mgr_with(PermissionsConfig::default(), project.clone());
        assert!(
            mgr.boundary_block_reason(&attack).is_none(),
            "outside-boundary edits are gated by the prompt, not hard-blocked: {}",
            attack.display()
        );
        let _ = std::fs::remove_dir_all(&project);
    }

    #[test]
    fn boundary_nonexistent_cwd_proceeds_via_lexical_tail() {
        let missing = std::env::temp_dir().join("__maki_test_absent_cwd_xyz");
        let _ = std::fs::remove_dir_all(&missing);
        let mgr = mgr_with(PermissionsConfig::default(), missing.clone());
        assert!(
            mgr.boundary_block_reason(&missing.join("file.txt"))
                .is_none()
        );
    }

    #[test]
    fn permission_answer_roundtrip() {
        for a in [
            PermissionAnswer::AllowOnce,
            PermissionAnswer::AllowSession,
            PermissionAnswer::AllowAlwaysProject,
            PermissionAnswer::Deny,
            PermissionAnswer::DenyWithGuidance("hint".into()),
        ] {
            assert_eq!(PermissionAnswer::decode(&a.encode()), Some(a));
        }
    }

    #[test_case(PermissionAnswer::AllowAlwaysProject ; "allow")]
    #[test_case(PermissionAnswer::Deny ; "deny")]
    #[test_case(PermissionAnswer::DenyWithGuidance(TAGGED_GUIDANCE.into()) ; "guidance_with_separator")]
    fn tagged_answer_roundtrip(answer: PermissionAnswer) {
        let tagged = TaggedAnswer::new(TAGGED_REQUEST_ID, answer);
        assert_eq!(TaggedAnswer::decode(&tagged.encode()), Some(tagged));
    }

    #[test_case("" ; "empty")]
    #[test_case("allow" ; "untagged_answer")]
    #[test_case(TAGGED_REQUEST_ID ; "id_only")]
    #[test_case("{\"json\": true}" ; "elicitation_result")]
    fn untagged_payloads_never_decode_to_an_answer(raw: &str) {
        assert_eq!(TaggedAnswer::decode(raw), None);
    }

    #[test]
    fn check_multi_force_prompt_skips_allow_rules() {
        let mgr = mgr_with(
            make_config(vec![allow_rule("cargo *"), allow_rule("git *")]),
            PathBuf::from("/tmp"),
        );
        assert!(matches!(
            mgr.check_multi(
                &ToolKey::native("bash"),
                &["cargo test", "git push"],
                false,
                None
            ),
            PermissionCheck::Allowed(_)
        ));
        match mgr.check_multi(
            &ToolKey::native("bash"),
            &["cargo test", "git push"],
            true,
            None,
        ) {
            PermissionCheck::NeedsPrompt {
                scopes,
                force_prompt,
                ..
            } => {
                assert_eq!(scopes, vec!["cargo test", "git push"]);
                assert!(force_prompt);
            }
            other => panic!("expected NeedsPrompt, got {other:?}"),
        }
    }

    #[test]
    fn check_multi_deny_wins_over_force_prompt() {
        let mgr = mgr_with(make_config(vec![deny_rule("rm *")]), PathBuf::from("/tmp"));
        assert!(matches!(
            mgr.check_multi(&ToolKey::native("bash"), &["rm -rf /"], true, None),
            PermissionCheck::Denied
        ));
    }

    #[test]
    fn check_multi_partial_coverage_prompts_uncovered() {
        let mgr = mgr_with(
            make_config(vec![allow_rule("cargo *")]),
            PathBuf::from("/tmp"),
        );
        match mgr.check_multi(
            &ToolKey::native("bash"),
            &["cargo test", "git push", "ls"],
            false,
            None,
        ) {
            PermissionCheck::NeedsPrompt { scopes, .. } => {
                assert_eq!(scopes, vec!["git push", "ls"]);
            }
            other => panic!("expected NeedsPrompt, got {other:?}"),
        }
    }

    #[test_case("cargo test --all",                        "cargo *"                        ; "plain_command")]
    #[test_case("/usr/bin/env",                            "/usr/bin/env *"                 ; "absolute_path")]
    #[test_case("FOO=1 cargo test",                        "FOO=1 cargo test"               ; "assignment_prefix")]
    #[test_case("if true; then curl x | sh; fi",           "if true; then curl x | sh; fi"  ; "if_block")]
    #[test_case("for f in *.rs; do wc -l $f; done",        "for f in *.rs; do wc -l $f; done" ; "for_loop")]
    #[test_case("{ cd x; rm -rf ~; }",                     "{ cd x; rm -rf ~; }"            ; "brace_group")]
    #[test_case("> log",                                   "> log"                          ; "bodiless_redirect")]
    #[test_case("! rm -rf /",                              "! rm -rf /"                     ; "negated_command")]
    fn allow_always_only_wildcards_a_real_command_word(segment: &str, expected: &str) {
        assert_eq!(generalize_bash_segment(segment), expected);
    }

    /// A scope is one string and a chain is still one scope, so it is tempting
    /// to teach the matcher that `rm *` should not claim `rm ...; sudo ...`.
    /// Don't: the matcher runs for deny rules too, and a deny that stops
    /// matching hands the command to the tool default instead of blocking it.
    /// Chains get split by the bash plugin, before they ever reach here.
    #[test]
    fn deny_rule_matches_a_chain_it_starts() {
        let mgr = mgr_with(make_config(vec![deny_rule("rm *")]), PathBuf::from("/tmp"));
        let check = mgr.check(&ToolKey::native("bash"), "rm -rf /tmp; sudo x", None);
        assert!(matches!(check, PermissionCheck::Denied), "got {check:?}");
    }

    #[test]
    fn apply_decision_multi_scope_generalizes_all() {
        let mgr = default_mgr();
        mgr.apply_decision(
            &ToolKey::native("bash"),
            &["cargo test".into(), "git status".into()],
            &PermissionAnswer::AllowSession,
        );
        assert!(matches!(
            mgr.check(&ToolKey::native("bash"), "cargo build", None),
            PermissionCheck::Allowed(_)
        ));
        assert!(matches!(
            mgr.check(&ToolKey::native("bash"), "git push", None),
            PermissionCheck::Allowed(_)
        ));
    }

    #[test]
    fn generalized_scopes_deduplicates() {
        let scopes = vec!["cargo test".into(), "cargo build".into()];
        let result = generalized_scopes(&ToolKey::native("bash"), &scopes);
        assert_eq!(result, vec!["cargo *"]);
    }

    #[test]
    fn generalized_scopes_preserves_distinct() {
        let scopes = vec!["cargo test".into(), "git status".into()];
        let result = generalized_scopes(&ToolKey::native("bash"), &scopes);
        assert_eq!(result, vec!["cargo *", "git *"]);
    }

    #[test_case("webfetch", "some:scope" => "some:scope" ; "unknown_tool_preserves_exact")]
    #[test_case("myserver.fetch", "{\"url\":\"https://a\"}" => "*" ; "mcp_tool_generalizes_to_wildcard")]
    fn generalize_single_scope(tool: &str, scope: &str) -> String {
        generalized_scopes(&ToolKey::parse(tool).unwrap(), &[scope.into()])
            .into_iter()
            .next()
            .unwrap()
    }

    #[test]
    fn generalize_edit_uses_parent_dir() {
        let result = generalize_scope(&ToolKey::native("edit"), "/home/user/project/src/main.rs");
        let expected = format!(
            "{}/**",
            Path::new("/home/user/project/src/main.rs")
                .parent()
                .unwrap()
                .display()
        );
        assert_eq!(result, expected);
    }

    #[test]
    fn generalize_edit_root_file() {
        let result = generalize_scope(&ToolKey::native("edit"), "/Cargo.toml");
        let expected = format!(
            "{}/**",
            Path::new("/Cargo.toml").parent().unwrap().display()
        );
        assert_eq!(result, expected);
    }

    /// "Allow always" stores a command's generalized scope as a rule, so the
    /// command must match the very rule it would create. When this broke, the
    /// bare `pwd` never matched its own `pwd *` rule and we reprompted forever.
    #[test_case("bash", "pwd" ; "bash_bare_command")]
    #[test_case("bash", "cargo test" ; "bash_command_with_args")]
    #[test_case("bash", "git status --short" ; "bash_command_with_flags")]
    #[test_case("edit", "/home/user/project/src/main.rs" ; "edit_path")]
    #[test_case("webfetch", "https://example.com" ; "unknown_tool_exact")]
    #[test_case("myfetch.search", "{\"url\":\"https://a\"}" ; "mcp_tool_call")]
    fn command_matches_its_own_generalized_rule(tool: &str, scope: &str) {
        let tool_key = ToolKey::parse(tool).unwrap();
        let rule = &generalized_scopes(&tool_key, &[scope.into()])[0];
        assert!(
            scope_matches(rule, scope),
            "{scope:?} does not match its generalized rule {rule:?}"
        );
    }

    /// "Allow always" on an MCP tool generalizes the stored scope to `*`, so a
    /// later call with different arguments matches the persisted rule instead of
    /// reprompting, while a different MCP tool is still gated by its `tool` name.
    #[test]
    fn mcp_allow_always_matches_any_args_but_stays_per_tool() {
        let mgr = default_mgr();
        mgr.apply_decision(
            &ToolKey::parse("myfetch.search").unwrap(),
            &["{\"url\":\"https://a\"}".into()],
            &PermissionAnswer::AllowSession,
        );
        // Same tool, different arguments -> allowed without reprompting.
        assert!(matches!(
            mgr.check(
                &ToolKey::parse("myfetch.search").unwrap(),
                "{\"url\":\"https://b\"}",
                None
            ),
            PermissionCheck::Allowed(_)
        ));
        // A distinct MCP tool is not covered by the fetch rule.
        assert!(!matches!(
            mgr.check(
                &ToolKey::parse("myfetch.exec").unwrap(),
                "{\"cmd\":\"ls\"}",
                None
            ),
            PermissionCheck::Allowed(_)
        ));
    }

    #[test]
    fn deny_rule_with_none_scope_blocks_everything() {
        let mgr = mgr_with(
            make_config(vec![PermissionRule {
                tool: ToolKey::native("bash"),
                scope: None,
                effect: Effect::Deny,
            }]),
            PathBuf::from("/tmp"),
        );
        assert!(matches!(
            mgr.check(&ToolKey::native("bash"), "anything", None),
            PermissionCheck::Denied
        ));
    }

    #[test]
    fn wildcard_deny_blocks_all_tools() {
        let mgr = mgr_with(
            make_config(vec![PermissionRule {
                tool: ToolKey::Wildcard,
                scope: None,
                effect: Effect::Deny,
            }]),
            PathBuf::from("/tmp"),
        );
        // Any deny wins: Wildcard deny blocks everything including builtins
        assert!(matches!(
            mgr.check(&ToolKey::native("bash"), "ls", None),
            PermissionCheck::Denied
        ));
        assert!(matches!(
            mgr.check(&ToolKey::native("write"), "/tmp/x", None),
            PermissionCheck::Denied
        ));
    }

    #[test]
    fn mcp_deny_always_blocks_all_arguments() {
        let project = tempfile::tempdir().unwrap();
        let mgr = mgr_with(make_config(vec![]), project.path().to_path_buf());
        let tool = ToolKey::McpTool {
            server: "deepwiki".into(),
            tool: "search".into(),
        };
        // User denies with specific arguments — should generalize to block all.
        mgr.apply_decision(
            &tool,
            &["{\"q\":\"dangerous\"}".into()],
            &PermissionAnswer::DenyAlwaysProject,
        );
        // Different arguments: still denied.
        assert!(matches!(
            mgr.check(&tool, "{\"q\":\"safe\"}", None),
            PermissionCheck::Denied
        ));
        // Even wildcard scope: denied.
        assert!(matches!(
            mgr.check(&tool, "*", None),
            PermissionCheck::Denied
        ));
    }

    /// Yolo is a mode whose one rule allows everything, so the oldest rule of
    /// all still holds: a deny beats it.
    #[test]
    fn the_yolo_mode_allows_but_deny_still_blocks() {
        let mgr = mgr_with(make_config(vec![deny_rule("rm *")]), PathBuf::from("/tmp"));
        assert!(mgr.toggle_yolo());
        assert!(mgr.is_yolo());
        assert!(matches!(
            mgr.check(&ToolKey::native(BASH_TOOL), CARGO_CMD, None),
            PermissionCheck::Allowed(_)
        ));
        assert!(matches!(
            mgr.check(&ToolKey::native(BASH_TOOL), "rm -rf /", None),
            PermissionCheck::Denied
        ));
    }

    /// And it outranks a `default`, which is what a mode's own blanket default
    /// deliberately does not do. Yolo carries a rule for exactly this reason.
    #[test]
    fn the_yolo_mode_outranks_a_per_tool_default() {
        let mgr = mgr_with(
            PermissionsConfig {
                tool_defaults: HashMap::from([(ToolKey::native(BASH_TOOL), DefaultEffect::Deny)]),
                ..Default::default()
            },
            PathBuf::from("/tmp"),
        );
        assert!(mgr.toggle_yolo());
        assert_eq!(allow_source(bash_check(&mgr)), Some(AllowSource::Mode));
    }

    fn seeded_mgr(yolo: bool) -> PermissionManager {
        mgr_with(
            PermissionsConfig {
                initial_mode: yolo.then(|| BUILTIN_MODE_YOLO.to_owned()),
                ..Default::default()
            },
            PathBuf::from("/tmp"),
        )
    }

    /// A fork runs the same session, so it has to answer both questions the
    /// same way or a respawned agent drifts from the tab that owns it.
    fn yolo_state(mgr: &PermissionManager) -> (bool, Option<String>) {
        let forked = mgr.fork();
        assert_eq!(
            (forked.is_yolo(), forked.persisted_mode()),
            (mgr.is_yolo(), mgr.persisted_mode()),
        );
        (mgr.is_yolo(), mgr.persisted_mode())
    }

    fn stored_yolo() -> Option<String> {
        Some(BUILTIN_MODE_YOLO.to_owned())
    }

    fn stored_off() -> Option<String> {
        Some(MODE_OFF.to_owned())
    }

    /// A stored answer replaces the seed outright, and no stored answer falls
    /// back to it: `--yolo` must neither be erased by an untouched session nor
    /// survive one the user explicitly turned off.
    #[test_case(false, None             => (false, None)           ; "no_flag_and_no_answer_stays_off")]
    #[test_case(true,  None             => (true,  None)           ; "the_flag_applies_but_is_never_stored")]
    #[test_case(false, Some(BUILTIN_MODE_YOLO) => (true, stored_yolo()) ; "stored_on_comes_back_without_the_flag")]
    #[test_case(true,  Some(BUILTIN_MODE_YOLO) => (true, stored_yolo()) ; "the_flag_does_not_wipe_stored_on")]
    #[test_case(true,  Some(MODE_OFF)   => (false, stored_off())    ; "stored_off_overrides_the_flag")]
    #[test_case(false, Some(MODE_OFF)   => (false, stored_off())    ; "stored_off_stays_off")]
    fn a_stored_answer_replaces_the_seed(
        seed: bool,
        stored: Option<&str>,
    ) -> (bool, Option<String>) {
        let mgr = seeded_mgr(seed);
        mgr.set_session_mode(stored).expect("a mode maki ships");
        yolo_state(&mgr)
    }

    /// `/yolo` always drives the effective state, so under `--yolo` it can turn
    /// the session off, and either way the session now owns the answer.
    #[test_case(false => (true,  stored_yolo()) ; "toggling_on_claims_the_session")]
    #[test_case(true  => (false, stored_off())  ; "toggling_off_under_the_flag_claims_the_session")]
    fn toggling_yolo_records_the_answer(seed: bool) -> (bool, Option<String>) {
        let mgr = seeded_mgr(seed);
        assert_eq!(mgr.toggle_yolo(), !seed);
        yolo_state(&mgr)
    }

    /// The whole point of a mode: a call that would have prompted runs, and the
    /// answer says the mode is why, since that is what the budget is spent on.
    #[test]
    fn a_mode_waves_through_what_would_have_prompted() {
        let mgr = mgr_in_mode(
            vec![mode(MODE_NAME, vec![allow_rule(CARGO_SCOPE)])],
            MODE_NAME,
        );
        assert_eq!(allow_source(bash_check(&mgr)), Some(AllowSource::Mode));
        mgr.set_mode(None).unwrap();
        assert_eq!(
            outcome(bash_check(&mgr)),
            PROMPTS,
            "and asks again once off"
        );
    }

    /// A mode is rules, so the rule that no allow outranks a deny holds for it
    /// too, in both directions.
    #[test]
    fn a_deny_still_wins_against_a_mode() {
        let mgr = mgr_with(
            PermissionsConfig {
                rules: vec![deny_rule(CARGO_SCOPE)],
                modes: vec![mode(MODE_NAME, vec![allow_rule(CARGO_SCOPE)])],
                initial_mode: Some(MODE_NAME.to_owned()),
                ..Default::default()
            },
            PathBuf::from("/tmp"),
        );
        assert_eq!(outcome(bash_check(&mgr)), DENIED);
    }

    #[test]
    fn a_mode_deny_blocks_what_the_config_allowed() {
        let mgr = mgr_with(
            PermissionsConfig {
                rules: vec![allow_rule(CARGO_SCOPE)],
                modes: vec![mode(OTHER_MODE, vec![deny_rule(CARGO_SCOPE)])],
                initial_mode: Some(OTHER_MODE.to_owned()),
                ..Default::default()
            },
            PathBuf::from("/tmp"),
        );
        assert_eq!(outcome(bash_check(&mgr)), DENIED);
    }

    /// A mode riding along with rules that already allowed the call spends
    /// nothing, or every call would eat a budget the mode never granted.
    #[test]
    fn a_call_the_rules_allowed_is_not_charged_to_the_mode() {
        let mgr = mgr_with(
            PermissionsConfig {
                rules: vec![allow_rule(CARGO_SCOPE)],
                modes: vec![mode(MODE_NAME, vec![allow_rule(CARGO_SCOPE)])],
                initial_mode: Some(MODE_NAME.to_owned()),
                ..Default::default()
            },
            PathBuf::from("/tmp"),
        );
        assert_eq!(allow_source(bash_check(&mgr)), Some(AllowSource::Rule));
    }

    /// Specific beats general whoever wrote it, so switching on a mode that
    /// allows by default cannot quietly undo a per-tool deny in the config.
    #[test]
    fn a_config_tool_default_outranks_a_modes_blanket_one() {
        let mgr = mgr_with(
            PermissionsConfig {
                tool_defaults: HashMap::from([(ToolKey::native(BASH_TOOL), DefaultEffect::Deny)]),
                modes: vec![Arc::new(PermissionMode {
                    name: MODE_NAME.to_owned(),
                    default: Some(DefaultEffect::Allow),
                    ..Default::default()
                })],
                initial_mode: Some(MODE_NAME.to_owned()),
                ..Default::default()
            },
            PathBuf::from("/tmp"),
        );
        assert_eq!(outcome(bash_check(&mgr)), DENIED);
        assert_eq!(
            allow_source(mgr.check(&ToolKey::native(READ_TOOL), "", None)),
            Some(AllowSource::Mode),
            "while a tool the config says nothing about follows the mode"
        );
    }

    #[test]
    fn a_modes_tool_default_outranks_the_configs() {
        let mgr = mgr_with(
            PermissionsConfig {
                tool_defaults: HashMap::from([(ToolKey::native(BASH_TOOL), DefaultEffect::Deny)]),
                modes: vec![Arc::new(PermissionMode {
                    name: MODE_NAME.to_owned(),
                    tool_defaults: HashMap::from([(
                        ToolKey::native(BASH_TOOL),
                        DefaultEffect::Allow,
                    )]),
                    ..Default::default()
                })],
                initial_mode: Some(MODE_NAME.to_owned()),
                ..Default::default()
            },
            PathBuf::from("/tmp"),
        );
        assert_eq!(allow_source(bash_check(&mgr)), Some(AllowSource::Mode));
    }

    fn budgeted_mgr(max: u32) -> PermissionManager {
        mgr_in_mode(
            vec![Arc::new(PermissionMode {
                name: MODE_NAME.to_owned(),
                rules: vec![allow_rule(CARGO_SCOPE)],
                max_auto_calls: Some(max),
                ..Default::default()
            })],
            MODE_NAME,
        )
    }

    /// The budget is spent by calls the mode waved through, and a spent one
    /// hands the question back to the user rather than widening or narrowing.
    #[test]
    fn a_spent_budget_asks_again() {
        let mgr = budgeted_mgr(2);
        for spent in 0..2 {
            assert_eq!(mgr.mode_spend(), (spent, Some(2)));
            let source = allow_source(bash_check(&mgr)).expect("the mode allows it");
            assert_eq!(source, AllowSource::Mode);
            assert!(mgr.allowed_by(BASH_TOOL, source).is_ok());
        }
        assert_eq!(outcome(bash_check(&mgr)), PROMPTS);
        mgr.begin_turn();
        assert_eq!(mgr.mode_spend(), (0, Some(2)), "a new turn, a new budget");
        assert_eq!(allow_source(bash_check(&mgr)), Some(AllowSource::Mode));
    }

    /// A spent budget silences the mode's allows alone: running out of rope is
    /// no reason to loosen what the mode tightened.
    #[test]
    fn a_spent_budget_keeps_denying() {
        let mgr = mgr_in_mode(
            vec![Arc::new(PermissionMode {
                name: MODE_NAME.to_owned(),
                rules: vec![deny_rule(CARGO_SCOPE)],
                max_auto_calls: Some(0),
                ..Default::default()
            })],
            MODE_NAME,
        );
        assert_eq!(outcome(bash_check(&mgr)), DENIED);
    }

    /// The same rule one layer down: a spent budget drops the mode's allow-by-
    /// default and keeps its deny-by-default.
    #[test_case(DefaultEffect::Allow, PROMPTS ; "an_allow_default_goes_quiet")]
    #[test_case(DefaultEffect::Deny, DENIED ; "a_deny_default_holds")]
    fn a_spent_budget_only_silences_the_modes_defaults_that_widen(
        eff: DefaultEffect,
        expected: &str,
    ) {
        let mgr = mgr_in_mode(
            vec![Arc::new(PermissionMode {
                name: MODE_NAME.to_owned(),
                tool_defaults: HashMap::from([(ToolKey::native(BASH_TOOL), eff)]),
                max_auto_calls: Some(0),
                ..Default::default()
            })],
            MODE_NAME,
        );
        assert_eq!(outcome(bash_check(&mgr)), expected);
    }

    #[test]
    fn a_turn_mode_lapses_when_the_turn_ends() {
        let mgr = mgr_in_mode(
            vec![Arc::new(PermissionMode {
                name: MODE_NAME.to_owned(),
                expires: ModeExpiry::Turn,
                ..Default::default()
            })],
            MODE_NAME,
        );
        mgr.begin_turn();
        assert_eq!(mgr.active_mode_name().as_deref(), Some(MODE_NAME));
        mgr.end_turn();
        assert_eq!(mgr.active_mode_name(), None);
    }

    #[test]
    fn a_session_mode_survives_the_turn() {
        let mgr = mgr_in_mode(vec![mode(MODE_NAME, Vec::new())], MODE_NAME);
        mgr.begin_turn();
        mgr.end_turn();
        assert_eq!(mgr.active_mode_name().as_deref(), Some(MODE_NAME));
    }

    /// The human just contradicted the standing grant, so a mode that asked to
    /// be dropped over that is dropped. One that did not stays on.
    #[test_case(true, None ; "revert_on_deny_drops_it")]
    #[test_case(false, Some(MODE_NAME) ; "otherwise_it_stays")]
    fn a_denial_from_the_user_can_revert_the_mode(revert: bool, expect: Option<&str>) {
        let mgr = mgr_in_mode(
            vec![Arc::new(PermissionMode {
                name: MODE_NAME.to_owned(),
                revert_on_deny: revert,
                ..Default::default()
            })],
            MODE_NAME,
        );
        mgr.note_user_deny();
        assert_eq!(mgr.active_mode_name().as_deref(), expect);
    }

    #[test]
    fn an_unknown_mode_is_refused_rather_than_read_as_off() {
        let mgr = mgr_in_mode(vec![mode(MODE_NAME, Vec::new())], MODE_NAME);
        assert!(mgr.set_mode(Some("nope")).is_err());
        assert_eq!(
            mgr.active_mode_name().as_deref(),
            Some(MODE_NAME),
            "and leaves the mode it could not change"
        );
    }

    /// Cycling walks every mode and passes back through off, so Shift+Tab can
    /// always get to prompting for everything.
    #[test]
    fn cycling_walks_the_modes_and_back_off() {
        let mgr = mgr_with(
            PermissionsConfig {
                modes: vec![mode(MODE_NAME, Vec::new()), mode(OTHER_MODE, Vec::new())],
                ..Default::default()
            },
            PathBuf::from("/tmp"),
        );
        let walked: Vec<Option<String>> = (0..3)
            .map(|_| mgr.cycle_mode().map(|m| m.name.clone()))
            .collect();
        assert_eq!(
            walked,
            vec![
                Some(MODE_NAME.to_owned()),
                Some(OTHER_MODE.to_owned()),
                None
            ]
        );
    }

    /// A subagent runs turns of its own, so it inherits the mode and none of
    /// the parent's spending.
    #[test]
    fn a_fork_inherits_the_mode_with_a_fresh_budget() {
        let mgr = budgeted_mgr(2);
        mgr.charge_mode();
        let forked = mgr.fork();
        assert_eq!(forked.active_mode_name().as_deref(), Some(MODE_NAME));
        assert_eq!(forked.mode_spend(), (0, Some(2)));
        assert_eq!(mgr.mode_spend(), (1, Some(2)), "and leaves the parent's");
    }

    const DECIDE_REASON: &str = "a plugin said no";
    const ASK_REASON: &str = "a layer wants the human";
    const DECIDE_CODE: &str = "remote_mutation";
    const PIPE_TO_SHELL: &str = "| sh";

    /// Answers with one decision and counts what it was asked about.
    struct TestDecider {
        answer: fn(&PermissionCall) -> Decision,
        calls: Arc<AtomicUsize>,
    }

    impl TestDecider {
        /// The decider as the gate takes it, plus the counter the test reads.
        fn installed(
            answer: fn(&PermissionCall) -> Decision,
        ) -> (InstalledPermissionHook, Arc<AtomicUsize>) {
            let calls = Arc::new(AtomicUsize::new(0));
            let hook: Box<dyn crate::tools::hook::PermissionHook> = Box::new(Self {
                answer,
                calls: Arc::clone(&calls),
            });
            (Arc::new(hook), calls)
        }
    }

    impl crate::tools::hook::PermissionHook for TestDecider {
        fn wraps(&self) -> bool {
            true
        }

        fn run<'a>(
            &'a self,
            call: &'a PermissionCall<'a>,
        ) -> crate::tools::registry::BoxFuture<'a, Decision> {
            self.calls.fetch_add(1, Ordering::Relaxed);
            let answer = (self.answer)(call);
            Box::pin(async move { answer })
        }
    }

    /// Runs the gate with `decider` installed and no answer channel, so a call
    /// that reaches the prompt fails rather than hanging.
    fn enforce_with(
        mgr: &PermissionManager,
        decider: Option<InstalledPermissionHook>,
        ask: Option<&str>,
    ) -> Result<(), PermissionError> {
        enforce_input(mgr, decider, ask, None)
    }

    fn enforce_input(
        mgr: &PermissionManager,
        decider: Option<InstalledPermissionHook>,
        ask: Option<&str>,
        input: Option<&Value>,
    ) -> Result<(), PermissionError> {
        let (guard, _events) = crate::event_stream();
        let event_tx = guard.sender(0);
        smol::block_on(mgr.enforce(
            &ToolKey::native(BASH_TOOL),
            &crate::tools::PermissionScopes::single(CARGO_CMD.to_owned()),
            Gate {
                event_tx: &event_tx,
                user_response_rx: None,
                request_id: "req",
                cancel: &crate::CancelToken::none(),
                plan_path: None,
                input,
                ask,
                decider,
            },
        ))
    }

    #[test]
    fn a_decider_can_allow_a_call_the_rules_left_to_the_user() {
        let mgr = mgr_in_mode(vec![mode(MODE_NAME, Vec::new())], MODE_NAME);
        let (decider, _) = TestDecider::installed(|_| Decision::Allow(Rationale::default()));
        assert!(enforce_with(&mgr, Some(decider), None).is_ok());
        assert_eq!(
            mgr.mode_spend(),
            (0, None),
            "a decider's grant is its own, not the mode's to pay for"
        );
    }

    #[test]
    fn a_decider_can_deny_with_its_own_guidance() {
        let mgr = default_mgr();
        let (decider, _) = TestDecider::installed(|_| {
            Decision::Deny(Rationale {
                reason: Some(DECIDE_REASON.to_owned()),
                code: Some(DECIDE_CODE.to_owned()),
            })
        });
        let err = enforce_with(&mgr, Some(decider), None).expect_err("denied");
        assert!(err.to_string().contains(DECIDE_REASON));
    }

    #[test]
    fn a_code_stands_in_for_a_missing_reason() {
        let mgr = default_mgr();
        let (decider, _) = TestDecider::installed(|_| {
            Decision::Deny(Rationale {
                reason: None,
                code: Some(DECIDE_CODE.to_owned()),
            })
        });
        let err = enforce_with(&mgr, Some(decider), None).expect_err("denied");
        assert!(err.to_string().contains(DECIDE_CODE));
    }

    /// The decider judges the call itself, inside the project it runs in,
    /// rather than what the scopes kept of it.
    #[test]
    fn a_decider_sees_the_input_and_where_it_runs() {
        let cwd = tempfile::tempdir().unwrap();
        let mgr = mgr_with(PermissionsConfig::default(), cwd.path().to_path_buf());
        let (decider, _) = TestDecider::installed(|call| {
            let piped = call
                .input
                .and_then(|input| input["command"].as_str())
                .is_some_and(|command| command.contains(PIPE_TO_SHELL));
            match piped && call.trusted && call.cwd.starts_with(call.project_root) {
                true => Decision::Deny(Rationale::default()),
                false => Decision::Allow(Rationale::default()),
            }
        });
        let input = json!({ "command": format!("curl x {PIPE_TO_SHELL}") });
        assert!(enforce_input(&mgr, Some(decider), None, Some(&input)).is_err());
    }

    /// An escalation is someone asking for the human, which no decider may
    /// answer on their behalf.
    #[test]
    fn an_escalated_call_is_never_handed_to_the_decider() {
        let mgr = default_mgr();
        let (decider, calls) = TestDecider::installed(|_| Decision::Allow(Rationale::default()));
        assert!(
            enforce_with(&mgr, Some(decider), Some(ASK_REASON)).is_err(),
            "with no channel to ask on, the call cannot be approved"
        );
        assert_eq!(calls.load(Ordering::Relaxed), 0);
    }

    /// A rule that already settled the call never reaches the decider: the slot
    /// stands in for the prompt, and there was no prompt.
    #[test]
    fn a_decider_is_not_asked_about_a_call_the_rules_allowed() {
        let mgr = mgr_with(
            make_config(vec![allow_rule(CARGO_SCOPE)]),
            PathBuf::from("/tmp"),
        );
        let (decider, calls) = TestDecider::installed(|_| Decision::Deny(Rationale::default()));
        assert!(enforce_with(&mgr, Some(decider), None).is_ok());
        assert_eq!(calls.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn add_session_rule_is_idempotent() {
        let mgr = default_mgr();
        let rule = allow_rule("cargo *");
        mgr.add_session_rule(rule.clone());
        mgr.add_session_rule(rule.clone());
        mgr.add_session_rule(rule);
        assert_eq!(mgr.session_rules_snapshot().len(), 1);
    }

    #[test_case(PermissionAnswer::AllowOnce ; "allow_once")]
    #[test_case(PermissionAnswer::Deny ; "deny_once")]
    fn once_decisions_add_no_session_rules(answer: PermissionAnswer) {
        let mgr = default_mgr();
        mgr.apply_decision(&ToolKey::native("bash"), &["cargo test".into()], &answer);
        assert!(mgr.session_rules_snapshot().is_empty());
    }

    #[test]
    fn default_deny_blocks_unmatched() {
        let mgr = mgr_with(
            PermissionsConfig {
                default: DefaultEffect::Deny,
                ..Default::default()
            },
            PathBuf::from("/tmp"),
        );
        assert!(matches!(
            mgr.check(&ToolKey::native("bash"), "cargo test", None),
            PermissionCheck::Denied
        ));
    }

    #[test]
    fn default_deny_with_allow_rules() {
        let mgr = mgr_with(
            PermissionsConfig {
                default: DefaultEffect::Deny,
                rules: vec![allow_rule("cargo *")],
                ..Default::default()
            },
            PathBuf::from("/tmp"),
        );
        assert!(matches!(
            mgr.check(&ToolKey::native("bash"), "cargo test", None),
            PermissionCheck::Allowed(_)
        ));
        assert!(matches!(
            mgr.check(&ToolKey::native("bash"), "rm -rf /", None),
            PermissionCheck::Denied
        ));
    }

    #[test]
    fn default_allow_allows_unmatched() {
        let mgr = mgr_with(
            PermissionsConfig {
                default: DefaultEffect::Allow,
                ..Default::default()
            },
            PathBuf::from("/tmp"),
        );
        assert!(matches!(
            mgr.check(&ToolKey::native("bash"), "cargo test", None),
            PermissionCheck::Allowed(_)
        ));
    }

    #[test]
    fn default_prompt_is_default_behavior() {
        let mgr = mgr_with(PermissionsConfig::default(), PathBuf::from("/tmp"));
        assert!(matches!(
            mgr.check(&ToolKey::native("bash"), "cargo test", None),
            PermissionCheck::NeedsPrompt { .. }
        ));
    }

    #[test]
    fn mcp_server_wildcard_matches_all_server_tools() {
        let mgr = mgr_with(
            make_config(vec![PermissionRule {
                tool: ToolKey::McpServer {
                    server: "deepwiki".into(),
                },
                scope: None,
                effect: Effect::Allow,
            }]),
            PathBuf::from("/tmp"),
        );
        assert!(matches!(
            mgr.check(
                &ToolKey::McpTool {
                    server: "deepwiki".into(),
                    tool: "search".into()
                },
                "{}",
                None
            ),
            PermissionCheck::Allowed(_)
        ));
        assert!(matches!(
            mgr.check(
                &ToolKey::McpTool {
                    server: "deepwiki".into(),
                    tool: "web_search".into()
                },
                "{}",
                None
            ),
            PermissionCheck::Allowed(_)
        ));
    }

    #[test]
    fn mcp_server_wildcard_does_not_match_other_server() {
        let mgr = mgr_with(
            make_config(vec![PermissionRule {
                tool: ToolKey::McpServer {
                    server: "deepwiki".into(),
                },
                scope: None,
                effect: Effect::Allow,
            }]),
            PathBuf::from("/tmp"),
        );
        assert!(!matches!(
            mgr.check(
                &ToolKey::McpTool {
                    server: "github".into(),
                    tool: "search".into()
                },
                "{}",
                None
            ),
            PermissionCheck::Allowed(_)
        ));
    }

    #[test]
    fn per_tool_default_overrides_global() {
        let mgr = mgr_with(
            PermissionsConfig {
                default: DefaultEffect::Deny,
                tool_defaults: HashMap::from([(ToolKey::native("bash"), DefaultEffect::Allow)]),
                rules: vec![],
                ..Default::default()
            },
            PathBuf::from("/tmp"),
        );
        assert!(matches!(
            mgr.check(&ToolKey::native("bash"), "cargo test", None),
            PermissionCheck::Allowed(_)
        ));
        assert!(matches!(
            mgr.check(&ToolKey::native("write"), "/etc/passwd", None),
            PermissionCheck::Denied
        ));
    }

    #[test_case("write", true ; "write_tool_allowed")]
    #[test_case("edit", true ; "edit_tool_allowed")]
    #[test_case("bash", false ; "non_write_tool_prompts")]
    fn plan_path_auto_allows_file_write_tools_only(tool: &str, expect_allowed: bool) {
        let plan_path = Path::new(PLAN_FILE);
        let mgr = default_mgr();
        assert_eq!(
            matches!(
                mgr.check(&ToolKey::native(tool), PLAN_FILE, Some(plan_path)),
                PermissionCheck::Allowed(_)
            ),
            expect_allowed,
        );
    }

    /// Plan mode is read-only and an MCP server can write without saying so,
    /// so approving one for the user would break that. Native tools are known,
    /// and the ones plan mode does not block stay automatic.
    #[test_case(MCP_TOOL,  MCP_ARGS,  DefaultEffect::Prompt, true  => PROMPTS ; "yolo_plan_mode_prompts_for_mcp")]
    #[test_case(MCP_TOOL,  MCP_ARGS,  DefaultEffect::Allow,  true  => PROMPTS ; "default_allow_plan_mode_prompts_for_mcp")]
    #[test_case(MCP_TOOL,  MCP_ARGS,  DefaultEffect::Prompt, false => ALLOWED ; "yolo_build_mode_allows_mcp")]
    #[test_case(READ_TOOL, READ_SCOPE, DefaultEffect::Prompt, true => ALLOWED ; "yolo_plan_mode_allows_native_read")]
    fn plan_mode_outranks_blanket_approval_for_mcp_tools(
        tool: &str,
        scope: &str,
        default: DefaultEffect,
        plan_mode: bool,
    ) -> &'static str {
        let mgr = mgr_with(
            PermissionsConfig {
                initial_mode: Some(BUILTIN_MODE_YOLO.to_owned()),
                default,
                ..Default::default()
            },
            PathBuf::from("/tmp"),
        );
        let plan_path = Path::new(PLAN_FILE);
        outcome(mgr.check(
            &ToolKey::parse(tool).expect("test tool key parses"),
            scope,
            plan_mode.then_some(plan_path),
        ))
    }

    /// A rule is the user's own decision about this exact tool, so plan mode
    /// leaves it alone. Only automatic approval is held back.
    #[test]
    fn plan_mode_keeps_an_explicit_allow_rule_for_an_mcp_tool() {
        let mgr = mgr_with(
            make_config(vec![PermissionRule {
                tool: ToolKey::parse(MCP_TOOL).expect("test tool key parses"),
                scope: Some("*".into()),
                effect: Effect::Allow,
            }]),
            PathBuf::from("/tmp"),
        );
        assert_eq!(
            outcome(mgr.check(
                &ToolKey::parse(MCP_TOOL).expect("test tool key parses"),
                MCP_ARGS,
                Some(Path::new(PLAN_FILE)),
            )),
            ALLOWED
        );
    }

    /// The gate itself, apart from any one source of approval. A tool plan mode
    /// cannot read is the only case where how squarely a yes was aimed changes
    /// the answer.
    #[test_case(&mcp_tool_key(), true,  Approval::Standing    => false ; "opaque_tool_refuses_a_standing_yes")]
    #[test_case(&mcp_tool_key(), true,  Approval::ForThisTool => true  ; "opaque_tool_takes_an_answer_about_itself")]
    #[test_case(&mcp_tool_key(), false, Approval::Standing    => true  ; "no_plan_mode_takes_anything")]
    #[test_case(&native_key(),   true,  Approval::Standing    => true  ; "native_tool_is_never_opaque")]
    fn the_gate_only_ranks_approvals_for_a_tool_plan_mode_cannot_read(
        tool: &ToolKey,
        plan_mode: bool,
        approval: Approval,
    ) -> bool {
        ApprovalGate::new(tool, plan_mode.then_some(Path::new(PLAN_FILE))).accepts(approval)
    }

    /// A rule that was not written for this exact tool is a standing approval
    /// the user never gave it, so plan mode holds it back. That is what holds
    /// back the yolo mode too, whose one rule names no tool. Denies are not
    /// approvals and keep winning.
    #[test_case(ToolKey::Wildcard,  Effect::Allow, true  => PROMPTS ; "wildcard_allow_prompts_in_plan_mode")]
    #[test_case(mcp_server_key(),   Effect::Allow, true  => PROMPTS ; "server_allow_prompts_in_plan_mode")]
    #[test_case(mcp_tool_key(),     Effect::Allow, true  => ALLOWED ; "exact_tool_allow_decides_in_plan_mode")]
    #[test_case(ToolKey::Wildcard,  Effect::Deny,  true  => DENIED  ; "wildcard_deny_denies_in_plan_mode")]
    #[test_case(ToolKey::Wildcard,  Effect::Allow, false => ALLOWED ; "wildcard_allow_outside_plan_mode")]
    #[test_case(mcp_server_key(),   Effect::Allow, false => ALLOWED ; "server_allow_outside_plan_mode")]
    #[test_case(ToolKey::Wildcard,  Effect::Deny,  false => DENIED  ; "wildcard_deny_outside_plan_mode")]
    fn plan_mode_holds_back_rules_not_written_for_the_mcp_tool(
        rule_key: ToolKey,
        effect: Effect,
        plan_mode: bool,
    ) -> &'static str {
        let mgr = mgr_with(
            make_config(vec![PermissionRule {
                tool: rule_key,
                scope: None,
                effect,
            }]),
            PathBuf::from(TEST_CWD),
        );
        outcome(mgr.check(
            &mcp_tool_key(),
            MCP_ARGS,
            plan_mode.then_some(Path::new(PLAN_FILE)),
        ))
    }

    #[test]
    fn plugin_rules_apply_to_manager_and_forks() {
        let store = Arc::new(PluginRuleStore::default());
        let mgr = PermissionManager::new(
            PermissionsConfig::default(),
            PathBuf::from("/tmp"),
            ProjectConfig::for_project(Path::new("/tmp")),
            Arc::clone(&store),
        );
        let fork = mgr.fork();
        store.replace("memory", vec![plugin_edit_rule("/x/**", Effect::Allow)]);
        for m in [&mgr, &fork] {
            assert!(matches!(
                m.check(&ToolKey::native("edit"), "/x/f", None),
                PermissionCheck::Allowed(_)
            ));
        }
    }

    #[test]
    fn config_deny_beats_plugin_allow() {
        let store = Arc::new(PluginRuleStore::default());
        store.replace("memory", vec![plugin_edit_rule("/x/**", Effect::Allow)]);
        let mgr = PermissionManager::new(
            make_config(vec![plugin_edit_rule("/x/**", Effect::Deny)]),
            PathBuf::from("/tmp"),
            ProjectConfig::for_project(Path::new("/tmp")),
            store,
        );
        assert!(matches!(
            mgr.check(&ToolKey::native("edit"), "/x/f", None),
            PermissionCheck::Denied
        ));
    }

    #[test]
    fn plan_path_multi_scope_all_must_match() {
        let plan_path = Path::new(PLAN_FILE);
        let mgr = default_mgr();

        // All scopes match plan → allowed
        assert!(matches!(
            mgr.check_multi(
                &ToolKey::native("write"),
                &[PLAN_FILE, PLAN_FILE],
                false,
                Some(plan_path),
            ),
            PermissionCheck::Allowed(_)
        ));

        // One scope is non-plan → needs prompt
        assert!(matches!(
            mgr.check_multi(
                &ToolKey::native("write"),
                &[PLAN_FILE, "/etc/passwd"],
                false,
                Some(plan_path),
            ),
            PermissionCheck::NeedsPrompt { .. }
        ));
    }

    /// `away/..` spells the plan file, but `away` is a symlink, so the write
    /// lands beside its target instead. A symlinked spelling of the plan file
    /// itself still is the plan file.
    #[test]
    #[cfg(unix)]
    fn plan_auto_allow_follows_symlinks_like_the_write() {
        let dir = tempfile::tempdir().unwrap();
        let cwd = tempfile::tempdir().unwrap();
        let plans = dir.path().join("plans");
        let elsewhere = dir.path().join("elsewhere/deep");
        std::fs::create_dir_all(&plans).unwrap();
        std::fs::create_dir_all(&elsewhere).unwrap();
        std::os::unix::fs::symlink(&elsewhere, plans.join("away")).unwrap();
        std::os::unix::fs::symlink(&plans, dir.path().join("alias")).unwrap();
        let plan = plans.join("plan.md");
        let mgr = mgr_with(PermissionsConfig::default(), cwd.path().to_path_buf());
        let write = ToolKey::native("write");

        for (scope, expected) in [
            (plans.join("away/../plan.md"), PROMPTS),
            (dir.path().join("alias/plan.md"), ALLOWED),
        ] {
            let scope = scope.to_string_lossy();
            assert_eq!(
                outcome(mgr.check(&write, &scope, Some(&plan))),
                expected,
                "{scope}"
            );
        }
    }
}
