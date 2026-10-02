+++
title = "Permissions"
weight = 6
[extra]
group = "Reference"
+++

# Permissions

Maki uses a permission system to decide what each tool is allowed to do and when to ask you first.

Whether a project's `.maki` configuration loads at all is a separate question,
answered once per folder. See [folder trust](/docs/folder-trust/).

## Rule Layers

Rules come from five layers, combined for resolution:

1. **Session rules**, set during the current session (in-memory only)
2. **Config rules**, loaded from TOML permission files
3. **Builtin rules**, the hardcoded defaults
4. **Plugin rules**, declared by plugins via [`maki.api.register_permission_rule`](/docs/lua-api/#maki-api-register_permission_rule)
5. **Mode rules**, from the [permission mode](#permission-modes) you switched on, YOLO included

Any matching deny blocks the tool. No exceptions, so a config deny always beats a plugin allow.

A [`tool.<name>.input` hook](/docs/hooks/) runs before any of this. Rules are
resolved against the call as the hook left it, so what the prompt shows you is
what runs.

## Check Flow

For every tool call, each scope resolves like this:

```
tool call
    │
deny rule matches?  ── yes ──►  blocked. no exceptions
    │ no
allow rule matches? ── yes ──►  runs
    │ no
mode allows it?     ── yes ──►  runs, and spends from the mode budget
    │ no
plan file write?    ── yes ──►  runs
    │ no
default says allow? ── yes ──►  runs
    │ no
decide slot answers? ─ yes ──►  runs, or is blocked, as the layer said
    │ no
    ▼
Maki asks you
```

Deny rules are checked across all layers before anything else, so a deny cannot be bypassed by a permission mode (YOLO included), a decide layer, or the plan-file auto-allow. In plan mode, writes to any path other than the plan file are rejected before this flow; this applies to the file-write tools only. All other tools, including MCP tools, follow the check flow below as usual. `default` resolves per-tool first, then global; the built-in default is `"prompt"`.

## Builtin Defaults

File-write tools are pre-allowed inside the project working directory (cwd at session start, canonicalized). Paths outside that tree still need a prompt or an explicit allow rule:

| Tool | Scope | Notes |
|------|-------|-------|
| `write` | `<cwd>/**` | Outside cwd requires permission |
| `edit` | `<cwd>/**` | Outside cwd requires permission |
| `multiedit` | `<cwd>/**` | Outside cwd requires permission |
| `edit_lines` | `<cwd>/**` | Outside cwd requires permission |
| `insert_lines` | `<cwd>/**` | Same, when the opt-in tool is enabled |
| `task` | `*` | Subagent spawning always allowed |

The memory plugin uses a plugin rule to pre-allow the file-write tools inside its notes directory (under maki's state dir), so the agent can edit memory notes directly without a prompt.

These tools have no builtin allow rule, so they prompt (or follow your `default`) every time unless you add rules:

- `bash` - Shell commands (scopes come from tree-sitter parsing)
- `websearch` - Web search queries
- `webfetch` - URL fetching

Tools that never declare permission scopes (for example `read`, `glob`, `grep`, `index`, `memory`, `skill`, `todo_write`) **skip** the permission manager entirely. They always run. If you need to block one of them, turn the plugin off in `init.lua` (`plugins.read = { enabled = false }`) rather than using `permissions.toml`.

Container tools like `batch` and `code_execution` prompt for each inner tool individually.

## TOML Configuration

There are two permission files:

- **Global**: `~/.config/maki/permissions.toml`
- **Project**: `.maki/permissions.toml` in the active Git checkout, or in the
  working directory outside Git (takes precedence over global)

The project file's `deny` scopes always apply. The rest of it waits on
[folder trust](/docs/folder-trust/).

```toml
default = "deny"

[bash]
allow = [
    "cargo *",
    "git *",
]
deny = [
    "rm -rf *",
    "sudo *",
]

[read]
default = "allow"

[mcp.deepwiki]
allow = ["search", "fetch"]

[mcp.github]
deny = ["admin_delete"]
```

Each tool gets its own section with `allow` and `deny` arrays. Values are glob-like scope patterns.

> **Note:** In MCP server sections (`[mcp.*]`), the boolean forms `allow = true` and `deny = true` are deprecated and ignored. Use `default = "allow"` or `default = "deny"` instead. For native tool sections (e.g. `[bash]`), `allow = true` still works.

### The `default` key

Controls what happens when no allow or deny rule matches. Can be `"prompt"` (built-in default), `"deny"`, or `"allow"`. Set it globally or per-tool:

```toml
default = "deny"

[bash]
default = "prompt"
allow = ["cargo *"]
```

Here everything is denied by default, except `bash` which still prompts, and `cargo *` commands which are allowed.

Project files **cannot** set `default = "allow"` (top-level, per-tool, or MCP).
That value is ignored so a repository cannot grant itself full access. Project
**allow lists** work once the folder is [trusted](/docs/folder-trust/). Put
`default = "allow"` only in the global file.

## Scope Patterns

| Pattern | Matches |
|---------|--------|
| `*` or `**` | Any value (full wildcard) |
| `prefix*` | Values starting with prefix |
| `cmd *` | Bare `cmd` or `cmd` plus args (`pwd *` matches `pwd` and `pwd -L`, not `pwdx`) |
| `dir/**` | `dir` itself or anything under it (path-aware on Windows and Unix) |
| `exact` | Exact match only |

## MCP Tool Permissions

MCP tools use natural TOML nesting. Server names are table keys under `[mcp]`, tool names are array values:

```toml
# Global permissions.toml (default = "allow" is ignored in project files)
[mcp.deepwiki]
allow = ["search", "fetch"]

[mcp.github]
deny = ["admin_delete"]

[mcp.lean-lsp]
default = "allow"               # allow all tools on this server (global only)
```

Tool names must match `^[a-zA-Z0-9_-]{1,64}$` (no dots, max 64 chars). Server names cannot contain dots.

## Permission Prompts

When a gated tool needs permission, Maki asks you.

| Key | Action |
|-----|--------|
| `y` | Allow once (immediate) |
| `s` | Allow for this session (confirm with `Enter` or `y`; any other key cancels) |
| `a` | Always allow for this project (confirm; saved to `.maki/permissions.toml`) |
| `A` | Always allow globally (confirm; saved to `~/.config/maki/permissions.toml`) |
| `n` | Open deny guidance editor (type optional guidance, then `Enter` to deny once; `Esc` cancels) |
| `d` | Deny always for this project (confirm; saved to `.maki/permissions.toml`) |
| `D` | Deny always globally (confirm) |

Session and always-allow / always-deny choices need a second key (`Enter` or `y`) so a fat-finger does not rewrite your rules. Deny-once with `n` lets you type a short reason the agent will see.

The keys are the same in a folder you have not
[trusted](/docs/folder-trust/), where `a` and `d` last for the session instead
of reaching `.maki/permissions.toml`.

ACP clients offer the four options the protocol defines. "Allow always" lasts
for the session, and "Reject always" is a project answer that follows folder
trust like the TUI, reading "Reject for this session" in an untrusted folder.

### Scope Generalization

When you pick "always allow" (or always deny for MCP), the saved scope is generalized so it stays useful beyond that one call:

- **bash**: `cargo test --all` becomes `cargo *`
- **write / edit / multiedit / edit_lines / insert_lines**: `/path/to/file.rs` becomes `/path/to/**`
- **MCP tools**: always `*` (per-tool, so allowing `deepwiki.search` will not cover `deepwiki.fetch`)
- **webfetch / websearch** (and anything else gated): the exact URL or query string is stored as-is

For MCP tools, both allow and deny decisions generalize to `*` (the entire tool). MCP inputs are opaque JSON with no meaningful scope pattern. Denying a single MCP invocation denies that tool until you revoke the rule.

## Permission Modes

A permission mode is a named bundle of rules you switch on for a while. It is
how you get auto-accept behaviour without writing a standing rule into your
config: the mode applies while it is on, and the rules in your file are what you
fall back to.

Write one as a `[modes.<name>]` section. The body takes everything the file
itself takes, so a mode is read the same way the rest of your `permissions.toml`
is:

```toml
# ~/.config/maki/permissions.toml
[modes.auto]
description = "Build and test without asking"
max_auto_calls = 25
revert_on_deny = true

[modes.auto.bash]
allow = ["cargo *", "git diff", "git status", "rg *"]
deny = ["cargo publish *"]

[modes.auto.edit]
default = "allow"

[modes.review]
description = "Read the tree, change nothing"
default = "deny"

[modes.review.read]
default = "allow"
```

### Switching modes

| Gesture | Effect |
|---------|--------|
| `/permission` | List the modes, marking the active one with `*` |
| `/permission auto` | Switch to `auto` |
| `/permission off` | Switch back to asking |
| `Shift+Tab` | Cycle through the modes and back to off |
| `--permission-mode auto` | Start in `auto` |
| `--yolo` | Start in the built-in `yolo` mode |

The status bar shows the active mode, with its spend when the mode set a
ceiling: `[auto 7/25]`. A mode you switched to is stored with the session, so a
resume comes back in it, and switching off is stored too. `--permission-mode`
only sets the starting value for sessions you never switched by hand, the same
way `--yolo` does.

`off` is how a mode is switched off, so a `[modes.off]` section is ignored.

To start every session in a mode:

```lua
-- ~/.config/maki/init.lua
maki.setup({
    always_permission_mode = "auto",
})
```

### Budget

A mode is a standing grant, so it is worth bounding. Three optional keys do
that:

| Key | Default | Meaning |
|-----|---------|---------|
| `max_auto_calls` | unbounded | Calls this mode may wave through in one turn |
| `revert_on_deny` | `false` | Switch the mode off when you deny a call |
| `expires` | `"session"` | `"turn"` drops the mode when the turn ends |
| `cycle` | `true` | `false` keeps the mode out of `Shift+Tab`, so it has to be named |

Only the calls the mode decided count against `max_auto_calls`. A call an allow
rule already covered costs nothing, and the counter resets at the start of each
turn. A spent budget silences the mode's allows and leaves its denies in place,
so running out of rope never loosens anything.

### How a mode resolves

A mode joins the rule layers rather than replacing them:

- Any matching deny wins, including a deny the mode added.
- An allow from your config, session, builtins or a plugin is checked first, and
  costs the mode nothing.
- Specific beats general, whoever wrote it. A mode's own `[modes.auto.bash]
  default` outranks a `[bash] default` in the file, and a `[bash] default` in
  the file outranks a mode's blanket `default`. So switching on a mode that
  allows by default cannot quietly undo a `[bash] default = "deny"`.

A project file may define modes, under the same limit as the rest of it: allow
lists work once the folder is [trusted](/docs/folder-trust/), and
`default = "allow"` is ignored, top-level or per-tool. A repository can narrow
what runs inside it and never widen it.

### Built-in modes

Maki ships two, and they resolve in a config that never mentions modes:

| Mode | Does |
|------|------|
| `accept_edits` | Lets the file-write tools write anywhere without asking |
| `yolo` | Allows everything a deny rule does not catch. See [YOLO mode](#yolo-mode) |

Defining `[modes.accept_edits]` or `[modes.yolo]` yourself replaces the built-in
outright, inheriting none of its fields.

In [SDK mode](/docs/headless/), `--permission-mode` and the `set_permission_mode`
control request also take the four names that protocol defines. `acceptEdits` and
`bypassPermissions` switch on the two modes above, `default` is no mode, and
`plan` is [plan mode](/docs/quick-start/), which the TUI reaches with `Tab`.
Those names work only there, since they are what SDK clients send on the wire.

### Deciding in Lua

When rules leave a call for you to answer, a plugin can answer in your place
through the `permission.decide` slot. Use it for policy no rule can express, such
as reading an allowlist from a file or counting what the agent has already done.
See [hooks](/docs/hooks/#permission-decide).

## YOLO Mode

YOLO is a built-in permission mode whose one rule allows everything. Toggle it
with `/yolo`, or start in it with `--yolo` or `--permission-mode
bypassPermissions`. Explicit deny rules still apply. Tools that never declare
permission scopes are unaffected, since they never prompted.

Being a mode, it behaves like the ones you write: the status bar shows `[yolo]`,
the answer is stored with the session so a resume comes back the same way, and
`--yolo` only sets the starting value for sessions you never switched by hand.
`/permission yolo` and `/permission off` do the same job as `/yolo`.

It carries a rule rather than `default = "allow"`, which is what keeps it as
strong as it has always been: a rule outranks every `default` in your file, so a
`[bash] default = "deny"` does not hold it back. A mode you write with
`default = "allow"` loses to that same per-tool default. `Shift+Tab` skips yolo
for the same reason, so handing over everything stays something you ask for by
name.

To start in YOLO mode every time:

```lua
-- ~/.config/maki/init.lua
maki.setup({
    always_yolo = true,
})
```

## Bash Command Parsing

Bash commands get parsed with tree-sitter to extract individual commands. Something like `cd /tmp && cargo test` is checked as two separate commands.

Some constructs are too complex to analyze statically, so they always trigger a prompt:

- Command substitution: `$(...)`, backticks
- Process substitution: `<(...)`, `>(...)`
- Subshells: `(...)`
- Arithmetic expansion: `$((...))`

Brace groups `{ ... }` and control flow (`if`, `for`, …) are segmented when possible; they do not by themselves force a prompt the way substitutions do.

## Plugin Permissions

Lua plugins have a separate, unrelated gate. A `plugin.toml` manifest next to the Lua file controls which gated `maki.*` APIs it may call. No manifest means every gated call is denied, including for your own `init.lua`. The [Lua API reference](/docs/lua-api/#plugin-permissions) documents the manifest and lists every permission.

It runs after [folder trust](/docs/folder-trust/) has let the Lua file load, and
limits which APIs the file reaches rather than sandboxing the file.

### Plugin egress: net_hosts

`net = true` lets a plugin reach any public host. `net_hosts` in the same
table narrows that to an allowlist:

```toml
[permissions]
net = true
net_hosts = ["api.acme.com", "*.acme.dev"]
```

A pattern is an exact host or a single leading `*.` label. `*.acme.dev` matches
`api.acme.dev`, and it does not match `acme.dev` or `evilacme.dev`. An empty
list reaches no host at all, which differs from leaving the key out.

The list covers the plugin's `maki.net` calls and the `base_url` of any
[provider it registers](/docs/providers/#plugin-providers), so an auth hook
cannot send credentials to a host the manifest does not name. A plugin that
calls `maki.provider.register` must declare a non-empty list.

For an installed [package](/docs/packages/#package-permissions), Maki stores
the hosts with the approval and asks again when an update widens or drops the
list.

## Network Addresses

`webfetch`, `websearch` and every plugin that calls `maki.net` go through one guard. A request to a private, loopback or link-local address is refused, and so is a redirect that lands on one. The model picks these URLs, so a page it reads could otherwise talk it into fetching `http://169.254.169.254/` or an admin panel on your LAN.

To reach a service on your own machine or network, list it in [`net.allowed_private_hosts`](/docs/configuration/#net). An allowed host also keeps plain `http://` instead of being upgraded to `https://`, since a service on your LAN rarely has a certificate.

A provider plugin calling its own origin also skips the guard, since chat requests already go there. This covers an origin you set with `<SLUG>_BASE_URL` or `providers.toml`, and a built-in provider's default. It does not cover a `base_url` that a third-party plugin declares.

## Session Persistence

When you save a session, its permission rules are saved too. Loading the session restores them.
