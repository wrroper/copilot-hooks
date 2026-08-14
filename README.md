# copilot-hooks

A collection of [GitHub Copilot CLI](https://docs.github.com/en/copilot/using-github-copilot/using-github-copilot-in-the-command-line) hooks.

## Hooks included

| File | Hook event | Purpose |
|------|-----------|---------|
| `tool-approver.json` | `permissionRequest` | Auto-approve / deny / ask for tool calls based on configurable regex patterns |
| `worktree-trust.json` | `sessionStart` | Automatically add git worktree directories to Copilot's trusted folders list |

---

## tool-approver

The main hook. Before Copilot's permission dialog fires, this script evaluates the pending tool call against three regex lists:

- **`allowRegex`** — auto-approve matching calls silently
- **`denyRegex`** — hard-block matching calls with an explanation
- **`alwaysAskRegex`** — force manual approval even if `allowRegex` would match

If nothing matches, the hook falls through and Copilot's normal prompt handles it.

### Canonical form

Patterns match against a **canonical string** derived from the `permissionRequest` payload:

| Tool type | Canonical form | Example |
|-----------|---------------|---------|
| File write/edit/create | `write` | `write` |
| Shell command | `shell(<command>)` | `shell(dotnet build)` |
| MCP tool | `<serverName>(<toolName>)` | `ado(wit_work_item)` |
| URL fetch | `url(<url>)` | `url(https://example.com/)` |

### Files

```
tool-approver/
  tool-approver.py                   # Hook script (invoked by tool-approver.json)
  tool-approver-config.jsonc         # Shared allow/deny/ask patterns — edit this
  tool-approver-config.local.jsonc   # Personal machine overrides — not committed
  tool-approver-approved.jsonl       # Log: auto-approved calls     (gitignored)
  tool-approver-denied.jsonl         # Log: denied calls            (gitignored)
  tool-approver-ask.jsonl            # Log: always-ask calls        (gitignored)
  tool-approver-suggestions.jsonl    # Log: fall-throughs to review (gitignored)
  tool-approver.log                  # Diagnostic log               (gitignored)
```

### Installation

1. Copy the contents of this repo into `~/.copilot/hooks/`
2. Ensure `python` (3.10+) is on your `PATH`
3. Edit `tool-approver-config.jsonc` to match your workflow
4. Optionally add personal overrides to `tool-approver-config.local.jsonc`

> **Tip:** After your first session, review `tool-approver-suggestions.jsonl`. Every unmatched tool call lands there with its full canonical string — use it to tune your patterns.

### Fail-safe behavior

The hook is **fail-open**: any unhandled exception outputs `{}` and exits 0, so Copilot's normal prompt takes over. A non-zero exit would deny the tool call entirely.

---

## worktree-trust

On `sessionStart`, if the current working directory matches a configured path pattern (e.g. your git worktrees root), the hook automatically adds it to Copilot's `trustedFolders` list in `~/.copilot/config.json`.

**Edit the regex** in `worktree-trust.json` to match your own worktree root before using it.

---

## Contributing

Pattern suggestions and improvements welcome — open a PR or issue.
