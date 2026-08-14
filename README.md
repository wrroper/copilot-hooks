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

#### 1. Locate your Copilot CLI hooks directory

Copilot CLI loads hooks from the `hooks/` folder inside your Copilot config directory. The location depends on your OS:

| OS | Hooks directory |
|----|----------------|
| **Windows** | `%USERPROFILE%\.copilot\hooks\` |
| **macOS / Linux** | `~/.copilot/hooks/` |

The directory won't exist yet if you've never installed a hook — create it manually.

#### 2. Clone or copy the files

```bash
# Option A — clone directly into your hooks directory (recommended)
git clone https://github.com/wrroper/copilot-hooks ~/.copilot/hooks

# Option B — copy files manually
# Download/clone the repo somewhere, then copy the contents into ~/.copilot/hooks/
```

On **Windows** (PowerShell):
```powershell
git clone https://github.com/wrroper/copilot-hooks "$env:USERPROFILE\.copilot\hooks"
```

After cloning, your hooks directory should look like this:
```
~/.copilot/hooks/
  tool-approver.json
  worktree-trust.json
  tool-approver/
    tool-approver.py
    tool-approver-config.jsonc
    tool-approver-config.local.jsonc
```

#### 3. Prerequisites

- **Python 3.10+** must be on your `PATH` (verify with `python --version`)
- No third-party Python packages are required — only the standard library

#### 4. Configure

- Edit `tool-approver/tool-approver-config.jsonc` to add, remove, or adjust allow/deny/ask patterns for the tools you use
- Add machine-specific overrides to `tool-approver/tool-approver-config.local.jsonc` (this file is gitignored so it won't be committed if you fork the repo)
- If using `worktree-trust.json`, update the path regex to match your worktree root

#### 5. Verify

Start a new Copilot CLI session and trigger any tool call. If the hook is working you'll either see it auto-approved silently, denied with a message, or Copilot's normal prompt will appear (fall-through). Check `tool-approver/tool-approver.log` for diagnostic output.

> **Tip:** After your first session, review `tool-approver-suggestions.jsonl`. Every unmatched tool call lands there with its full canonical string — use it to tune your patterns.

### Fail-safe behavior

The hook is **fail-open**: any unhandled exception outputs `{}` and exits 0, so Copilot's normal prompt takes over. A non-zero exit would deny the tool call entirely.

---

## Curating patterns from the suggestions log

Every tool call that doesn't match any pattern is logged to `tool-approver-suggestions.jsonl` as a fall-through. Periodically reviewing this file and promoting entries into `tool-approver-config.jsonc` tightens your coverage over time.

### 1. Review the suggestions log

Open `tool-approver/tool-approver-suggestions.jsonl`. Each line is a JSON object:

```json
{
  "canonical": "shell(npm run build)",
  "decision": "fall_through",
  "reason": "No pattern matched part: \"shell(npm run build)\"",
  "suggested_allowRegex": "^shell\\(npm run build\\)$",
  "raw_input": { ... }
}
```

The key fields are:

| Field | What to use it for |
|-------|--------------------|
| `canonical` | The exact string your pattern needs to match |
| `suggested_allowRegex` | A ready-made strict regex — good starting point, loosen as needed |
| `raw_input` | Full payload from Copilot — useful if the canonical looks wrong |

### 2. Decide: allow, deny, or always-ask?

For each entry, ask:

- **Allow** — Is this a routine, safe operation you'd approve every time without thinking? (e.g. `dotnet build`, read-only MCP tools)
- **Deny** — Should this never be allowed regardless of context? (e.g. inline SQL execution, pipe-to-interpreter)
- **Always-ask** — Is it legitimate but risky enough to warrant a human glance every time? (e.g. `git push`, `Remove-Item -Force`)
- **Leave it** — One-off or context-dependent; not worth a permanent pattern.

### 3. Add the pattern to the right config file

Edit **`tool-approver-config.jsonc`** for patterns that apply across all machines, or **`tool-approver-config.local.jsonc`** for patterns that only make sense on this machine.

Use the `suggested_allowRegex` as a starting point, but consider loosening it:

```jsonc
// Too strict — only matches this exact command
{ "pattern": "^shell\\(dotnet build --project src/MyApp\\.csproj\\)$", "reason": "..." }

// Better — matches any dotnet build invocation
{ "pattern": "^shell\\(dotnet\\s+build\\b", "reason": "dotnet build — standard dev workflow." }
```

Add the entry to the appropriate list (`allowRegex`, `denyRegex`, or `alwaysAskRegex`) with a `reason` that explains why it's safe or unsafe. The reason is shown in the log and in Copilot's denial message, so write it as if explaining to a future reviewer.

### 4. Test your new pattern

Run the hook manually against a sample payload to confirm your regex matches as expected:

```powershell
# Pipe a minimal permissionRequest payload to the script
'{"toolName":"powershell","toolInput":{"command":"dotnet build"}}' | python tool-approver/tool-approver.py
# Expected output: {"behavior":"allow"}
```

### 5. Trim the suggestions log

Once you've processed a batch of entries, clear the file so the next review starts fresh:

```powershell
Clear-Content tool-approver/tool-approver-suggestions.jsonl
```

> **Tip:** Do a curation pass after any new project or tooling setup — the first few sessions in a new context generate the most unmatched patterns.

---

## worktree-trust

On `sessionStart`, if the current working directory matches a configured path pattern (e.g. your git worktrees root), the hook automatically adds it to Copilot's `trustedFolders` list in `~/.copilot/config.json`.

**Edit the regex** in `worktree-trust.json` to match your own worktree root before using it.

---

## Contributing

Pattern suggestions and improvements welcome — open a PR or issue.

---

## Further reading

- [GitHub Copilot hooks reference](https://docs.github.com/en/copilot/reference/hooks-reference) — full event reference, payload schemas, config format, and precedence rules
- [Using hooks with GitHub Copilot CLI](https://docs.github.com/en/copilot/how-tos/copilot-cli/customize-copilot/use-hooks) — official how-to guide with examples
- [Copilot SDK — hooks deep-dive](https://github.com/github/copilot-sdk/blob/main/docs/features/hooks.md) — lower-level detail on hook execution and the permissionRequest behavior
