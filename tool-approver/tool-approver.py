#!/usr/bin/env python3
"""
tool-approver.py — permissionRequest hook for GitHub Copilot CLI.

Fires before Copilot's permission dialog and auto-approves/denies/asks based
on configurable regex patterns. Falls through (outputs {}) for unmatched tools
so normal prompting still works.

Adapted from advanced-tool-approver.py (a Claude Code permissionRequest hook).

Key differences from the Claude version:
  - Hook event : permissionRequest (not PreToolUse)
  - Output     : {"behavior": "allow"|"deny", "message": "..."} (not permissionDecision)
  - Fail mode  : MUST output {} and exit 0 on error — permissionRequest command hooks
                 are fail-CLOSED (non-zero exit = deny the tool call entirely).
  - Canonicals : Copilot CLI permission pattern syntax — see _build_canonical() below.

Canonical form (determines which regex shape to use in config patterns):
  write                        — file write/create/edit operations
  shell(<command>)             — shell command (PowerShell on Windows)
  <serverName>(<toolName>)     — MCP tool (e.g. ado(wit_get_work_item))
  url(<url>)                   — URL fetch

NOTE: The exact toolName format in the permissionRequest payload is not fully
documented. On first run, every call is logged to the suggestions file with the
full raw input so patterns can be verified and adjusted. Review the suggestions
log after your first session in a new worktree.

Evaluation order (first match wins):
  1. Built-in deny  — hard-coded patterns for disk format, pipe-to-interpreter,
                      recursive delete on system-critical paths.
  2. Config deny    — denyRegex from merged config.
  3. Config ask     — alwaysAskRegex (forces manual approval even if allow would match).
  4. Config allow   — allowRegex.
  5. Fall-through   — output {} and log to suggestions file.

Config files (merged at runtime; local appends to shared, never replaces):
  tool-approver-config.jsonc        shared patterns (edit to add new tools)
  tool-approver-config.local.jsonc  personal machine overrides (not shared)

Logging (JSONL, one entry per hook invocation):
  tool-approver-approved.jsonl   — auto-approved calls
  tool-approver-denied.jsonl     — denied calls
  tool-approver-ask.jsonl        — always-ask calls
  tool-approver-suggestions.jsonl — fall-throughs (patterns to consider adding)
  tool-approver.log              — diagnostic log (INFO/DEBUG/ERROR)
"""

import json
import os
import pathlib
import re
import shlex
import sys
import uuid
from datetime import datetime

# ---------------------------------------------------------------------------
# Module-level paths (override via environment variables for testing)
# ---------------------------------------------------------------------------

SCRIPT_DIR = pathlib.Path(__file__).parent

CONFIG_PATH = pathlib.Path(
    os.environ.get("TOOL_APPROVER_CONFIG_PATH", str(SCRIPT_DIR / "tool-approver-config.jsonc"))
)
CONFIG_LOCAL_PATH = pathlib.Path(
    os.environ.get("TOOL_APPROVER_CONFIG_LOCAL_PATH", str(SCRIPT_DIR / "tool-approver-config.local.jsonc"))
)
LOG_FILE = pathlib.Path(
    os.environ.get("TOOL_APPROVER_LOG_FILE", str(SCRIPT_DIR / "tool-approver.log"))
)
SUGGESTIONS_LOG = pathlib.Path(
    os.environ.get("TOOL_APPROVER_SUGGESTIONS_LOG", str(SCRIPT_DIR / "tool-approver-suggestions.jsonl"))
)
APPROVED_LOG = pathlib.Path(
    os.environ.get("TOOL_APPROVER_APPROVED_LOG", str(SCRIPT_DIR / "tool-approver-approved.jsonl"))
)
DENIED_LOG = pathlib.Path(
    os.environ.get("TOOL_APPROVER_DENIED_LOG", str(SCRIPT_DIR / "tool-approver-denied.jsonl"))
)
ASK_LOG = pathlib.Path(
    os.environ.get("TOOL_APPROVER_ASK_LOG", str(SCRIPT_DIR / "tool-approver-ask.jsonl"))
)

LOG_LEVEL = os.environ.get("TOOL_APPROVER_LOG_LEVEL", "INFO")

# ---------------------------------------------------------------------------
# Built-in tool name sets (Copilot CLI permissionRequest payload uses toolName
# as the raw CLI tool name, not the kind-based format the script was originally
# designed for)
# ---------------------------------------------------------------------------

_WRITE_TOOL_NAMES: frozenset[str] = frozenset(
    {"edit", "create", "str_replace_editor", "apply_patch"}
)
_SHELL_TOOL_NAMES: frozenset[str] = frozenset({"powershell", "bash", "shell"})

# Command stems that are always safe and can be skipped during decomposition.
# These are pure navigation, output-formatting, or pipe-sink commands with no
# write capability or network access.
_ALWAYS_SAFE_STEMS: frozenset[str] = frozenset({
    # Directory navigation
    "cd", "set-location", "sl", "push-location", "pushd", "pop-location", "popd",
    # Output sinks
    "out-null", "out-default", "out-host", "out-string",
    # Output formatters / selectors (common pipe stages)
    "select-object", "sort-object", "where-object", "measure-object",
    "format-table", "format-list", "format-wide", "format-custom", "tee-object",
    # Unix-style output filters (safe as pipe stages)
    "head", "tail", "more", "less",
    # Print / echo
    "echo", "write-host", "write-output", "write-verbose",
    "write-debug", "write-warning", "write-information",
})

# ---------------------------------------------------------------------------
# System-critical path detection (reused from advanced-tool-approver)
# ---------------------------------------------------------------------------

_SYSTEM_CRITICAL_PATH_PATTERNS: list[re.Pattern] = [
    re.compile(r"^~(?:/|\\|$)"),
    re.compile(r"^/home/[^/]+(?:/|$)", re.IGNORECASE),
    re.compile(r"^[A-Za-z]:/Users/[^/]+(?:/|$)", re.IGNORECASE),
]

_PS_REMOVE_CMDS: frozenset[str] = frozenset({"remove-item", "rm", "ri", "del", "erase", "rd"})


def _path_depth(path: str) -> int:
    normalized = path.replace("\\", "/")
    if len(normalized) >= 3 and normalized[1] == ":" and normalized[2] == "/":
        remaining = normalized[3:]
    elif normalized.startswith("/"):
        remaining = normalized[1:]
    else:
        return 999
    return len([c for c in remaining.split("/") if c])


def _is_system_critical_path(path: str) -> bool:
    normalized = path.replace("\\", "/")
    if _path_depth(path) <= 1:
        return True
    for pattern in _SYSTEM_CRITICAL_PATH_PATTERNS:
        if pattern.search(normalized):
            return True
    parts = [p for p in normalized.split("/") if p]
    if ".git" in parts:
        return True
    return False


# ---------------------------------------------------------------------------
# Built-in deny checks (adapted from advanced-tool-approver)
# ---------------------------------------------------------------------------

BUILTIN_DENY_PATTERNS: list[tuple[re.Pattern, str]] = [
    (
        re.compile(r"\|\s*bash(?![\w-])", re.IGNORECASE),
        "Security: command piped to bash. DO NOT reformulate as a piped interpreter invocation.",
    ),
    (
        re.compile(r"\|\s*sh(?![\w-])", re.IGNORECASE),
        "Security: command piped to sh. DO NOT reformulate as a piped interpreter invocation.",
    ),
    (
        re.compile(r"\bformat\s+[a-zA-Z]:", re.IGNORECASE),
        "Destructive: Windows disk format command. DO NOT retry any disk format operation.",
    ),
    (
        re.compile(r">\s*/etc/(passwd|shadow|sudoers)"),
        "Security: overwriting system authentication file. DO NOT attempt to modify /etc/passwd, /etc/shadow, or /etc/sudoers.",
    ),
]


def _check_destructive_remove_item(command: str) -> str | None:
    """Return a denial reason if command is a recursive Remove-Item on a system-critical path."""
    cmd_normalized = command.replace("\\", "/")
    try:
        tokens = shlex.split(cmd_normalized)
    except ValueError:
        tokens = cmd_normalized.split()
    if not tokens or tokens[0].lower() not in _PS_REMOVE_CMDS:
        return None

    has_recursive = False
    targets: list[str] = []
    i = 1
    while i < len(tokens):
        tok = tokens[i]
        lower = tok.lower()
        if lower in ("-recurse", "--recurse", "-r"):
            has_recursive = True
        elif lower in ("-force", "--force", "-f"):
            pass  # goes to alwaysAsk for non-system paths
        elif tok.startswith("-") and len(tok) > 1:
            flags = tok[1:].lower()
            if flags.isalpha() and "r" in flags:
                has_recursive = True
        else:
            targets.append(tok)
        i += 1

    if not has_recursive:
        return None

    for target in targets:
        if _is_system_critical_path(target):
            return (
                "Destructive: Remove-Item targeting a system-critical path. "
                "DO NOT retry this deletion using any other tool or shell command. "
                "Ask the user to perform any necessary deletion directly."
            )
        if target in (".", "./", "../") or target.startswith("./") or target.startswith("../"):
            return (
                "Destructive: Remove-Item targeting a relative path (path normalization "
                "may have failed). DO NOT retry with relative paths."
            )
    return None


# ---------------------------------------------------------------------------
# Command decomposition
# ---------------------------------------------------------------------------

def _command_stem(part: str) -> str:
    """Return the lowercase executable/cmdlet stem of a single command part."""
    part = part.strip()
    # Strip leading call operator (& or .)
    if len(part) > 2 and part[0] in ("&", ".") and part[1] in (" ", '"', "'"):
        part = part[2:].strip()
    # Quoted executable: "C:\path\to\cmd.exe" ...
    if part.startswith('"'):
        end = part.find('"', 1)
        stem = part[1:end] if end > 1 else part[1:]
    elif part.startswith("'"):
        end = part.find("'", 1)
        stem = part[1:end] if end > 1 else part[1:]
    else:
        stem = part.split()[0] if part.split() else ""
    # Keep only the filename portion and strip extension
    stem = stem.replace("\\", "/").split("/")[-1]
    if "." in stem:
        stem = stem.rsplit(".", 1)[0]
    return stem.lower()


def _split_compound_command(command: str) -> list[str]:
    """
    Split a compound shell command into individual parts, respecting quotes.

    Splits on ``&&``, ``||``, ``;``, and ``|`` (pipe).  Each part is checked
    independently — the strictest decision across all parts wins.
    """
    parts: list[str] = []
    current: list[str] = []
    i = 0
    in_single = False
    in_double = False

    while i < len(command):
        c = command[i]

        # Consume escape sequences inside quoted strings
        if c == "\\" and (in_single or in_double) and i + 1 < len(command):
            current.append(c)
            current.append(command[i + 1])
            i += 2
            continue

        if c == "'" and not in_double:
            in_single = not in_single
            current.append(c)
        elif c == '"' and not in_single:
            in_double = not in_double
            current.append(c)
        elif not in_single and not in_double:
            if i + 1 < len(command) and command[i : i + 2] in ("&&", "||"):
                parts.append("".join(current).strip())
                current = []
                i += 2
                continue
            elif c in (";", "|"):
                parts.append("".join(current).strip())
                current = []
            else:
                current.append(c)
        else:
            current.append(c)

        i += 1

    if current:
        parts.append("".join(current).strip())

    return [p for p in parts if p]


def _is_always_safe_part(part: str) -> bool:
    """Return True if a command part is always safe (navigation, output, etc.)."""
    return _command_stem(part) in _ALWAYS_SAFE_STEMS


# ---------------------------------------------------------------------------
# Canonical construction
# ---------------------------------------------------------------------------

def _build_canonical(input_data: dict) -> str:
    """
    Build the canonical string from the permissionRequest payload.

    The Copilot CLI sends permissionRequest payloads with a flat ``toolName``
    field (the CLI tool name) and a ``toolInput`` object.  This is different
    from the older ``kind``-based format the script was originally designed for,
    so this function now handles both:

    Primary (Copilot CLI native) format:
      toolName="edit"|"create"|...         → write
      toolName="powershell"|"bash"          → shell(<toolInput.command>)
      toolName="web_fetch"                  → url(<toolInput.url>)
      toolName="server/tool"  (slash)       → server(tool)
      toolName="server(tool)" (parens)      → returned as-is (already canonical)

    Legacy / kind-based format (fallback):
      kind="write"                          → write
      kind="commands", commandIdentifiers   → shell(<first identifier>)
      kind="mcp", serverName, toolName      → serverName(toolName)
      kind="url", url                       → url(<url>)
    """
    tool_name = input_data.get("toolName") or input_data.get("tool_name", "")
    tool_input = input_data.get("toolInput") or input_data.get("tool_input") or {}
    if not isinstance(tool_input, dict):
        tool_input = {}

    # Already in canonical form (e.g. "ado(wit_get_work_item)", "write", "read")
    if tool_name and ("(" in tool_name or tool_name in ("write", "read")):
        return tool_name

    # --- Copilot CLI native tool names → canonical form ---

    if tool_name in _WRITE_TOOL_NAMES:
        return "write"

    if tool_name in _SHELL_TOOL_NAMES:
        command = tool_input.get("command", "")
        if command:
            return f"shell({command})"
        return "shell()"

    if tool_name == "web_fetch":
        url = tool_input.get("url", "")
        if url:
            return f"url({url})"
        return "url()"

    # Slash-format MCP tool name: "github-mcp-server/web_search" → "github-mcp-server(web_search)"
    if "/" in tool_name and "(" not in tool_name:
        parts = tool_name.split("/", 1)
        if len(parts) == 2 and parts[0] and parts[1]:
            return f"{parts[0]}({parts[1]})"

    # --- Legacy: kind-based format (fallback for older/alternate payload shapes) ---

    kind = input_data.get("kind", "")

    if kind == "write":
        return "write"

    if kind == "mcp":
        server = input_data.get("serverName", input_data.get("server_name", ""))
        tool = input_data.get("toolName", input_data.get("tool_name", ""))
        if server and tool:
            return f"{server}({tool})"
        if server:
            return f"{server}()"
        if tool:
            return tool

    if kind == "commands":
        identifiers = input_data.get("commandIdentifiers", input_data.get("command_identifiers", []))
        if identifiers:
            return f"shell({identifiers[0]})"
        command = input_data.get("command", "")
        if command:
            return f"shell({command})"

    if kind == "url":
        url = input_data.get("url", "")
        return f"url({url})"

    # Fall back to the raw tool name or kind
    if tool_name:
        return tool_name
    if kind:
        return kind

    return "<unknown>"


def _extract_shell_command(canonical: str) -> str | None:
    """Extract the inner command string from a shell(<command>) canonical."""
    if canonical.startswith("shell(") and canonical.endswith(")"):
        return canonical[len("shell("):-1]
    return None


# ---------------------------------------------------------------------------
# Logging helpers
# ---------------------------------------------------------------------------

def _log(message: str, level: str = "INFO") -> None:
    levels = {"DEBUG": 0, "INFO": 1, "WARN": 2, "ERROR": 3}
    if levels.get(level, 1) >= levels.get(LOG_LEVEL, 1):
        try:
            with open(LOG_FILE, "a", encoding="utf-8") as f:
                f.write(f"{datetime.now().isoformat()} [{level}] {message}\n")
        except OSError:
            pass


def _write_jsonl(log_file: pathlib.Path, entry: dict) -> None:
    try:
        with open(log_file, "a", encoding="utf-8") as f:
            f.write(json.dumps(entry, separators=(",", ":")) + "\n")
    except OSError:
        pass


def _make_log_entry(
    correlation_id: str,
    input_data: dict,
    canonical: str,
    decision: str,
    reason: str,
) -> dict:
    return {
        "log_version": "1",
        "correlation_id": correlation_id,
        "ts": datetime.now().isoformat(),
        "canonical": canonical,
        "decision": decision,
        "reason": reason,
        # Include full input so we can verify canonical format on first runs
        "raw_input": input_data,
        "suggested_allowRegex": f"^{re.escape(canonical)}$" if canonical != "<unknown>" else None,
    }


# ---------------------------------------------------------------------------
# Config loading (JSONC with // and /* */ comments)
# ---------------------------------------------------------------------------

def _strip_jsonc_comments(text: str) -> str:
    """Remove // line comments and /* */ block comments, respecting string literals."""
    result = []
    i = 0
    in_string = False
    while i < len(text):
        c = text[i]
        if in_string:
            if c == "\\":
                result.append(c)
                i += 1
                if i < len(text):
                    result.append(text[i])
                    i += 1
                continue
            if c == '"':
                in_string = False
            result.append(c)
        else:
            if c == '"':
                in_string = True
                result.append(c)
            elif c == "/" and i + 1 < len(text) and text[i + 1] == "/":
                while i < len(text) and text[i] != "\n":
                    i += 1
                continue
            elif c == "/" and i + 1 < len(text) and text[i + 1] == "*":
                i += 2
                while i < len(text) - 1 and not (text[i] == "*" and text[i + 1] == "/"):
                    i += 1
                i += 2
                continue
            else:
                result.append(c)
        i += 1
    return "".join(result)


def _load_config(config_path: pathlib.Path, required: bool = False) -> dict:
    try:
        with open(config_path, "r", encoding="utf-8") as f:
            return json.loads(_strip_jsonc_comments(f.read()))
    except (OSError, json.JSONDecodeError):
        if required:
            raise
        return {}


def _merge_configs(base: dict, local: dict) -> dict:
    return {
        "allowRegex": base.get("allowRegex", []) + local.get("allowRegex", []),
        "denyRegex": base.get("denyRegex", []) + local.get("denyRegex", []),
        "alwaysAskRegex": base.get("alwaysAskRegex", []) + local.get("alwaysAskRegex", []),
    }


def _load_patterns(
    config: dict,
) -> tuple[list[tuple[re.Pattern, str]], list[tuple[re.Pattern, str]], list[tuple[re.Pattern, str]]]:
    """Parse allow/deny/alwaysAsk pattern lists from config."""
    def _compile(entry: object) -> tuple[re.Pattern, str] | None:
        if isinstance(entry, str):
            pattern_str, reason = entry, ""
        elif isinstance(entry, dict):
            pattern_str = entry.get("pattern", "")
            reason = entry.get("reason", "")
            if not pattern_str:
                return None
        else:
            return None
        try:
            return re.compile(pattern_str, re.DOTALL | re.IGNORECASE), reason
        except re.error:
            return None

    allow = [c for e in config.get("allowRegex", []) if (c := _compile(e)) is not None]
    deny = [c for e in config.get("denyRegex", []) if (c := _compile(e)) is not None]
    ask = [c for e in config.get("alwaysAskRegex", []) if (c := _compile(e)) is not None]
    return allow, deny, ask


# ---------------------------------------------------------------------------
# Evaluation pipeline
# ---------------------------------------------------------------------------

def evaluate(
    canonical: str,
    config: dict,
) -> tuple[str, str]:
    """
    Evaluate the canonical tool call and return (decision, reason).
    decision: "allow" | "deny" | "ask" | "fall_through"

    For shell commands the full command is decomposed into individual parts by
    &&, ||, ; and | (pipe).  Each non-trivial part is evaluated independently
    and the STRICTEST decision across all parts wins:
        deny > ask > fall_through > allow
    """
    allow_patterns, deny_patterns, ask_patterns = _load_patterns(config)

    shell_cmd = _extract_shell_command(canonical)

    # 1. Built-in deny on the FULL command string first (catches pipe-to-bash etc.
    #    which are only visible before splitting).
    check_targets = [canonical]
    if shell_cmd:
        check_targets.append(shell_cmd)

    for target in check_targets:
        for pattern, reason in BUILTIN_DENY_PATTERNS:
            if pattern.search(target):
                return "deny", f"Built-in deny: {reason}"

    if shell_cmd:
        rm_reason = _check_destructive_remove_item(shell_cmd)
        if rm_reason:
            return "deny", f"Built-in deny: {rm_reason}"

    # 2. Shell commands: decompose and evaluate each part independently.
    if shell_cmd:
        _DECISION_RANK = {"deny": 3, "ask": 2, "fall_through": 1, "allow": 0}
        strictest = "allow"
        strictest_reason = ""

        for part in _split_compound_command(shell_cmd):
            if _is_always_safe_part(part):
                continue

            part_canonical = f"shell({part})"

            # Built-in deny on each decomposed part (catches injected commands)
            for pattern, reason in BUILTIN_DENY_PATTERNS:
                if pattern.search(part):
                    return "deny", f"Built-in deny (part: {part!r}): {reason}"
            rm_reason = _check_destructive_remove_item(part)
            if rm_reason:
                return "deny", f"Built-in deny (part: {part!r}): {rm_reason}"

            # Config deny
            for pattern, reason in deny_patterns:
                if pattern.search(part_canonical):
                    return "deny", reason or f"Config denyRegex matched: {part_canonical!r}"

            # Config alwaysAsk
            matched_ask = False
            for pattern, reason in ask_patterns:
                if pattern.search(part_canonical):
                    if _DECISION_RANK["ask"] > _DECISION_RANK[strictest]:
                        strictest = "ask"
                        strictest_reason = reason or f"Config alwaysAskRegex matched: {part_canonical!r}"
                    matched_ask = True
                    break

            if matched_ask:
                continue

            # Config allow
            matched_allow = any(p.search(part_canonical) for p, _ in allow_patterns)

            if not matched_allow:
                if _DECISION_RANK["fall_through"] > _DECISION_RANK[strictest]:
                    strictest = "fall_through"
                    strictest_reason = f"No pattern matched part: {part_canonical!r}"

        return strictest, strictest_reason

    # 3. Non-shell canonicals (write, mcp, url): evaluate the canonical as a whole.
    for pattern, reason in deny_patterns:
        if pattern.search(canonical):
            return "deny", reason or f"Config denyRegex matched: {canonical!r}"

    for pattern, reason in ask_patterns:
        if pattern.search(canonical):
            return "ask", reason or f"Config alwaysAskRegex matched: {canonical!r}"

    for pattern, reason in allow_patterns:
        if pattern.search(canonical):
            return "allow", reason or f"Config allowRegex matched: {canonical!r}"

    return "fall_through", ""


# ---------------------------------------------------------------------------
# Hook output
# ---------------------------------------------------------------------------

def _output_allow(reason: str) -> None:
    json.dump({"behavior": "allow"}, sys.stdout)
    sys.stdout.flush()


def _output_deny(reason: str) -> None:
    json.dump({"behavior": "deny", "message": reason}, sys.stdout)
    sys.stdout.flush()


def _output_fallthrough() -> None:
    # Empty output — falls through to Copilot's normal permission prompt
    json.dump({}, sys.stdout)
    sys.stdout.flush()


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def main() -> None:
    correlation_id = str(uuid.uuid4())

    # --- Parse input (fail-open on parse error) ---
    try:
        raw = sys.stdin.read()
        input_data: dict = json.loads(raw) if raw.strip() else {}
    except (json.JSONDecodeError, Exception) as exc:
        _log(f"Failed to parse hook input: {exc}", "ERROR")
        _output_fallthrough()
        sys.exit(0)

    # --- All processing in one big try/except so we never exit non-zero ---
    try:
        cwd = input_data.get("cwd", "") or os.getcwd()
        canonical = _build_canonical(input_data)

        _log(f"FIRED: canonical={canonical!r} cwd={cwd!r}", "DEBUG")

        if canonical == "<unknown>":
            _log(f"Could not determine canonical from input: {json.dumps(input_data)}", "WARN")
            _write_jsonl(SUGGESTIONS_LOG, _make_log_entry(
                correlation_id, input_data, canonical, "fall_through",
                "Could not determine canonical — inspect raw_input to understand payload format"
            ))
            _output_fallthrough()
            return

        config = _merge_configs(
            _load_config(CONFIG_PATH, required=True),
            _load_config(CONFIG_LOCAL_PATH),
        )

        decision, reason = evaluate(canonical, config)

        entry = _make_log_entry(correlation_id, input_data, canonical, decision, reason)

        if decision == "allow":
            _log(f"ALLOW: {canonical!r} — {reason}", "INFO")
            _write_jsonl(APPROVED_LOG, entry)
            _output_allow(reason)

        elif decision == "deny":
            _log(f"DENY: {canonical!r} — {reason}", "INFO")
            _write_jsonl(DENIED_LOG, entry)
            _output_deny(reason)

        elif decision == "ask":
            _log(f"ASK: {canonical!r} — {reason}", "INFO")
            _write_jsonl(ASK_LOG, entry)
            # "ask" is not a valid behavior for permissionRequest; fall through
            # so Copilot's own prompt handles it.
            _output_fallthrough()

        else:  # fall_through
            _log(f"FALL_THROUGH: {canonical!r}", "DEBUG")
            _write_jsonl(SUGGESTIONS_LOG, entry)
            _output_fallthrough()

    except Exception as exc:
        _log(f"Unhandled exception (failing open): {exc}", "ERROR")
        _output_fallthrough()
        sys.exit(0)


if __name__ == "__main__":
    main()
