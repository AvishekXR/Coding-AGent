"""Safety and governance (L6). Spec section 5.9. No LLM.

Three surfaces, each with its own failure mode:

  5.9.1 **Production access.** Read-only by default, under a separate scoped identity, fully
        audited. There is no write path in this codebase -- not a disabled one, not one behind
        a flag. `assert_no_write_path()` proves that by inspection rather than by promise,
        because "we do not do that" is not a control.

  5.9.2 **Prompt injection.** Logs, alert payloads and ticket text are attacker-writable and
        flow straight into model context; the reported success rate against SRE agents is
        11.2%. The defence that matters is not a filter -- filters are bypassable and give
        false confidence. It is that **tool selection is never a function of content**. In this
        system the next tool is chosen by which Gate rule fired, and the Gate is deterministic
        Python that never reads log text. An injected instruction can therefore be *read*, but
        it has nothing to steer: there is no code path from log content to a tool call.

  5.9.3 **Budgets and circuit breakers.** Enforced in agent/runner.py. Exhaustion produces
        UNRESOLVED with a frontier, never a guess.

`quote_as_data` and `extract_fields` implement the structured-extraction half of 5.9.2: free
text reaches the model fenced as data, never concatenated into instructions.
"""
from __future__ import annotations

import ast
import re
from dataclasses import dataclass, field
from pathlib import Path

import config as cfg

#: Shapes that commonly carry an injected instruction. Used to *annotate* text as suspicious
#: and to raise an incident-class-L finding -- never as a filter that would license trusting
#: whatever passes it. Detection is a reporting aid; the structural defence is above.
_INJECTION_MARKERS = (
    re.compile(r"\bignore\s+(all\s+)?(previous|prior|above)\b", re.I),
    re.compile(r"\b(disregard|override)\s+(your|the)\s+(instructions|rules|prompt)\b", re.I),
    re.compile(r"\byou\s+are\s+now\b", re.I),
    re.compile(r"\bsystem\s*[:>]\s*", re.I),
    re.compile(r"\b(new|updated)\s+instructions?\b", re.I),
    re.compile(r"</?(system|instructions?|assistant)>", re.I),
    re.compile(r"\bthe\s+root\s+cause\s+is\b", re.I),
    re.compile(r"\b(call|invoke|run|execute)\s+\w+\s*\(", re.I),
    re.compile(r"\b(kubectl|aws|terraform|psql)\s+\w+", re.I),
)

#: Any mutating verb that must not exist anywhere in the solving half.
_WRITE_CALLS = re.compile(
    r"\b(?:"
    r"kubectl\s+(?:apply|delete|patch|set|scale|edit)"
    r"|aws\s+\w+\s+(?:put|create|delete|update|attach|detach)"
    r"|terraform\s+(?:apply|destroy|import)"
    r"|helm\s+(?:install|upgrade|uninstall|rollback)"
    r")\b",
    re.I,
)

#: Directories that must contain no write path to any real environment.
GUARDED_PACKAGES = ("agent", "indexer", "ledger", "tools", "safety")


@dataclass
class SafetyReport:
    violations: list[str] = field(default_factory=list)
    findings: list[str] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        return not self.violations

    def to_dict(self) -> dict:
        return {"ok": self.ok, "violations": self.violations, "findings": self.findings}


# --- 5.9.2 -------------------------------------------------------------------
def looks_like_injection(text: str) -> list[str]:
    """Return the injection markers present in `text`. Empty list means none matched.

    A reporting aid, not a gate. Treating this as the defence would be the mistake: a
    filter that passes is not evidence that text is safe, and building on it would quietly
    move the system back to trusting content.
    """
    hits = []
    for rx in _INJECTION_MARKERS:
        m = rx.search(text or "")
        if m:
            hits.append(m.group(0).strip())
    return hits


def quote_as_data(text: str, label: str = "untrusted") -> str:
    """Fence free text so it cannot read as instruction.

    Delimiters are escaped inside the payload so the content cannot close its own fence and
    continue as prose outside it.
    """
    body = str(text or "").replace("<{}>".format(label), "").replace(
        "</{}>".format(label), "")
    return "<{lab}>{body}</{lab}>".format(lab=label, body=body)


def extract_fields(record: dict, allowed: tuple[str, ...]) -> dict:
    """Structured extraction: keep known keys, drop everything else. Spec 5.9.2.

    Free-text values are truncated and never interpreted. What reaches the model is a shape
    the system chose, not a shape an attacker chose.
    """
    out = {}
    for k in allowed:
        if k in record:
            v = record[k]
            out[k] = v[:500] if isinstance(v, str) else v
    return out


# --- 5.9.1 -------------------------------------------------------------------
def assert_no_write_path(root: Path | None = None) -> SafetyReport:
    """Prove by inspection that no module in the solving half can mutate a real environment.

    Spec 5.9.1 prohibits direct kubectl, direct cloud CLI mutation and direct database writes.
    An assertion in a review checklist is not a control; a test that reads the source is.
    """
    root = Path(root or cfg.ROOT)
    report = SafetyReport()

    for pkg in GUARDED_PACKAGES:
        for path in sorted((root / pkg).rglob("*.py")):
            text = path.read_text(encoding="utf-8")
            rel = path.relative_to(root).as_posix()

            for m in _WRITE_CALLS.finditer(text):
                line = text[: m.start()].count("\n") + 1
                # A mutation named inside a string that is prose -- a remediation step in a
                # report, or a prohibition in a docstring -- is not a call.
                if _inside_string_or_comment(text, m.start()):
                    continue
                report.violations.append(
                    "{}:{} names a mutating command outside a string: {!r}".format(
                        rel, line, m.group(0)))

            tree = ast.parse(text)
            for node in ast.walk(tree):
                if not isinstance(node, ast.Call):
                    continue
                name = _call_name(node)
                if name in ("os.system", "os.popen", "subprocess.call",
                            "subprocess.check_call"):
                    report.findings.append(
                        "{}:{} uses {} -- prefer subprocess.run with an argument list".format(
                            rel, getattr(node, "lineno", 0), name))
    return report


def _inside_string_or_comment(text: str, index: int) -> bool:
    """Whether `index` falls inside a Python string literal or a comment."""
    line_start = text.rfind("\n", 0, index) + 1
    line = text[line_start:index]
    if "#" in line:
        return True
    # Count unescaped quotes before the position on this line, plus triple-quote parity above.
    before = text[:index]
    if before.count('"""') % 2 == 1 or before.count("'''") % 2 == 1:
        return True
    return (line.count('"') % 2 == 1) or (line.count("'") % 2 == 1)


def _call_name(node: ast.Call) -> str:
    f = node.func
    if isinstance(f, ast.Attribute):
        parts = [f.attr]
        cur = f.value
        while isinstance(cur, ast.Attribute):
            parts.append(cur.attr)
            cur = cur.value
        if isinstance(cur, ast.Name):
            parts.append(cur.id)
        return ".".join(reversed(parts))
    if isinstance(f, ast.Name):
        return f.id
    return ""


def audit_summary(ledger, run_id: str) -> dict:
    """The audit trail for one run, as 5.9.1 requires it to be reportable."""
    rows = ledger.audit_log(run_id)
    by_tool: dict[str, int] = {}
    for r in rows:
        by_tool[r["tool"]] = by_tool.get(r["tool"], 0) + 1
    return {
        "run_id": run_id,
        "calls": len(rows),
        "identities": sorted({r["identity"] for r in rows}),
        "by_tool": by_tool,
        "errors": sum(1 for r in rows if r["outcome"] == "error"),
        "tokens_returned": sum(r["tokens"] or 0 for r in rows),
    }
