"""Cross-repository reverse index. Spec 5.2.

Answers: which files, in *any* repository, mention this literal?

This is the component that lets the agent cross a repository boundary, and the reason the
reference incident is solvable at all -- the decisive mention of the renamed key lives in a
repository nobody would think to open. Per 5.2 it must index configuration,
infrastructure-as-code and documentation, not only application source.

Version 0 is a ripgrep sweep into SQLite, as the spec directs. One `rg` process per
repository returns candidate lines; literal extraction happens here so that snippets stay
exact and the patterns stay readable.
"""
from __future__ import annotations

import re
import shutil
import subprocess
from pathlib import Path

import config as cfg
from ledger.ledger import Ledger, Mention

#: What counts as a literal worth indexing. Deliberately broad: a reverse index is only
#: useful if the thing you need is already in it, and lookups are exact so breadth is cheap.
PATTERNS = {
    # ORDERS_TABLE, AWS_REGION, REPORT_WINDOW_MINUTES -- screaming snake case with at least
    # one underscore, which excludes bare words like INFO or ERROR.
    "env_key": re.compile(r"\b[A-Z][A-Z0-9]*(?:_[A-Z0-9]+)+\b"),
    # arn:aws:dynamodb:*:*:table/orders-prod
    "arn": re.compile(r"\barn:[a-z0-9-]*:[A-Za-z0-9:*/_.-]+"),
    # orders-prod, orders-staging, acme-reports-prod, analytics-etl
    "resource": re.compile(r"\b[a-z][a-z0-9]*(?:-[a-z0-9]+)+\b"),
    # api.internal.acme.example
    "host": re.compile(r"\b[a-z0-9-]+(?:\.[a-z0-9-]+){2,}\b"),
    # orders.strict_validation, billing.new_pricing -- feature-flag keys and dotted settings.
    # Spec 5.2 lists flag keys among the literals this index must cover. A flag is one of the
    # very few things that can change production behaviour with no commit anywhere, so the
    # ledger's flag history is often the only record of the cause -- and it has nothing to
    # attach to unless the index can resolve the key back to the code that reads it.
    "dotted_key": re.compile(r"\b[a-z][a-z0-9_]*(?:\.[a-z][a-z0-9_]+)+\b"),
}

#: Combined pattern handed to ripgrep to pull candidate lines out of the tree.
_RG_PATTERN = "|".join(
    ["[A-Z][A-Z0-9]*(_[A-Z0-9]+)+", "arn:[a-z0-9-]*:", "[a-z][a-z0-9]*(-[a-z0-9]+)+",
     r"[a-z][a-z0-9_]*(\.[a-z][a-z0-9_]+)+"]
)

KIND_BY_SUFFIX = {
    ".py": "code", ".js": "code", ".ts": "code", ".go": "code", ".java": "code",
    ".rb": "code", ".sh": "code",
    ".yaml": "config", ".yml": "config", ".json": "config", ".toml": "config",
    ".ini": "config", ".env": "config", ".properties": "config",
    ".tf": "iac", ".hcl": "iac", ".tfvars": "iac",
    ".md": "docs", ".rst": "docs", ".txt": "docs",
}
KIND_BY_NAME = {"CODEOWNERS": "config", "Dockerfile": "iac", "Makefile": "code"}

#: Noise that would otherwise dominate the index without ever being searched for.
STOPWORDS = {
    "aws-iam-policy-document", "aws-region", "utf-8", "e-g", "read-only",
    "in-house", "day-before", "per-table", "near-identical", "cross-region",
    "de-duplicating", "all-or-nothing", "byte-for-byte", "hand-written",
    "self-contained", "up-to-date", "top-level", "well-defined", "case-sensitive",
    "platform-independent", "brace-delimited", "file-backed", "append-only",
    "human-authored", "machine-state", "multi-cause", "single-cause",
}

MAX_SNIPPET = 200
#: A literal appearing on more lines than this in one file is boilerplate, not a signal.
MAX_ROWS_PER_LITERAL_PER_FILE = 5


def kind_of(path: str) -> str:
    p = Path(path)
    if p.name in KIND_BY_NAME:
        return KIND_BY_NAME[p.name]
    return KIND_BY_SUFFIX.get(p.suffix.lower(), "docs")


def extract_literals(line: str) -> set[str]:
    out: set[str] = set()
    for name, pat in PATTERNS.items():
        for m in pat.finditer(line):
            lit = m.group(0).rstrip(".,;:)\"'")
            if len(lit) < 4 or lit.lower() in STOPWORDS:
                continue
            # `host` and `resource` overlap; keep both spellings so either lookup hits.
            out.add(lit)
    return out


def _repos(repos_dir: Path) -> list[Path]:
    return sorted(d for d in Path(repos_dir).iterdir() if (d / ".git").is_dir())


def ripgrep_path() -> str | None:
    """Locate ripgrep, or None if it is not installed.

    Spec 5.2 specifies a ripgrep sweep, and rg is the right tool at real-repository scale.
    But the index is load-bearing -- without it the agent cannot cross a repository boundary
    and the whole target incident class becomes unsolvable -- so it must not depend on an
    optional binary being on PATH. See DECISIONS.md D-007.
    """
    return shutil.which("rg")


#: Directories never worth indexing. Kept small; the point of a reverse index is coverage.
SKIP_DIRS = {".git", "__pycache__", "node_modules", ".venv", "venv", ".terraform",
             "dist", "build", ".pytest_cache"}
#: Files larger than this are almost certainly generated or binary.
MAX_FILE_BYTES = 2_000_000


def _sweep_rg(repo: Path) -> list[tuple[str, int, str]]:
    """One ripgrep pass. Returns (relative_path, line_number, line_text)."""
    r = subprocess.run(
        [ripgrep_path(), "--no-heading", "--with-filename", "--line-number",
         "--no-messages", "--color", "never", "-e", _RG_PATTERN, "."],
        cwd=str(repo), capture_output=True, text=True,
    )
    # rg exits 1 when there are no matches, which is not an error.
    if r.returncode not in (0, 1):
        raise RuntimeError("ripgrep failed in {}: {}".format(repo, r.stderr))

    out = []
    for line in r.stdout.splitlines():
        # path:line:content -- split only twice, content may contain colons.
        parts = line.split(":", 2)
        if len(parts) < 3:
            continue
        path, lineno, content = parts
        if not lineno.isdigit():
            continue
        rel = path.lstrip("./").replace("\\", "/")
        out.append((rel, int(lineno), content))
    return out


def _sweep_python(repo: Path) -> list[tuple[str, int, str]]:
    """Pure-Python equivalent of the ripgrep sweep. Same output contract."""
    rx = re.compile(_RG_PATTERN)
    out = []
    for path in sorted(repo.rglob("*")):
        if not path.is_file():
            continue
        if any(part in SKIP_DIRS for part in path.relative_to(repo).parts):
            continue
        try:
            if path.stat().st_size > MAX_FILE_BYTES:
                continue
            text = path.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError):
            continue  # binary or unreadable: rg would skip it too
        rel = path.relative_to(repo).as_posix()
        for lineno, content in enumerate(text.splitlines(), start=1):
            if rx.search(content):
                out.append((rel, lineno, content))
    return out


def _sweep(repo: Path) -> list[tuple[str, int, str]]:
    return _sweep_rg(repo) if ripgrep_path() else _sweep_python(repo)


def build(ledger: Ledger, repos_dir: Path | None = None) -> dict:
    """Rebuild the reverse index across every repository. Returns summary counts."""
    repos_dir = Path(repos_dir or cfg.REPOS_DIR)
    ledger.conn.execute("DELETE FROM mentions")

    seen_per_file: dict[tuple[str, str, str], int] = {}
    rows = 0
    literals: set[str] = set()

    for repo in _repos(repos_dir):
        for rel, lineno, content in _sweep(repo):
            kind = kind_of(rel)
            snippet = content.strip()[:MAX_SNIPPET]
            for lit in extract_literals(content):
                key = (lit, repo.name, rel)
                if seen_per_file.get(key, 0) >= MAX_ROWS_PER_LITERAL_PER_FILE:
                    continue
                seen_per_file[key] = seen_per_file.get(key, 0) + 1
                ledger.upsert_mention(lit, Mention(
                    repo=repo.name, path=rel, line=lineno, snippet=snippet, kind=kind,
                ))
                literals.add(lit)
                rows += 1
    ledger.commit()

    by_kind = {
        r[0]: r[1] for r in ledger.conn.execute(
            "SELECT kind, COUNT(*) FROM mentions GROUP BY kind"
        ).fetchall()
    }
    return {"rows": rows, "literals": len(literals), "by_kind": by_kind}
