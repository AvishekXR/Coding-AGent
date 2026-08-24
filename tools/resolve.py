"""Configuration resolution chains. Spec 5.4.3 -- the `why_this_value` tool.

Spec 5.4.3 identifies this as the tool that cracks the reference incident and the one no
surveyed vendor offers. Building the rest of the system first made it obvious *why* that is
true, and the reason is worth stating plainly:

Every other retrieval path here answers "what is related to what". The reverse index says two
files mention the same name. Ranking says a change is close to the failing service. Both are
associative, and association is symmetric -- it cannot distinguish the file that supplied a
value from a file that merely mentions it. In the reference incident the wrong destination is
named in three places, only one of which had anything to do with the failure.

A resolution chain is directional. It answers "where did this value actually come from",
which means it can report the hop that was *supposed* to supply a value and did not. That
negative fact has no audit event, emits no metric, and appears in no diff. It can only be
found by walking the chain and looking.

Kept out of tools/api.py because it is real logic rather than transport, and because the
near-miss comparison below is the sort of thing that deserves to be tested directly.
"""
from __future__ import annotations

import re
from pathlib import Path

from agent.types import Hop

#: Order in which configuration sources are consulted. The chain terminates at the hop that
#: actually supplied the value.
RESOLUTION_ORDER = ("configmap", "secret", "deployment_env", "helm_values",
                    "terraform", "cli_flag", "code_default")

#: Sources that exist as recorded cluster state (as opposed to repository content).
_OBSERVED_SOURCES = ("configmap", "secret", "deployment_env")

#: How a code-level default is recognised in source. Covers the common shapes:
#: env.get("KEY", DEFAULT) / os.environ.get("KEY", "literal") / DEFAULT_KEY = "literal".
_DEFAULT_PATTERNS = (
    r"""get\(\s*['"]{key}['"]\s*,\s*([A-Za-z_][A-Za-z0-9_]*|['"][^'"]*['"])""",
    r"""^\s*DEFAULT_{key}\s*=\s*['"]([^'"]*)['"]""",
    r"""^\s*{key}_DEFAULT\s*=\s*['"]([^'"]*)['"]""",
)


def near_misses(key: str, candidates: list[str]) -> list[str]:
    """Keys that look like `key` but are not it.

    A rename leaves exactly this fingerprint: the key the code reads is gone, and something
    very close to it is present in the same source. Comparison is on a normalised form, so
    suffix changes and separator changes are both caught without knowing what any particular
    key means.
    """
    def norm(s: str) -> str:
        return s.replace("_", "").replace("-", "").upper()

    k = norm(key)
    out = []
    for c in candidates:
        if c == key:
            continue
        n = norm(c)
        if n.startswith(k) or k.startswith(n) or (len(k) > 5 and (k in n or n in k)):
            out.append(c)
    return sorted(out)


def code_default(repos: Path, key: str, service: str) -> dict | None:
    """Find a hardcoded fallback for `key` in the service's own repository."""
    repo_dir = Path(repos) / service
    if not repo_dir.is_dir():
        return None

    pats = [re.compile(p.format(key=re.escape(key)), re.M) for p in _DEFAULT_PATTERNS]
    for path in sorted(repo_dir.rglob("*.py")):
        if ".git" in path.parts:
            continue
        try:
            text = path.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError):
            continue
        for pat in pats:
            m = pat.search(text)
            if not m:
                continue
            raw = m.group(1).strip()
            value = raw.strip("\"'")
            line = text[: m.start()].count("\n") + 1
            if raw == value and raw.isidentifier():
                # The default is a named constant, not a literal. Resolve it, so the chain
                # reports the value the service actually used rather than a symbol name.
                cm = re.search(
                    r"^\s*" + re.escape(raw) + r"""\s*=\s*['"]([^'"]*)['"]""", text, re.M)
                if cm:
                    value = cm.group(1)
                    line = text[: cm.start()].count("\n") + 1
            return Hop(
                source_type="code_default",
                source_ref="{}:{}:{}".format(
                    service, path.relative_to(repo_dir).as_posix(), line),
                found=True, value=value,
                note="hardcoded fallback in application source",
            ).to_dict()
    return None


def build_chain(ledger, repos: Path, key: str, service: str) -> dict:
    """Walk the resolution chain for one key in one service."""
    rows = ledger.conn.execute(
        "SELECT kind, name, namespace, key, value, source_ref, observed_at "
        "FROM config_state WHERE service = ? ORDER BY kind, name",
        (service,),
    ).fetchall()

    present = {(r["kind"], r["name"]): r for r in rows if r["key"] == key}
    containers = sorted({(r["kind"], r["name"]) for r in rows})

    hops: list[dict] = []
    for source_type in _OBSERVED_SOURCES:
        for ckind, cname in [c for c in containers if c[0] == source_type]:
            hit = present.get((ckind, cname))
            if hit is not None:
                hops.append(Hop(
                    source_type=source_type,
                    source_ref="{}/{}".format(source_type, cname),
                    found=True, value=hit["value"],
                    note="supplied by {} (observed {})".format(cname, hit["observed_at"]),
                ).to_dict())
                continue

            siblings = [r["key"] for r in rows if (r["kind"], r["name"]) == (ckind, cname)]
            near = near_misses(key, siblings)
            note = "key absent, falling through"
            if near:
                note += (
                    "; this source does define {} -- a near-identical key. A key the code "
                    "reads being gone while a similar one is present is what a rename looks "
                    "like from here".format(", ".join(near))
                )
            hops.append(Hop(
                source_type=source_type,
                source_ref="{}/{}".format(source_type, cname),
                found=False, value=None, note=note,
            ).to_dict())

    cd = code_default(repos, key, service)
    if cd:
        hops.append(cd)

    terminal = next((h for h in hops if h["found"]), None)
    out = {
        "key": key, "service": service, "chain": hops, "terminal": terminal,
        "resolved_value": (terminal or {}).get("value"),
        "near_miss_keys": sorted({
            n for h in hops if not h["found"]
            for n in re.findall(r"does define ([^-]+) --", h["note"])
        }),
    }

    if terminal and terminal["source_type"] == "code_default":
        # Emit prominently, per spec 5.4.3.
        out["finding"] = (
            "TERMINAL HOP IS A CODE DEFAULT. {key} resolved to {val!r} from a hardcoded "
            "fallback at {ref}, because no configuration source that was supposed to supply "
            "it contains the key. An expected configuration source went missing. The default "
            "itself is not the fault -- it was harmless for as long as the key was present -- "
            "so the question to ask is what removed the key."
        ).format(key=key, val=terminal.get("value"), ref=terminal.get("source_ref"))
    elif terminal is None:
        out["finding"] = (
            "{} is supplied by no source at all; the service sees no value for it.".format(key)
        )
    return out


def keys_read_by(repos: Path, service: str) -> list[str]:
    """Which configuration keys does this service's source actually read?

    Used to find the key worth asking about when nothing has named one yet. A key that code
    reads but no configuration source supplies is the interesting case.
    """
    repo_dir = Path(repos) / service
    if not repo_dir.is_dir():
        return []
    rx = re.compile(r"""(?:environ|env)(?:\.get)?\(?\s*['"]([A-Z][A-Z0-9_]{2,})['"]""")
    found: set[str] = set()
    for path in sorted(repo_dir.rglob("*.py")):
        if ".git" in path.parts:
            continue
        try:
            text = path.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError):
            continue
        found |= set(rx.findall(text))
    return sorted(found)
