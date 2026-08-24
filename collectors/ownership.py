"""Ownership map. Spec 4.2 (L0) and 5.4.5.

Reads the organisation's ownership file plus each repository's CODEOWNERS. Ownership is what
turns a cause into something a human can act on: a decision package that names a change but
not the team that owns it still leaves the on-call engineer doing the last hop.
"""
from __future__ import annotations

from pathlib import Path

import yaml

import config as cfg
from ledger.ledger import Ledger

OWNERSHIP_FILE = cfg.ENV_DIR / "fixtures" / "ownership.yaml"


def collect(ledger: Ledger, path: Path | None = None) -> int:
    src = Path(path or OWNERSHIP_FILE)
    if not src.exists():
        return 0
    entries = yaml.safe_load(src.read_text(encoding="utf-8")) or []
    for e in entries:
        ledger.set_ownership(
            pattern=e["pattern"], team=e.get("team"), oncall=e.get("oncall"),
            slack=e.get("slack"), escalation=e.get("escalation"),
        )
    return len(entries)


def team_lookup(ledger: Ledger):
    """Return a callable repo -> team name, cached, for the collectors to attribute rows."""
    cache: dict[str, str | None] = {}

    def team_of(repo: str) -> str | None:
        if repo not in cache:
            owner = ledger.owner_of(repo)
            cache[repo] = (owner or {}).get("team")
        return cache[repo]

    return team_of
