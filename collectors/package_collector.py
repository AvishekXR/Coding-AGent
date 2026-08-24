"""OS and package state. Spec 5.1.1, and the reason class E exists.

The Datadog outage of 8 March 2023 (Appendix B.2) was caused by an automatic systemd security
update delivered through a legacy channel baked into the base image, on a default 06:00-07:00
window -- which is why five independent regions on three cloud providers failed at the same
moment. Deploys involved: zero. No commit, no pull request, no CI run.

A change ledger built from version control and the deploy pipeline shows a clean board for
that entire incident. This collector is what stops the system confidently reporting "no
changes found" while tens of thousands of nodes are off the network.
"""
from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path

import config as cfg
from ledger.ledger import Change, Ledger
from util import iso, parse_ts


def collect(ledger: Ledger, t0: datetime | str, t1: datetime | str,
            state_dir: Path | None = None, team_of=None) -> int:
    """Read unattended-upgrade style records into the ledger."""
    state = Path(state_dir or cfg.STATE_DIR)
    path = state / "host" / "packages.jsonl"
    if not path.exists():
        return 0

    lo, hi = parse_ts(t0), parse_ts(t1)
    now = iso(datetime.utcnow())
    written = 0

    for line in path.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        ev = json.loads(line)
        ts = parse_ts(ev["ts"])
        if not (lo <= ts <= hi):
            continue

        pkg = ev.get("package", "?")
        summary = "{} {} -> {} on {} ({})".format(
            ev.get("action", "upgrade"), pkg, ev.get("to_version", "?"),
            ev.get("scope", "fleet"), ev.get("channel", "unknown channel"))

        ledger.upsert_change(Change(
            id="package:{}:{}".format(pkg, ts.strftime("%Y%m%dT%H%M%S")),
            ts=ts, source="package",
            # Nobody authored this in any repository. Attributing it to a person would be a
            # lie; attributing it to the mechanism is the honest answer and is still
            # actionable -- someone owns the update channel.
            author=ev.get("actor", "unattended-upgrades"),
            team=ev.get("team", "Platform"),
            repo=None,
            path="host/{}".format(pkg),
            summary=summary[:200],
            diff_ref="package:{}".format(pkg),
            evidenced=True, raw=ev, collected_at=now,
        ))
        written += 1
    return written
