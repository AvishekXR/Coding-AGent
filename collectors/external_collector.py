"""Documented external events. Spec 5.1.1 and 5.6.

Provider status incidents, certificate expiries, scheduled traffic events.

This collector is what makes "not ours" a legitimate answer. Spec 5.6.2 is strict about it:
the model may not assert that a provider had an incident. An external cause is valid **only**
when a collector recorded a corroborating row, and rows written here carry `evidenced` so the
Gate can tell a recorded event from an asserted one.

`evidenced=0` is deliberately supported: a provider status page that says "investigating"
is a report of an event, not yet a confirmation of one. Rows land unevidenced until
corroborated, and the Gate refuses to terminate on them -- which is the correct behaviour
during the first twenty minutes of an incident, when a status page is the least reliable
source in the building.
"""
from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path

import config as cfg
from ledger.ledger import Change, Ledger
from util import iso, parse_ts

#: Statuses that count as corroboration rather than rumour.
CONFIRMED = {"identified", "confirmed", "resolved", "postmortem", "monitoring"}


def collect(ledger: Ledger, t0: datetime | str, t1: datetime | str,
            state_dir: Path | None = None, team_of=None) -> int:
    state = Path(state_dir or cfg.STATE_DIR)
    path = state / "external" / "events.jsonl"
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

        status = (ev.get("status") or "investigating").lower()
        evidenced = status in CONFIRMED

        ledger.upsert_change(Change(
            id="external:{}:{}".format(ev.get("provider", "?"),
                                       ts.strftime("%Y%m%dT%H%M%S")),
            ts=ts, source="external", author=ev.get("provider", "unknown"),
            team=ev.get("owner_team"), repo=None,
            path=ev.get("component"),
            summary="{}: {} [{}]".format(
                ev.get("provider", "?"), ev.get("title", "event"), status)[:200],
            diff_ref="external:{}".format(ev.get("url", "")),
            evidenced=evidenced, raw=ev, collected_at=now,
        ))
        written += 1
    return written
