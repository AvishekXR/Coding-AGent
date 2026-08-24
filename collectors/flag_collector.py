"""Feature-flag platform history. Spec 5.1.1.

A flag flip is a production change with no commit, no review and, on most platforms, a
different audit trail from everything else. It is also the fastest way to change behaviour in
a running system, which makes it disproportionately likely to be the answer.
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
    state = Path(state_dir or cfg.STATE_DIR)
    path = state / "flags" / "history.jsonl"
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

        key = ev.get("flag", "?")
        ledger.upsert_change(Change(
            id="flag:{}:{}".format(key, ts.strftime("%Y%m%dT%H%M%S")),
            ts=ts, source="flag", author=ev.get("actor", "unknown"),
            team=ev.get("team"), repo=None, path="flags/{}".format(key),
            summary="flag {} {} -> {} for {} by {}".format(
                key, ev.get("from"), ev.get("to"), ev.get("scope", "all"),
                ev.get("actor", "unknown"))[:200],
            diff_ref="flag:{}".format(key),
            evidenced=True, raw=ev, collected_at=now,
        ))
        written += 1
    return written
