"""Cloud provider control-plane events. Spec 5.1.1.

IAM edits, security groups, DNS, console actions. This is the collector that sees a change
made by a human clicking in a console -- an action that exists in no repository, has no
review, and leaves no trace anywhere else.
"""
from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path

import config as cfg
from ledger.ledger import Change, Ledger
from util import iso, parse_ts

#: Read-only API names. A control-plane trail is mostly reads; they are not changes.
READ_PREFIXES = ("Describe", "Get", "List", "Head", "Lookup", "BatchGet")

#: Automation principals whose actions are already in the ledger via the iac collector.
AUTOMATION = {"terraform-ci", "argocd", "flux"}


def collect(ledger: Ledger, t0: datetime | str, t1: datetime | str,
            state_dir: Path | None = None, team_of=None) -> int:
    state = Path(state_dir or cfg.STATE_DIR)
    path = state / "cloud" / "cloudtrail.jsonl"
    if not path.exists():
        return 0

    lo, hi = parse_ts(t0), parse_ts(t1)
    now = iso(datetime.utcnow())
    written = 0

    for line in path.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        ev = json.loads(line)
        name = ev.get("eventName", "")
        if name.startswith(READ_PREFIXES):
            continue
        principal = (ev.get("userIdentity") or {}).get("arn", "unknown")
        if principal in AUTOMATION:
            continue

        ts = parse_ts(ev.get("eventTime"))
        if not (lo <= ts <= hi):
            continue

        req = ev.get("requestParameters") or {}
        target = req.get("roleName") or req.get("name") or req.get("summary") or ""

        ledger.upsert_change(Change(
            id="cloudtrail:{}:{}".format(name, ts.strftime("%Y%m%dT%H%M%S")),
            ts=ts, source="cloudtrail", author=principal,
            team=team_of(principal) if team_of else None,
            repo=None, path=ev.get("eventSource"),
            summary="{} via {} by {}{}".format(
                name, ev.get("eventSource", "?"), principal,
                ": " + str(target) if target else "")[:200],
            diff_ref="cloudtrail:{}".format(name),
            evidenced=True, raw=ev, collected_at=now,
        ))
        written += 1
    return written
