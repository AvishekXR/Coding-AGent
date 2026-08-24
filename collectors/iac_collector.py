"""Infrastructure-as-code applies. Spec 5.1.1, phase 1.

A commit and an apply are different events and the ledger carries both. The commit says a
human wrote something; the apply says it reached production, and *when*. They can be hours
apart, and for the Gate's timing rule (5.6 rule 3) the apply is often the honest comparison.

In this world a terraform apply is recorded as a CloudTrail PutRolePolicy event by the
terraform-ci principal, carrying the repo and path it came from.
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
    trail = state / "cloud" / "cloudtrail.jsonl"
    if not trail.exists():
        return 0

    lo, hi = parse_ts(t0), parse_ts(t1)
    now = iso(datetime.utcnow())
    written = 0

    for line in trail.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        ev = json.loads(line)
        if ev.get("userIdentity", {}).get("arn") != "terraform-ci":
            continue
        ts = parse_ts(ev["eventTime"])
        if not (lo <= ts <= hi):
            continue

        req = ev.get("requestParameters", {})
        repo = req.get("repo")
        path = req.get("path")
        applied_by = req.get("appliedBy", "")
        author = applied_by.split(" <")[0] if applied_by else "terraform-ci"

        ledger.upsert_change(Change(
            id="iac:{}:{}".format(repo, ts.strftime("%Y%m%dT%H%M%S")),
            ts=ts,
            source="iac",
            author=author,
            team=team_of(repo) if team_of and repo else None,
            repo=repo,
            path=path,
            summary="terraform apply: {} {}".format(repo, path or "")[:200],
            diff_ref="iac:{}:{}".format(repo, path or ""),
            evidenced=True,
            raw=ev,
            collected_at=now,
        ))
        written += 1
    return written
