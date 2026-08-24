"""Kubernetes audit log. Spec 5.1.1.

ConfigMap, Secret, RBAC and CRD mutations. The reason this collector exists separately from
git is that a cluster mutation need not have a commit behind it: someone can edit a ConfigMap
with kubectl, and then the only record anywhere is this stream.
"""
from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path

import config as cfg
from ledger.ledger import Change, Ledger
from util import iso, parse_ts

#: Verbs that change something. `get`, `list` and `watch` are noise here.
MUTATING = {"create", "update", "patch", "delete", "deletecollection"}

#: Actors whose changes are already represented by a git commit plus an apply. Recording them
#: again would double-count every ConfigMap edit that came through the normal path.
AUTOMATION = {"system:config-sync", "system:deployment-controller", "system:serviceaccount"}


def collect(ledger: Ledger, t0: datetime | str, t1: datetime | str,
            state_dir: Path | None = None, team_of=None) -> int:
    state = Path(state_dir or cfg.STATE_DIR)
    path = state / "cluster" / "audit.jsonl"
    if not path.exists():
        return 0

    lo, hi = parse_ts(t0), parse_ts(t1)
    now = iso(datetime.utcnow())
    written = 0

    for line in path.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        ev = json.loads(line)
        verb = (ev.get("verb") or "").lower()
        if verb not in MUTATING:
            continue
        user = (ev.get("user") or {}).get("username", "unknown")
        if any(user.startswith(a) for a in AUTOMATION):
            continue

        ts = parse_ts(ev.get("requestReceivedTimestamp"))
        if not (lo <= ts <= hi):
            continue

        ref = ev.get("objectRef") or {}
        resource, name = ref.get("resource", "?"), ref.get("name", "?")
        diff = (ev.get("annotations") or {}).get("diff")

        ledger.upsert_change(Change(
            id="k8s:{}:{}:{}".format(resource, name, ts.strftime("%Y%m%dT%H%M%S")),
            ts=ts, source="k8s", author=user,
            team=team_of(name) if team_of else None,
            repo=None,
            path="{}/{}/{}".format(ref.get("namespace", "default"), resource, name),
            summary="{} {} {}/{} by {}".format(
                verb, resource, ref.get("namespace", "default"), name, user)[:200],
            diff_ref="k8s:{}:{}".format(resource, name),
            evidenced=True, raw=ev, collected_at=now,
        ))
        written += 1
    return written
