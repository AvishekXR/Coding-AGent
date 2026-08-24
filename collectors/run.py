"""Build the L0 world model: change ledger, reverse index, ownership map.

    python -m collectors.run                     # collect the injected incident's window
    python -m collectors.run --from ... --to ...

This is the background half of spec 4.1. It runs continuously in a real deployment and
contains no model calls at all -- which is where most of the eventual accuracy comes from.
"""
from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime, timedelta
from pathlib import Path

import config as cfg
from collectors import git_collector, iac_collector, ownership
from ledger import index as reverse_index
from ledger.ledger import Ledger
from util import parse_ts


def incident_meta() -> dict | None:
    p = cfg.STATE_DIR / "incident.json"
    return json.loads(p.read_text(encoding="utf-8")) if p.exists() else None


def collect_all(t0: datetime, t1: datetime, ledger: Ledger | None = None) -> dict:
    """Run every phase-1 collector plus the reverse index. Returns summary counts."""
    own = close_after = None
    if ledger is None:
        ledger = Ledger()
        close_after = ledger

    ledger.clear_changes()
    own = ownership.collect(ledger)
    team_of = ownership.team_lookup(ledger)

    n_git = git_collector.collect(ledger, t0, t1, team_of=team_of)
    n_iac = iac_collector.collect(ledger, t0, t1, team_of=team_of)
    ledger.commit()

    idx = reverse_index.build(ledger)

    meta = incident_meta()
    if meta:
        ledger.upsert_incident(
            incident_id=meta["id"], opened_at=meta["opened_at_ts"],
            first_symptom_ts=meta["first_symptom_ts"],
            window_start=meta["window_start_ts"], window_end=meta["window_end_ts"],
            alert=meta["alert"], status="open",
        )
    ledger.commit()

    summary = {
        "window": [t0.isoformat(), t1.isoformat()],
        "ownership_rows": own,
        "changes": {"git": n_git, "iac": n_iac, "total": n_git + n_iac},
        "reverse_index": idx,
    }
    if close_after is not None:
        close_after.close()
    return summary


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="Build the change ledger and reverse index.")
    ap.add_argument("--from", dest="t0", help="window start (ISO)")
    ap.add_argument("--to", dest="t1", help="window end (ISO)")
    ap.add_argument("--json", action="store_true")
    args = ap.parse_args(argv)

    meta = incident_meta()
    if args.t0 and args.t1:
        t0, t1 = parse_ts(args.t0), parse_ts(args.t1)
    elif meta:
        # Collect a wider span than the incident window: a cause can predate the window,
        # and a ledger that only knows the window cannot prove a change is the first mover.
        t0 = parse_ts(meta["window_start_ts"]) - timedelta(days=30)
        t1 = parse_ts(meta["window_end_ts"])
    else:
        raise SystemExit("no incident injected and no --from/--to given")

    summary = collect_all(t0, t1)

    if args.json:
        print(json.dumps(summary, indent=2))
        return 0

    c = summary["changes"]
    i = summary["reverse_index"]
    print("window        : {} -> {}".format(*summary["window"]))
    print("ownership     : {} patterns".format(summary["ownership_rows"]))
    print("changes       : {} total  (git {}, iac {})".format(c["total"], c["git"], c["iac"]))
    print("reverse index : {} rows over {} literals".format(i["rows"], i["literals"]))
    print("              : {}".format(i["by_kind"]))
    return 0


if __name__ == "__main__":
    sys.exit(main())
