"""Apply a seeded incident to a freshly seeded world. Spec section 11.1.

    python -m incidents.inject 001
    python -m incidents.inject 001 --no-reseed     # apply onto the existing world

Reseeding by default is deliberate: an incident must be reproducible from nothing, and a
world that has already had an incident applied is not a clean baseline.
"""
from __future__ import annotations

import argparse
import importlib.util
import json
import sys
from datetime import datetime
from pathlib import Path

import config as cfg
from env import seed as seedmod
from env.world import World

INCIDENTS_DIR = Path(__file__).resolve().parent


def find_incident_dir(key: str) -> Path:
    """Resolve '001' or a full directory name to the incident directory."""
    exact = INCIDENTS_DIR / key
    if exact.is_dir():
        return exact
    matches = sorted(
        d for d in INCIDENTS_DIR.iterdir()
        if d.is_dir() and (d.name == key or d.name.startswith(key + "_"))
    )
    if not matches:
        raise SystemExit("no incident matching {!r} in {}".format(key, INCIDENTS_DIR))
    if len(matches) > 1:
        raise SystemExit("ambiguous incident key {!r}: {}".format(
            key, ", ".join(d.name for d in matches)))
    return matches[0]


def load_incident_module(d: Path):
    """Load `inject.py` by path.

    The spec's directory names start with digits (`001_silent_write_redirect`), which are not
    importable as packages. Loading by path keeps the layout in section 7.1 byte-for-byte.
    """
    spec = importlib.util.spec_from_file_location(
        "incident_" + d.name.replace("-", "_"), d / "inject.py"
    )
    if spec is None or spec.loader is None:
        raise SystemExit("cannot load {}".format(d / "inject.py"))
    mod = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = mod
    spec.loader.exec_module(mod)
    return mod


def inject(key: str, reseed: bool = True, seed_value: int = 4471) -> dict:
    d = find_incident_dir(key)
    mod = load_incident_module(d)
    incident = mod.build()
    meta = dict(mod.META)

    if reseed:
        seedmod.seed()

    w = World.open()
    day = meta["day"]
    start = datetime.fromisoformat("{}T{}:00".format(day, meta["window_start"]))
    end = datetime.fromisoformat("{}T{}:00".format(day, meta["window_end"]))

    w.run_traffic(start, end, seed=seed_value, hooks=incident.hooks(w.repos))
    w.save()

    meta["window_start_ts"] = start.isoformat()
    meta["window_end_ts"] = end.isoformat()
    meta["first_symptom_ts"] = "{}T{}:00".format(day, meta["first_symptom"])
    meta["opened_at_ts"] = "{}T{}:00".format(day, meta["opened_at"])
    (cfg.STATE_DIR / "incident.json").write_text(
        json.dumps(meta, indent=2), encoding="utf-8"
    )
    return meta


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="Inject a seeded incident.")
    ap.add_argument("incident", help="incident key, e.g. 001")
    ap.add_argument("--no-reseed", action="store_true",
                    help="apply onto the existing world instead of reseeding first")
    ap.add_argument("--seed", type=int, default=4471, help="traffic RNG seed")
    args = ap.parse_args(argv)

    meta = inject(args.incident, reseed=not args.no_reseed, seed_value=args.seed)
    w = World.open()

    prod = w.db.count("orders-prod")
    staging = w.db.count("orders-staging")
    print("incident      : {}".format(meta["id"]))
    print("window        : {} -> {}".format(meta["window_start_ts"], meta["window_end_ts"]))
    print("first symptom : {}".format(meta["first_symptom_ts"]))
    print("opened at     : {}".format(meta["opened_at_ts"]))
    print("orders-prod   : {} rows".format(prod))
    print("orders-staging: {} rows".format(staging))
    print("pod env       : {}".format(w.cluster.env_for("orders-api")))
    return 0


if __name__ == "__main__":
    sys.exit(main())
