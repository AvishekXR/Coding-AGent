"""Bring the simulated company up, healthy and reproducibly. Spec section 11.1.

    python -m env.seed            # build repositories + world + baseline telemetry
    python -m env.seed --check    # prove the incident window is flat when nothing is injected

The baseline day matters: anomaly detection needs something to be anomalous *against*. Seed
generates a full healthy day-before at the same hours as the incident window, so every
threshold in indexer/anomalies.py is measured, never assumed.
"""
from __future__ import annotations

import argparse
import os
import shutil
import subprocess
import sys
import tempfile
from datetime import datetime, timedelta
from pathlib import Path

import config as cfg
from env.world import World

FIXTURES = cfg.ENV_DIR / "fixtures" / "repos"

#: The day before the incident, same hours. Baseline for every anomaly threshold.
BASELINE_DAY = "2026-08-19"
#: The incident day (spec section 8 timeline).
INCIDENT_DAY = cfg.INCIDENT_DATE

WINDOW_START_H = 8
WINDOW_END_H = 10
WINDOW_END_M = 15


def at(day: str, hh: int, mm: int = 0) -> datetime:
    return datetime.fromisoformat("{}T{:02d}:{:02d}:00".format(day, hh, mm))


def window(day: str) -> tuple[datetime, datetime]:
    return at(day, WINDOW_START_H), at(day, WINDOW_END_H, WINDOW_END_M)


# --- git ---------------------------------------------------------------------
def git(repo: Path, *args: str, when: datetime | None = None,
        author: str | None = None) -> str:
    env = dict(os.environ)
    env.setdefault("GIT_CONFIG_NOSYSTEM", "1")
    if when is not None:
        stamp = when.strftime("%Y-%m-%dT%H:%M:%S") + "+00:00"
        env["GIT_AUTHOR_DATE"] = stamp
        env["GIT_COMMITTER_DATE"] = stamp
    if author is not None:
        name, email = author.split(" <")
        env["GIT_AUTHOR_NAME"] = env["GIT_COMMITTER_NAME"] = name
        env["GIT_AUTHOR_EMAIL"] = env["GIT_COMMITTER_EMAIL"] = email.rstrip(">")
    r = subprocess.run(
        ["git", "-C", str(repo), *args],
        env=env, capture_output=True, text=True,
    )
    if r.returncode != 0:
        raise RuntimeError("git {} failed in {}:\n{}".format(" ".join(args), repo, r.stderr))
    return r.stdout


def commit_all(repo: Path, message: str, when: datetime, author: str) -> str:
    git(repo, "add", "-A")
    git(repo, "commit", "-m", message, when=when, author=author)
    return git(repo, "rev-parse", "HEAD").strip()


#: Baseline history, so `git log` in the incident window is not the whole repository.
#: orders-api is deliberately absent after its initial commit: spec 8.3 requires the failing
#: service to be untouched for two weeks.
BASELINE_HISTORY = [
    ("platform-config", "2026-08-11T14:02", "dee-mensah <dee@acme.example>",
     "Raise ORDER_MAX_ITEMS for the seasonal catalogue",
     [("overlays/prod/orders.yaml", "ORDER_MAX_ITEMS: \"50\"", "ORDER_MAX_ITEMS: \"75\"")]),
    ("platform-iac", "2026-08-13T09:40", "dee-mensah <dee@acme.example>",
     "Add reports bucket read permission for the reporting service",
     [("modules/iam/s3.tf", '"s3:GetObject",', '"s3:GetObject",\n      "s3:ListBucket",')]),
    ("analytics-etl", "2026-08-17T11:20", "rin-tanaka <rin@acme.example>",
     "Widen the reporting window to five minutes",
     [("etl/metrics.py", "window_end.isoformat()", "window_end.isoformat()")]),
]


def build_repos(repos_dir: Path) -> None:
    """Create four real git repositories from the fixtures, with dated history."""
    if repos_dir.exists():
        shutil.rmtree(repos_dir, onerror=_force_rw)
    repos_dir.mkdir(parents=True)

    initial = datetime.fromisoformat("2026-08-06T10:00:00")
    for src in sorted(FIXTURES.iterdir()):
        if not src.is_dir():
            continue
        dst = repos_dir / src.name
        shutil.copytree(src, dst)
        git(dst, "init", "-q", "-b", "main")
        git(dst, "config", "user.name", "seed")
        git(dst, "config", "user.email", "seed@acme.example")
        commit_all(dst, "Initial import of {}".format(src.name), initial,
                   "platform-bootstrap <bootstrap@acme.example>")

    for repo, when, author, message, edits in BASELINE_HISTORY:
        d = repos_dir / repo
        for rel, old, new in edits:
            p = d / rel
            text = p.read_text(encoding="utf-8")
            if old != new and old in text:
                p.write_text(text.replace(old, new, 1), encoding="utf-8")
            else:
                # A no-op content edit still needs a commit to exist in history; touch a
                # comment line so the diff is real.
                p.write_text(text + "\n# reviewed {}\n".format(when[:10]), encoding="utf-8")
        commit_all(d, message, datetime.fromisoformat(when + ":00"), author)


def _force_rw(func, path, _exc):
    """git keeps objects read-only on Windows; make them writable so rmtree can proceed."""
    os.chmod(path, 0o700)
    func(path)


# --- world -------------------------------------------------------------------
def build_world(state_dir: Path, repos_dir: Path, baseline: bool = True) -> World:
    if state_dir.exists():
        shutil.rmtree(state_dir, onerror=_force_rw)
    state_dir.mkdir(parents=True)

    w = World.open(state_dir=state_dir, repos=repos_dir)
    w.bootstrap(at(BASELINE_DAY, 7, 0))
    if baseline:
        start, end = window(BASELINE_DAY)
        w.run_traffic(start, end, seed=4471)
    w.save()
    return w


def seed(state_dir: Path | None = None, repos_dir: Path | None = None) -> World:
    repos_dir = Path(repos_dir or cfg.REPOS_DIR)
    state_dir = Path(state_dir or cfg.STATE_DIR)
    build_repos(repos_dir)
    return build_world(state_dir, repos_dir)


# --- health check ------------------------------------------------------------
def check_healthy() -> int:
    """Run the incident window with no changes injected and assert the world stays flat.

    This is half of the phase-0 acceptance test: seed.sh brings up a *healthy* system.
    Runs against a throwaway state directory so it cannot disturb a seeded world.
    """
    import json

    tmp = Path(tempfile.mkdtemp(prefix="hisev-health-"))
    try:
        w = build_world(tmp / "state", cfg.REPOS_DIR, baseline=False)
        start, end = window(INCIDENT_DAY)
        w.run_traffic(start, end, seed=4471)
        w.save()

        rows = [
            json.loads(line)
            for line in (tmp / "state" / "telemetry" / "metrics.jsonl")
            .read_text(encoding="utf-8").splitlines() if line.strip()
        ]
        created = [r["value"] for r in rows if r["metric"] == "orders_created"]
        denied = [r["value"] for r in rows if r["metric"] == "dynamodb_access_denied"]
        staging = [r["value"] for r in rows if r["metric"].endswith("orders-staging")]
        expected = 106

        ok = True
        if not created or min(created) != expected or max(created) != expected:
            print("FAIL orders_created not flat: min={} max={} expected={}".format(
                min(created or [0]), max(created or [0]), expected))
            ok = False
        else:
            print("PASS orders_created flat at {}/min across {} minutes".format(
                expected, len(created)))
        if any(denied):
            print("FAIL unexpected AccessDenied in a healthy window")
            ok = False
        else:
            print("PASS zero authorization failures")
        if staging:
            print("FAIL writes reached orders-staging in a healthy window")
            ok = False
        else:
            print("PASS zero writes to orders-staging")
        return 0 if ok else 1
    finally:
        shutil.rmtree(tmp, onerror=_force_rw)


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="Seed the simulated company.")
    ap.add_argument("--check", action="store_true",
                    help="verify the incident window is flat with nothing injected")
    args = ap.parse_args(argv)

    if args.check:
        return check_healthy()

    w = seed()
    print("repositories : {}".format(cfg.REPOS_DIR))
    print("state        : {}".format(cfg.STATE_DIR))
    print("baseline day : {} {:02d}:00-{:02d}:{:02d}".format(
        BASELINE_DAY, WINDOW_START_H, WINDOW_END_H, WINDOW_END_M))
    print("orders-prod  : {} rows".format(w.db.count("orders-prod")))
    print("orders-staging: {} rows".format(w.db.count("orders-staging")))
    print("pod env      : {}".format(w.cluster.env_for("orders-api")))
    return 0


if __name__ == "__main__":
    sys.exit(main())
