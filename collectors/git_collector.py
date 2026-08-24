"""Commits across every repository in every organisation. Spec 5.1.1, phase 1.

"Across every repository" is the whole point. Scoping the sweep to the failing service's
repository reproduces exactly the blind spot in spec 1.4: in the reference incident, orders-api
has no commits at all in the window and both causes live in someone else's repository.

Rows are emitted per (commit, file) rather than per commit, because ownership, the reverse
index and the answer key all work at path granularity. A commit touching more files than
`FANOUT_LIMIT` collapses to a single row so that a bulk refactor cannot flood the window.
"""
from __future__ import annotations

import subprocess
from datetime import datetime
from pathlib import Path

import config as cfg
from ledger.ledger import Change, Ledger
from util import git_ts, iso, parse_ts

FANOUT_LIMIT = 8

#: Records are separated by this so a commit subject containing a newline cannot corrupt
#: the parse. Log text is untrusted input (spec 0.2).
#:
#: The separator leads the record rather than trailing it. With --name-only git emits
#: "<format>\n\n<file>\n<file>", so a trailing separator would put each commit's filenames
#: into the *next* record -- which silently attributes every changed path to the wrong
#: commit and drops the last commit's files entirely.
_REC = "\x1e"
_FLD = "\x1f"
_FORMAT = _REC + _FLD.join(["%H", "%h", "%aI", "%an", "%ae", "%s"])


def _repos(repos_dir: Path) -> list[Path]:
    return sorted(d for d in Path(repos_dir).iterdir() if (d / ".git").is_dir())


def _run(repo: Path, *args: str) -> str:
    r = subprocess.run(["git", "-C", str(repo), *args], capture_output=True, text=True)
    if r.returncode != 0:
        raise RuntimeError("git {} failed in {}: {}".format(" ".join(args), repo, r.stderr))
    return r.stdout


def collect(ledger: Ledger, t0: datetime | str, t1: datetime | str,
            repos_dir: Path | None = None, team_of=None) -> int:
    """Write every commit in the window into the changes table. Returns rows written."""
    repos_dir = Path(repos_dir or cfg.REPOS_DIR)
    now = iso(datetime.utcnow())
    written = 0

    for repo in _repos(repos_dir):
        out = _run(
            repo, "log", "--no-merges",
            "--since", git_ts(t0), "--until", git_ts(t1),
            "--format=" + _FORMAT, "--name-only",
        )
        for record in out.split(_REC):
            record = record.strip("\n")
            if not record.strip():
                continue
            header, _, files_blob = record.partition("\n")
            fields = header.split(_FLD)
            if len(fields) < 6:
                continue
            sha, short, ts, author, email, subject = fields[:6]
            files = [f for f in files_blob.splitlines() if f.strip()]
            team = team_of(repo.name) if team_of else None

            if not files or len(files) > FANOUT_LIMIT:
                summary = subject if not files else "{} ({} files)".format(subject, len(files))
                written += _emit(ledger, repo.name, short, sha, ts, author, email, team,
                                 None, summary, now)
                continue
            for path in files:
                written += _emit(ledger, repo.name, short, sha, ts, author, email, team,
                                 path, subject, now)
    return written


def _emit(ledger: Ledger, repo: str, short: str, sha: str, ts: str, author: str,
          email: str, team: str | None, path: str | None, subject: str, now: str) -> int:
    cid = "git:{}:{}".format(repo, short) + (":" + path if path else "")
    ledger.upsert_change(Change(
        id=cid,
        ts=parse_ts(ts),
        source="git",
        author=author,
        team=team,
        repo=repo,
        path=path,
        summary=subject[:200],
        diff_ref="git:{}:{}:{}".format(repo, sha, path or ""),
        evidenced=True,
        raw={"sha": sha, "email": email},
        collected_at=now,
    ))
    return 1
