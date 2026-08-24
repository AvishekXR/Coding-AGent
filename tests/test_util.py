"""Pins the timestamp handling described in DECISIONS.md D-006."""
from __future__ import annotations

import subprocess
from datetime import datetime, timedelta, timezone

import pytest

from util import approx_tokens, git_ts, parse_ts


def test_git_ts_always_carries_an_explicit_offset():
    assert git_ts("2026-08-20T08:00:00") == "2026-08-20T08:00:00+00:00"
    assert git_ts(datetime(2026, 8, 20, 8, 0)) == "2026-08-20T08:00:00+00:00"


def test_git_ts_normalises_an_aware_timestamp_to_utc():
    aware = datetime(2026, 8, 20, 13, 45, tzinfo=timezone(timedelta(hours=5, minutes=45)))
    assert git_ts(aware) == "2026-08-20T08:00:00+00:00"


def test_parse_ts_accepts_z_and_offsets_and_returns_naive_utc():
    for s in ("2026-08-20T08:00:00Z", "2026-08-20T08:00:00+00:00",
              "2026-08-20T13:45:00+05:45", "2026-08-20T08:00:00"):
        got = parse_ts(s)
        assert got.tzinfo is None
        assert got == datetime(2026, 8, 20, 8, 0)


def test_git_window_is_timezone_independent(injected_world):
    """The regression itself: a window query must find the same commits regardless of the
    machine's timezone. A bare timestamp does not; git_ts() does."""
    world, meta = injected_world
    repo = world.repos / "platform-config"

    def count(since: str, until: str) -> int:
        out = subprocess.run(
            ["git", "-C", str(repo), "log", "--format=%H", "--since", since, "--until", until],
            capture_output=True, text=True,
        ).stdout
        return len([l for l in out.splitlines() if l.strip()])

    with_offset = count(git_ts(meta["window_start_ts"]), git_ts(meta["window_end_ts"]))
    assert with_offset >= 4, "the incident window must contain platform-config commits"

    # Documents the failure mode rather than asserting a specific wrong number: on a machine
    # at UTC the bare form happens to agree, so this only asserts the safe form is never worse.
    bare = count(meta["window_start_ts"], meta["window_end_ts"])
    assert with_offset >= bare


@pytest.mark.parametrize("text,lo,hi", [("", 0, 0), ("a" * 4000, 900, 1100)])
def test_approx_tokens_is_in_the_right_order_of_magnitude(text, lo, hi):
    assert lo <= approx_tokens(text) <= hi
