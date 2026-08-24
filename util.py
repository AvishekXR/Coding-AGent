"""Small shared helpers. Deliberately tiny -- anything that grows belongs in a real module.

The timestamp helpers here exist because of a genuine trap documented in DECISIONS.md D-006:
`git log --since/--until` interpret a bare ISO timestamp in the *machine's local timezone*.
On a machine at UTC+05:45 that silently shifts every window query by 5.75 hours and returns
an empty change list -- and an empty change list makes the agent look broken for a reason
that has nothing to do with the agent. Every timestamp handed to git goes through `git_ts()`.
"""
from __future__ import annotations

from datetime import datetime, timezone

#: The world's internal clock is naive and always UTC. Awareness is added only at the
#: boundary with tools that care (git). Mixing aware and naive datetimes raises TypeError,
#: so the rule is: naive everywhere inside, explicit UTC on the way out.
UTC = timezone.utc


def git_ts(dt: datetime | str) -> str:
    """Format a timestamp unambiguously for git's --since/--until/--date arguments."""
    if isinstance(dt, str):
        dt = parse_ts(dt)
    if dt.tzinfo is not None:
        dt = dt.astimezone(UTC).replace(tzinfo=None)
    return dt.strftime("%Y-%m-%dT%H:%M:%S") + "+00:00"


def parse_ts(s: str | datetime) -> datetime:
    """Parse an ISO timestamp to a naive-UTC datetime, accepting 'Z' and offsets."""
    if isinstance(s, datetime):
        return s.replace(tzinfo=None) if s.tzinfo is None else s.astimezone(UTC).replace(tzinfo=None)
    s = s.strip()
    if s.endswith("Z"):
        s = s[:-1] + "+00:00"
    dt = datetime.fromisoformat(s)
    if dt.tzinfo is not None:
        dt = dt.astimezone(UTC).replace(tzinfo=None)
    return dt


def iso(dt: datetime) -> str:
    """Canonical string form used as a primary key component and in every report."""
    return parse_ts(dt).isoformat()


def hhmm(dt: datetime | str) -> str:
    return parse_ts(dt).strftime("%H:%M")


def approx_tokens(text: str) -> int:
    """Cheap token estimate for the bounded-output rules (spec 0.2, 5.3).

    Four characters per token is the usual English rule of thumb. It is an estimate, so every
    budget that uses it is enforced with headroom rather than at the exact boundary.
    """
    return (len(text) + 3) // 4
