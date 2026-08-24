"""The change ledger. Spec sections 5.1 and 6.

The single highest-leverage asset in the system. It answers one question: what did any human
do anywhere in this organisation between two timestamps?

`lookup()` is the function the Gate calls, and its contract is the load-bearing one in the
whole codebase: it returns a row **only** for a human-authored change. If it can be made to
return something for a machine state, rule T1 collapses and the system reverts to being an
ordinary correlation engine.
"""
from __future__ import annotations

import json
import sqlite3
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path

import config as cfg
from util import iso, parse_ts

SCHEMA_PATH = Path(__file__).resolve().parent / "schema.sql"

#: Sources whose rows represent a human-authored change (spec 0.4). `external` is included
#: but is subject to the extra evidencing rule in 5.6.
HUMAN_SOURCES = {"git", "iac", "k8s", "cloudtrail", "flag", "package"}
EXTERNAL_SOURCE = "external"


@dataclass(frozen=True)
class Change:
    """One row of the ledger. Matches the Change contract in spec 5.4.1."""

    id: str
    ts: datetime
    source: str
    author: str | None
    team: str | None
    repo: str | None
    path: str | None
    summary: str
    diff_ref: str | None
    evidenced: bool = True
    raw: dict | None = None
    collected_at: str | None = None

    @property
    def is_external(self) -> bool:
        return self.source == EXTERNAL_SOURCE

    def to_dict(self, include_raw: bool = False) -> dict:
        d = {
            "id": self.id,
            "ts": iso(self.ts),
            "source": self.source,
            "author": self.author,
            "team": self.team,
            "repo": self.repo,
            "path": self.path,
            "summary": self.summary,
            "diff_ref": self.diff_ref,
        }
        if self.is_external:
            d["evidenced"] = self.evidenced
        if include_raw:
            d["raw"] = self.raw
        return d


@dataclass(frozen=True)
class Mention:
    """Spec 5.4.2."""

    repo: str
    path: str
    line: int
    snippet: str
    kind: str
    team: str | None = None
    last_modified: str | None = None

    def to_dict(self) -> dict:
        return {
            "repo": self.repo, "path": self.path, "line": self.line,
            "snippet": self.snippet, "kind": self.kind, "team": self.team,
            "last_modified": self.last_modified,
        }


def _row_to_change(r: sqlite3.Row) -> Change:
    return Change(
        id=r["id"], ts=parse_ts(r["ts"]), source=r["source"], author=r["author"],
        team=r["team"], repo=r["repo"], path=r["path"], summary=r["summary"],
        diff_ref=r["diff_ref"], evidenced=bool(r["evidenced"]),
        raw=json.loads(r["raw"]) if r["raw"] else None,
        collected_at=r["collected_at"],
    )


class Ledger:
    def __init__(self, path: Path | None = None):
        self.path = Path(path or cfg.LEDGER_DB)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.conn = sqlite3.connect(self.path)
        self.conn.row_factory = sqlite3.Row
        self.conn.executescript(SCHEMA_PATH.read_text(encoding="utf-8"))

    def close(self) -> None:
        self.conn.close()

    def __enter__(self) -> "Ledger":
        return self

    def __exit__(self, *exc) -> None:
        self.conn.commit()
        self.close()

    # -- writing --------------------------------------------------------------
    def upsert_change(self, c: Change) -> None:
        self.conn.execute(
            """INSERT INTO changes
                 (id, ts, source, author, team, repo, path, summary, diff_ref,
                  evidenced, raw, collected_at)
               VALUES (?,?,?,?,?,?,?,?,?,?,?,?)
               ON CONFLICT(id) DO UPDATE SET
                 ts=excluded.ts, source=excluded.source, author=excluded.author,
                 team=excluded.team, repo=excluded.repo, path=excluded.path,
                 summary=excluded.summary, diff_ref=excluded.diff_ref,
                 evidenced=excluded.evidenced, raw=excluded.raw,
                 collected_at=excluded.collected_at""",
            (c.id, iso(c.ts), c.source, c.author, c.team, c.repo, c.path, c.summary,
             c.diff_ref, int(c.evidenced), json.dumps(c.raw) if c.raw else None,
             c.collected_at or iso(datetime.utcnow())),
        )

    def upsert_mention(self, literal: str, m: Mention) -> None:
        self.conn.execute(
            """INSERT OR REPLACE INTO mentions
                 (literal, repo, path, line, snippet, kind, indexed_at)
               VALUES (?,?,?,?,?,?,?)""",
            (literal, m.repo, m.path, m.line, m.snippet, m.kind, iso(datetime.utcnow())),
        )

    def set_ownership(self, pattern: str, team: str, oncall: str, slack: str,
                      escalation: str) -> None:
        self.conn.execute(
            """INSERT OR REPLACE INTO ownership (pattern, team, oncall, slack, escalation)
               VALUES (?,?,?,?,?)""",
            (pattern, team, oncall, slack, escalation),
        )

    def commit(self) -> None:
        self.conn.commit()

    def clear_changes(self) -> None:
        """Collectors are re-runnable; a full re-collect starts from an empty table."""
        self.conn.execute("DELETE FROM changes")

    # -- reading --------------------------------------------------------------
    def lookup(self, change_id: str) -> Change | None:
        """Resolve a claimed cause id to a ledger row, or None.

        THE load-bearing function for rule T1 (spec 5.6). Returning None is how the Gate
        learns that a claimed cause is machine state rather than something a human did.

        The `EXTERNAL:` prefix is accepted per the Claim contract in 5.5.
        """
        cid = change_id[len("EXTERNAL:"):] if change_id.startswith("EXTERNAL:") else change_id
        r = self.conn.execute("SELECT * FROM changes WHERE id = ?", (cid,)).fetchone()
        return _row_to_change(r) if r else None

    def changes_between(self, t0: datetime | str, t1: datetime | str,
                        sources: list[str] | None = None,
                        repos: list[str] | None = None,
                        teams: list[str] | None = None,
                        limit: int = 200) -> list[Change]:
        q = ["SELECT * FROM changes WHERE ts >= ? AND ts <= ?"]
        args: list = [iso(parse_ts(t0)), iso(parse_ts(t1))]
        for col, vals in (("source", sources), ("repo", repos), ("team", teams)):
            if vals:
                q.append("AND {} IN ({})".format(col, ",".join("?" * len(vals))))
                args.extend(vals)
        q.append("ORDER BY ts ASC LIMIT ?")
        args.append(limit)
        rows = self.conn.execute(" ".join(q), args).fetchall()
        return [_row_to_change(r) for r in rows]

    def count_between(self, t0: datetime | str, t1: datetime | str) -> int:
        return self.conn.execute(
            "SELECT COUNT(*) FROM changes WHERE ts >= ? AND ts <= ?",
            (iso(parse_ts(t0)), iso(parse_ts(t1))),
        ).fetchone()[0]

    def group_counts(self, t0: datetime | str, t1: datetime | str) -> dict:
        """Counts grouped by source and team, for the over-limit path in spec 5.4.1."""
        out: dict[str, dict[str, int]] = {"by_source": {}, "by_team": {}}
        for col, key in (("source", "by_source"), ("team", "by_team")):
            rows = self.conn.execute(
                "SELECT {c}, COUNT(*) n FROM changes WHERE ts >= ? AND ts <= ? "
                "GROUP BY {c} ORDER BY n DESC".format(c=col),
                (iso(parse_ts(t0)), iso(parse_ts(t1))),
            ).fetchall()
            out[key] = {(r[0] or "unknown"): r[1] for r in rows}
        return out

    def who_mentions(self, literal: str, kinds: list[str] | None = None,
                     limit: int = 100) -> list[Mention]:
        q = ["SELECT * FROM mentions WHERE literal = ?"]
        args: list = [literal]
        if kinds:
            q.append("AND kind IN ({})".format(",".join("?" * len(kinds))))
            args.extend(kinds)
        q.append("ORDER BY repo, path, line LIMIT ?")
        args.append(limit)
        rows = self.conn.execute(" ".join(q), args).fetchall()
        out = []
        for r in rows:
            team = self.owner_of(r["repo"])
            out.append(Mention(
                repo=r["repo"], path=r["path"], line=r["line"], snippet=r["snippet"],
                kind=r["kind"], team=(team or {}).get("team"), last_modified=r["indexed_at"],
            ))
        return out

    def literals(self) -> list[str]:
        rows = self.conn.execute("SELECT DISTINCT literal FROM mentions").fetchall()
        return [r[0] for r in rows]

    def owner_of(self, path_or_repo_or_service: str) -> dict | None:
        """Spec 5.4.5. Exact pattern match first, then longest prefix."""
        key = (path_or_repo_or_service or "").strip()
        r = self.conn.execute(
            "SELECT * FROM ownership WHERE pattern = ?", (key,)
        ).fetchone()
        if r is None:
            head = key.split("/")[0].split(":")[0]
            r = self.conn.execute(
                "SELECT * FROM ownership WHERE pattern = ?", (head,)
            ).fetchone()
        if r is None:
            return None
        return {"team": r["team"], "oncall": r["oncall"], "slack": r["slack"],
                "escalation": r["escalation"]}

    # -- incidents, runs, gate events ----------------------------------------
    def upsert_incident(self, incident_id: str, opened_at: str, first_symptom_ts: str,
                        window_start: str, window_end: str, alert: str,
                        status: str = "open") -> None:
        self.conn.execute(
            """INSERT OR REPLACE INTO incidents
                 (id, opened_at, first_symptom_ts, window_start, window_end, alert, status)
               VALUES (?,?,?,?,?,?,?)""",
            (incident_id, opened_at, first_symptom_ts, window_start, window_end,
             alert, status),
        )

    def log_gate_event(self, run_id: str, step: int, accepted: bool, reason: str,
                       next_question: str | None, claim: str, rule: str = "") -> None:
        self.conn.execute(
            """INSERT INTO gate_events
                 (run_id, step, accepted, reason, next_question, claim, rule)
               VALUES (?,?,?,?,?,?,?)""",
            (run_id, step, int(accepted), reason, next_question, claim, rule),
        )
        self.conn.commit()

    def gate_events(self, run_id: str) -> list[dict]:
        rows = self.conn.execute(
            "SELECT * FROM gate_events WHERE run_id = ? ORDER BY step", (run_id,)
        ).fetchall()
        return [dict(r) for r in rows]

    def log_audit(self, run_id: str, incident_id: str, identity: str, tool: str,
                  args: str, outcome: str, tokens: int = 0) -> None:
        self.conn.execute(
            """INSERT INTO audit_log
                 (run_id, incident_id, ts, identity, tool, args, outcome, tokens)
               VALUES (?,?,?,?,?,?,?,?)""",
            (run_id, incident_id, iso(datetime.utcnow()), identity, tool, args,
             outcome, tokens),
        )
        self.conn.commit()

    def audit_log(self, run_id: str) -> list[dict]:
        rows = self.conn.execute(
            "SELECT * FROM audit_log WHERE run_id = ? ORDER BY id", (run_id,)
        ).fetchall()
        return [dict(r) for r in rows]

    def save_run(self, run: dict) -> None:
        self.conn.execute(
            """INSERT OR REPLACE INTO runs
                 (id, incident_id, started_at, steps, tokens, cost_usd, wall_seconds,
                  terminated_as, cause_ids, verification_tier, confidence, score,
                  depth_compliant, notes)
               VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
            (run["id"], run.get("incident_id"), run.get("started_at"), run.get("steps"),
             run.get("tokens"), run.get("cost_usd"), run.get("wall_seconds"),
             run.get("terminated_as"), json.dumps(run.get("cause_ids") or []),
             run.get("verification_tier"), run.get("confidence"), run.get("score"),
             int(bool(run.get("depth_compliant"))), run.get("notes")),
        )
        self.conn.commit()
