"""The seven tool contracts of spec 5.4, as a plain Python API.

`tools/server.py` exposes these same functions over MCP so that the identical interface serves
the local test environment and a real stack -- the transferability property spec 5.4 requires.
Keeping the callable core separate from the transport means tests exercise the real tool
bodies without an MCP round trip.

Three properties hold for every method here, and are tested:
  * read-only -- there is no mutation path in this file, by construction (spec 5.9.1);
  * bounded -- every result goes through tools/bounded.py (spec 0.2);
  * audited -- every call writes an audit_log row with run id, timestamp and identity (5.9.1).
"""
from __future__ import annotations

import json
import subprocess
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any, Callable

import config as cfg
from ledger.ledger import Ledger
from tools import resolve
from tools.bounded import HandleStore, assert_not_raw_logs, bound_list, bound_text, token_cost
from util import iso, parse_ts

#: The identity every tool call runs as. Deliberately not a human account and not a service
#: account with write scope (spec 5.9.1).
READ_ONLY_IDENTITY = "hisev-resolver-readonly"


class ToolError(Exception):
    """A tool failed. Spec 5.9.3: a malformed or timed-out response is recorded as unknown,
    not reasoned over. The caller must halt the chain rather than treat this as data."""


@dataclass
class ToolContext:
    """Per-run state: who is calling, for which incident, and what has been paged."""

    ledger: Ledger
    run_id: str = "adhoc"
    incident_id: str = "unknown"
    identity: str = READ_ONLY_IDENTITY
    handles: HandleStore = field(default_factory=HandleStore)
    repos: Path = field(default_factory=lambda: cfg.REPOS_DIR)
    state: Path = field(default_factory=lambda: cfg.STATE_DIR)
    #: Number of times each tool has been retried this run (spec 5.9.3).
    retries: dict[str, int] = field(default_factory=dict)
    #: Running total of tokens returned by tools, for the budget.
    tokens_returned: int = 0
    calls: list[dict] = field(default_factory=list)


def audited(name: str) -> Callable:
    """Wrap a tool so every call is logged, bounded-checked and token-counted."""

    def decorator(fn: Callable) -> Callable:
        def wrapper(self: "Tools", *args, **kwargs):
            arg_repr = json.dumps({"args": args, "kwargs": kwargs}, default=str)[:2000]
            try:
                result = fn(self, *args, **kwargs)
            except ToolError as e:
                self.ctx.retries[name] = self.ctx.retries.get(name, 0) + 1
                self.ctx.ledger.log_audit(
                    self.ctx.run_id, self.ctx.incident_id, self.ctx.identity, name,
                    arg_repr, "error", 0,
                )
                self.ctx.calls.append({"tool": name, "outcome": "error", "detail": str(e)})
                raise
            assert_not_raw_logs(result)
            cost = token_cost(result)
            self.ctx.tokens_returned += cost
            self.ctx.ledger.log_audit(
                self.ctx.run_id, self.ctx.incident_id, self.ctx.identity, name,
                arg_repr, "ok", cost,
            )
            self.ctx.calls.append({"tool": name, "outcome": "ok", "tokens": cost})
            return result

        wrapper.__name__ = fn.__name__
        wrapper.__doc__ = fn.__doc__
        wrapper.tool_name = name
        return wrapper

    return decorator


class Tools:
    """The agent's entire view of the world. Nothing else is reachable from the loop."""

    def __init__(self, ctx: ToolContext, ranker: Callable | None = None):
        self.ctx = ctx
        #: Optional list[Change] -> list[Change] reordering, injected by the causal indexer
        #: (spec 5.3, topology-weighted candidate ranking). Absent in phase 1, and the tool
        #: says so in its own output rather than pretending the order means something.
        self.ranker = ranker

    # -- 5.4.1 ---------------------------------------------------------------
    #: Absolute ceiling on rows pulled from the ledger for one window, regardless of `limit`.
    #: Exists so that a pathological window cannot exhaust memory before bounding happens.
    HARD_CEILING = 5000

    @audited("changes_between")
    def changes_between(self, t0: str, t1: str, sources: list[str] | None = None,
                        repos: list[str] | None = None, teams: list[str] | None = None,
                        limit: int = 200) -> dict:
        """What did any human do anywhere in this organisation between two timestamps?

        Over `limit`, returns counts grouped by source and team, the top-N by ranked
        proximity to the failing entity, *and a handle for the remainder*. Never truncates
        silently (spec 5.4.1) -- which means the SQL LIMIT cannot be the thing that hides the
        overflow: the full window is fetched, then ranked, then bounded.
        """
        rows = self.ctx.ledger.changes_between(
            t0, t1, sources=sources, repos=repos, teams=teams, limit=self.HARD_CEILING
        )
        total = len(rows)
        summary: dict[str, Any] = {
            "window": [iso(parse_ts(t0)), iso(parse_ts(t1))],
            "total_in_window": total,
        }

        all_items = [c.to_dict() for c in rows]
        note = ""
        if total > limit:
            ranked = self.ranker(rows) if self.ranker else rows
            all_items = [c.to_dict() for c in ranked]
            summary.update(self.ctx.ledger.group_counts(t0, t1))
            summary["ranking"] = ("topological proximity to the failing entity"
                                 if self.ranker else "first-mover order (no ranker attached)")
            kept = all_items[:limit]
            out = bound_list(kept, self.ctx.handles, summary=summary)
            # bound_list only knows about the page it was given, so the window-level
            # overflow is marked here and the *full* window goes behind the handle.
            out["_truncated"] = True
            out["_handle"] = self.ctx.handles.put(all_items)
            out["total"] = total
            out["note"] = (
                "{} of {} changes in this window returned, ranked by {}. "
                "Grouped counts are in `summary`; use get_handle({}) for the rest. "
                "This is a page, not the whole answer.".format(
                    len(out["items"]), total, summary["ranking"], out["_handle"])
            )
            return out

        return bound_list(all_items, self.ctx.handles, summary=summary, note=note)

    # -- 5.4.2 ---------------------------------------------------------------
    @audited("who_mentions")
    def who_mentions(self, literal: str, kinds: list[str] | None = None,
                     limit: int = 100) -> dict:
        """Which files, in EVERY indexed repository, mention this literal?

        Scoping to one repository defeats the purpose (spec 5.4.2), so there is deliberately
        no `repo` parameter on this tool.
        """
        ms = self.ctx.ledger.who_mentions(literal, kinds=kinds, limit=limit)
        items = [m.to_dict() for m in ms]
        by_repo: dict[str, int] = {}
        by_kind: dict[str, int] = {}
        for m in ms:
            by_repo[m.repo] = by_repo.get(m.repo, 0) + 1
            by_kind[m.kind] = by_kind.get(m.kind, 0) + 1
        return bound_list(items, self.ctx.handles, summary={
            "literal": literal, "repos": by_repo, "kinds": by_kind,
        })

    # -- 5.4.5 ---------------------------------------------------------------
    @audited("owner_of")
    def owner_of(self, path_or_repo_or_service: str) -> dict:
        owner = self.ctx.ledger.owner_of(path_or_repo_or_service)
        if owner is None:
            return {"query": path_or_repo_or_service, "team": None,
                    "note": "no ownership record; escalate to the platform on-call"}
        return dict(owner, query=path_or_repo_or_service)

    @audited("get_diff")
    def get_diff(self, change_id: str, max_lines: int = 200) -> dict:
        """Fetch the diff behind a ledger row. Handles only -- diffs are never inlined
        into a change list (spec 5.4.1: `diff_ref` is a handle, never the diff itself)."""
        change = self.ctx.ledger.lookup(change_id)
        if change is None:
            raise ToolError("no ledger row with id {!r}".format(change_id))
        ref = change.diff_ref or ""
        if not ref.startswith("git:"):
            return {"change_id": change_id, "diff": "", "truncated": False,
                    "note": "no diff available for source {!r}".format(change.source)}

        _, repo, sha, path = (ref.split(":", 3) + ["", "", ""])[:4]
        args = ["show", "--format=%H%n%an%n%aI%n%s%n", "--unified=3", sha]
        if path:
            args += ["--", path]
        try:
            out = subprocess.run(
                ["git", "-C", str(self.ctx.repos / repo), *args],
                capture_output=True, text=True, timeout=30,
            )
        except subprocess.TimeoutExpired as e:
            raise ToolError("git show timed out for {}".format(change_id)) from e
        if out.returncode != 0:
            raise ToolError("git show failed for {}: {}".format(change_id, out.stderr[:200]))

        lines = out.stdout.splitlines()
        clipped = lines[:max_lines]
        payload = bound_text("\n".join(clipped), self.ctx.handles, kind="diff")
        payload["change_id"] = change_id
        payload["truncated"] = payload.get("truncated", False) or len(lines) > max_lines
        return payload

    # -- 5.4.3 ---------------------------------------------------------------
    @audited("why_this_value")
    def why_this_value(self, key: str, service: str, at: str | None = None,
                       kind: str = "env") -> dict:
        """Where did this configuration value actually come from, hop by hop?

        The resolution-chain tool. See tools/resolve.py for why this is the tool that cracks
        the reference incident: it is the only retrieval path here that is *directional*, so
        it is the only one that can report a hop which was supposed to supply a value and did
        not. That absence has no audit event and no metric.
        """
        out = resolve.build_chain(self.ctx.ledger, self.ctx.repos, key, service)
        out["at"] = at
        out["kind"] = kind
        return out

    @audited("keys_read_by")
    def keys_read_by(self, service: str) -> dict:
        """Configuration keys this service's source reads. Used to pick what to ask about."""
        keys = resolve.keys_read_by(self.ctx.repos, service)
        rows = self.ctx.ledger.conn.execute(
            "SELECT DISTINCT key, value FROM config_state WHERE service = ?", (service,)
        ).fetchall()
        supplied = {r[0]: r[1] for r in rows}
        return {
            "service": service, "keys_read": keys,
            "keys_supplied": sorted(supplied),
            # The values name this service's dependencies -- the tables, queues and endpoints
            # it talks to. A change to whatever file defines one of them can reach this
            # service without mentioning it.
            "supplied_values": supplied,
            # The interesting set: read by code, supplied by nothing.
            "read_but_not_supplied": sorted(set(keys) - set(supplied)),
        }

    # -- paging --------------------------------------------------------------
    @audited("get_handle")
    def get_handle(self, handle: str, offset: int = 0, limit: int = 50) -> dict:
        """Page through a payload that a previous call had to withhold."""
        payload = self.ctx.handles.get(handle)
        if payload is None:
            raise ToolError("unknown handle {!r}".format(handle))
        if isinstance(payload, str):
            return bound_text(payload[offset:], self.ctx.handles)
        window = payload[offset: offset + limit]
        return {"items": window, "total": len(payload), "offset": offset,
                "returned": len(window)}

    # -- introspection used by the runner and the safety layer ---------------
    def tool_names(self) -> list[str]:
        return sorted(
            getattr(getattr(self, n), "tool_name")
            for n in dir(self)
            if not n.startswith("_") and hasattr(getattr(self, n, None), "tool_name")
        )
