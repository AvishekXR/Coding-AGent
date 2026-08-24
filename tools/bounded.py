"""The bounded-output rule. Spec 0.2:

    Every tool returns bounded output: 2,000 tokens maximum, or a handle plus a summary.
    No tool ever returns raw log content. Violating this reproduces the documented
    context-exhaustion failure mode.

This is enforced here, once, rather than trusted to each tool. A tool that would exceed its
budget returns the first page, a `_handle` for the rest, and a `_summary` describing what was
withheld -- explicitly *never* a silent truncation, which is the failure mode spec 5.4.1
calls out by name.
"""
from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from typing import Any

import config as cfg
from util import approx_tokens


class RawLogContent(Exception):
    """Raised when a tool tries to return raw log lines. Spec 0.2 forbids it outright."""


@dataclass
class HandleStore:
    """Holds withheld payloads for the current run so the agent can page through them.

    In-process and per-run by design: a handle is a way to fetch more of something you just
    asked for, not a durable cache that could go stale between incidents (spec 5.1.2).
    """

    _items: dict[str, Any] = field(default_factory=dict)

    def put(self, payload: Any) -> str:
        blob = json.dumps(payload, sort_keys=True, default=str)
        h = "h-" + hashlib.sha256(blob.encode("utf-8")).hexdigest()[:12]
        self._items[h] = payload
        return h

    def get(self, handle: str) -> Any | None:
        return self._items.get(handle)

    def __len__(self) -> int:
        return len(self._items)


def token_cost(payload: Any) -> int:
    return approx_tokens(json.dumps(payload, sort_keys=True, default=str))


def bound_list(items: list[dict], store: HandleStore, summary: dict | None = None,
               max_tokens: int | None = None, note: str = "") -> dict:
    """Return at most `max_tokens` worth of `items`, plus a handle for the remainder.

    The returned envelope always states the true total, so the agent can never mistake a
    page for the whole answer.
    """
    max_tokens = max_tokens or cfg.DEFAULT.max_tool_tokens
    total = len(items)

    kept: list[dict] = []
    running = token_cost({"items": [], "total": total, "summary": summary or {}})
    for item in items:
        cost = token_cost(item)
        if running + cost > max_tokens and kept:
            break
        kept.append(item)
        running += cost

    out: dict[str, Any] = {"items": kept, "total": total, "returned": len(kept)}
    if summary:
        out["summary"] = summary
    if note:
        out["note"] = note
    if len(kept) < total:
        out["_truncated"] = True
        out["_handle"] = store.put(items)
        out["_summary"] = summary or {"withheld": total - len(kept)}
        out["note"] = (note + " " if note else "") + (
            "{} of {} items returned; use get_handle({}) for the rest. "
            "This is a page, not the whole answer.".format(
                len(kept), total, out["_handle"])
        )
    return out


def bound_text(text: str, store: HandleStore, max_tokens: int | None = None,
               kind: str = "text") -> dict:
    """Bound a text payload (a diff, a chain). Never used for log lines."""
    max_tokens = max_tokens or cfg.DEFAULT.max_tool_tokens
    if approx_tokens(text) <= max_tokens:
        return {kind: text, "truncated": False}

    # Cut on a line boundary so the returned fragment is still readable.
    budget_chars = max_tokens * 4
    head = text[:budget_chars]
    head = head[: head.rfind("\n") + 1] or head
    return {
        kind: head,
        "truncated": True,
        "_handle": store.put(text),
        "note": "truncated at {} of {} characters; use get_handle() for the rest".format(
            len(head), len(text)),
    }


#: Substrings that mark a payload as raw telemetry rather than a structured finding.
_LOG_MARKERS = ('"level":', '"msg":', "\tINFO\t", " INFO ", " DEBUG ", " WARN ")


def assert_not_raw_logs(payload: Any) -> None:
    """Guard the 'no tool ever returns raw log content' half of the rule.

    A heuristic, and deliberately so: it is a backstop against a future tool being written
    carelessly, not the primary defence. The primary defence is that no tool in tools/api.py
    reads the log stream at all -- logs reach the model only as compressed patterns from the
    causal indexer (spec 5.3).
    """
    blob = json.dumps(payload, default=str)
    hits = sum(1 for m in _LOG_MARKERS if m in blob)
    if hits >= 2 and blob.count('"ts"') > 20:
        raise RawLogContent(
            "tool result looks like raw log lines; logs must reach the model only as "
            "compressed patterns from the causal indexer (spec 0.2, 5.3)"
        )
