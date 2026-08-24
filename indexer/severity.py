"""Severity and Anomaly -- the vocabulary the Gate's closure rule is written in.

Kept in its own module so that `agent/gate.py` can import the types without importing the
detection logic. The Gate must remain a pure function of its inputs; pulling in the causal
indexer would give it a path to telemetry it has no business touching.

DECISIONS.md D-004: severity is an ordered IntEnum rather than a float, so `>=` against the
configured threshold is total and exact, and `max()` over a residue has a well-defined winner.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from enum import IntEnum


class Severity(IntEnum):
    info = 0
    low = 1
    medium = 2
    high = 3
    critical = 4

    @staticmethod
    def parse(value: "str | int | Severity") -> "Severity":
        if isinstance(value, Severity):
            return value
        if isinstance(value, int):
            return Severity(value)
        key = str(value).strip().lower()
        if key not in Severity.__members__:
            raise ValueError(
                "unknown severity {!r}; expected one of {}".format(
                    value, ", ".join(Severity.__members__))
            )
        return Severity[key]

    def __str__(self) -> str:
        return self.name


@dataclass(frozen=True)
class Anomaly:
    """Spec 5.4.4. One observed deviation, already compressed by the causal indexer.

    `id` is what a Claim references in its `explains` set, so it must be stable across runs
    of the indexer over the same window -- otherwise a claim could never explain anything.
    """

    id: str
    entity: str
    kind: str
    first_seen: str
    magnitude: str
    severity: Severity
    evidence_ref: str
    #: Human-readable one-liner. Never raw log content (spec 0.2).
    detail: str = ""

    def to_dict(self) -> dict:
        return {
            "id": self.id, "entity": self.entity, "kind": self.kind,
            "first_seen": self.first_seen, "magnitude": self.magnitude,
            "severity": str(self.severity), "evidence_ref": self.evidence_ref,
            "detail": self.detail,
        }

    @property
    def sort_key(self) -> tuple:
        """Total ordering for deterministic residue selection (D-004).

        Highest severity first, then earliest onset, then id. Without the tie-breakers the
        Gate's next question could vary between identical runs, which would make the gate
        trace unreproducible and the rejection sequence untestable.
        """
        return (-int(self.severity), self.first_seen, self.id)


def worst(anomalies) -> Anomaly | None:
    """The anomaly that should drive the next question. Deterministic on ties."""
    items = list(anomalies)
    if not items:
        return None
    return sorted(items, key=lambda a: a.sort_key)[0]
