"""The structured objects that move between Proposer, Gate, Verifier and report.

These are plain dataclasses with no behaviour beyond serialisation. Keeping them dumb is what
lets the Gate stay a pure function of its inputs (spec 5.6).
"""
from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field
from typing import Any

#: The provenance probe, asked verbatim every time a claim is rejected under T1 (spec 2.4).
PROBE = (
    "What wrote that state? Name the commit, config edit, feature-flag toggle, "
    "schema migration, IAM change, package update or manual operation that produced it."
)


@dataclass
class Claim:
    """One structured hypothesis from the Proposer. Spec 5.5."""

    #: Ledger ids, or "EXTERNAL:<ledger_id>". A LIST: multi-cause is the normal case.
    cause_ids: list[str] = field(default_factory=list)
    #: Prose chain: cause -> ... -> symptom.
    mechanism: str = ""
    #: Anomaly ids this claim accounts for.
    explains: set[str] = field(default_factory=set)
    #: 0..1, calibrated (spec 5.8).
    confidence: float = 0.0
    #: Tool result refs backing the claim.
    evidence: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        d = asdict(self)
        d["explains"] = sorted(self.explains)
        return d

    def __str__(self) -> str:
        return json.dumps(self.to_dict(), sort_keys=True)


@dataclass
class Verdict:
    """The Gate's answer. Spec 5.6.

    `rule` records which rule fired, so gate_events can be read as a trace of *why* the
    investigation was pushed deeper rather than just that it was.
    """

    accepted: bool
    reason: str
    next_question: str | None = None
    rule: str = ""            # T1 | T2 | T3 | timing | ""

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class Hop:
    """One step in a configuration resolution chain. Spec 5.4.3."""

    source_type: str          # configmap|secret|env|helm_values|terraform|code_default|cli_flag
    source_ref: str           # repo:path:line, or a k8s object ref
    found: bool
    value: str | None
    note: str = ""

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class Proof:
    """The Verifier's output. Spec 5.7."""

    tier: str                 # T0..T4
    passed: bool
    observed: str
    expected: str
    command: str

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class DecisionPackage:
    """The deliverable handed to the on-call engineer. Spec 5.8.

    Every field is mandatory. `validate()` returns the list of missing ones; a report that
    fails validation is a bug in the reporter, not an acceptable partial result. Note that
    rollback_hazard and security_implications must be present *even when the answer is
    "none"* -- silence there is indistinguishable from not having checked.
    """

    incident_id: str
    status: str                              # resolved | unresolved | no_fault
    cause_set: list[dict] = field(default_factory=list)
    mechanism: str = ""
    short_term: str = ""
    long_term: str = ""
    order_of_operations: list[str] = field(default_factory=list)
    rollback_hazard: str = ""
    blast_radius: dict = field(default_factory=dict)
    security_implications: str = ""
    confidence: dict = field(default_factory=dict)   # value / would_change_my_mind / cheapest_query
    verification: dict = field(default_factory=dict)  # tier / command / observed
    owners: list[dict] = field(default_factory=list)
    unexplained: list[dict] = field(default_factory=list)
    #: Present only when status == "unresolved": ranked hypotheses + cheapest query (T4).
    frontier: dict = field(default_factory=dict)

    REQUIRED = (
        "cause_set", "mechanism", "short_term", "long_term", "order_of_operations",
        "rollback_hazard", "blast_radius", "security_implications", "confidence",
        "verification", "owners",
    )

    def validate(self) -> list[str]:
        """Return the names of mandatory fields that are empty. Empty list means valid."""
        if self.status == "no_fault":
            # A no-fault finding must still say what it looked at and what would change it,
            # otherwise it is indistinguishable from not having looked.
            missing = []
            if not self.mechanism:
                missing.append("mechanism")
            for k in ("would_change_my_mind", "cheapest_disambiguating_query"):
                if not self.confidence.get(k):
                    missing.append("confidence." + k)
            if self.cause_set:
                missing.append("cause_set must be empty for a no-fault finding")
            return missing
        if self.status == "unresolved":
            # T4 has its own contract (spec 2.1): ranked hypotheses, residue, cheapest query.
            missing = [k for k in ("ranked_hypotheses", "residue", "cheapest_query")
                       if not self.frontier.get(k)]
            return ["frontier." + m for m in missing]
        missing = []
        for name in self.REQUIRED:
            v = getattr(self, name)
            # `unexplained` may legitimately be empty; the fields above may not.
            if v in (None, "", [], {}):
                missing.append(name)
        return missing

    def to_dict(self) -> dict:
        return asdict(self)

    def to_json(self, indent: int = 2) -> str:
        return json.dumps(self.to_dict(), indent=indent, sort_keys=True, default=_default)


def _default(o: Any):
    if isinstance(o, set):
        return sorted(o)
    raise TypeError("not JSON serialisable: {!r}".format(type(o)))
