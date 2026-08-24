"""THE GATE (L3). Spec section 5.6. The core component.

    An investigation may terminate only when the Termination Rule permits it, and the check
    is performed in code, not requested in a prompt.

This is the only novel component in the system and the only place termination is decided.
Everything else here is conventional engineering in service of it.

Four invariants, each enforced by a test in tests/test_gate.py:

  1. **No model call and no network call.** Not a style preference. The single property that
     makes this project able to iterate fast is that "did the investigation terminate at a
     human-authored change?" is a boolean an automated harness can check without a human
     adjudicator (2.5). A Gate that asks a model to judge sufficiency destroys that property
     and reproduces the exact failure of 1.3, where the agent has no test for sufficiency and
     so either accepts the first plausible thing or accumulates plausible things for ever.
  2. **`cause_ids` is a list and multi-cause acceptance is the normal path.** A Gate that only
     ever accepts single causes fails the reference incident.
  3. **Every rejection carries a concrete next question.** A rejection without a question
     stalls the loop; there is an assertion for it at the bottom of `gate()`.
  4. **Pure function.** No mutation of any argument, no I/O beyond `ledger.lookup`.

If you find yourself wanting to make the Gate smarter, the judgement belongs in the Proposer
and the Gate checks its output.
"""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import Iterable, Protocol, Sequence

from agent.types import PROBE, Claim, Verdict
from indexer.severity import Anomaly, Severity, worst

#: Which rules are active. Exists so the build order in spec 11 can be demonstrated rather
#: than described: phase 2 runs ("T1",) and must reject the first two claims of the reference
#: trace; phase 3 adds ("T2", "timing") and must then reject a third. See DECISIONS.md D-008.
ALL_RULES = ("T1", "T2", "timing")

#: Reason strings are part of the contract: the evaluation harness and the gate_events trace
#: are read by matching on them, so they must not drift.
R_NO_CAUSE = "no cause named"
R_MACHINE_STATE = "cause is machine state, not a human-authored change"
R_EXTERNAL_UNEVIDENCED = "external cause asserted but not evidenced by a ledger row"
R_INCOMPLETE = "incomplete: unexplained anomaly remains"
R_POSTDATES = "cause postdates first symptom"
R_ACCEPTED = "provenance terminal and closure reached"

Q_EXTERNAL = "Which recorded external event? Provide its ledger id."
Q_PRECEDES = "Find a change that precedes the first symptom."


class LedgerLike(Protocol):
    """All the Gate is allowed to know about the ledger."""

    def lookup(self, change_id: str): ...


@dataclass(frozen=True)
class IncidentRef:
    """The minimum the Gate needs about the incident. Deliberately not the whole record."""

    id: str
    first_symptom_ts: datetime


def gate(claim: Claim, residue: Iterable[Anomaly], ledger: LedgerLike,
         incident: IncidentRef, cfg, rules: Sequence[str] = ALL_RULES) -> Verdict:
    """Decide whether this claim may terminate the investigation.

    Returns a Verdict. `accepted=False` always carries a `next_question`, which becomes the
    next thing the investigation asks -- so a rejection moves the loop forward rather than
    ending it.
    """
    verdict = _gate(claim, residue, ledger, incident, cfg, rules)
    # Invariant 3, asserted rather than trusted: a rejection with no question would stall
    # the control loop silently, which is far harder to debug than a crash here.
    assert verdict.accepted or verdict.next_question, \
        "rejection without a next question would stall the loop"
    return verdict


def _gate(claim: Claim, residue: Iterable[Anomaly], ledger: LedgerLike,
          incident: IncidentRef, cfg, rules: Sequence[str]) -> Verdict:

    # ---- Rule 1: provenance terminal (T1) --------------------------------
    # Machine state is never terminal. A machine state has no author, no rollback, no owner
    # to page and no fix, so an investigation that stops there has not finished.
    if "T1" in rules:
        if not claim.cause_ids:
            return Verdict(False, R_NO_CAUSE, PROBE, rule="T1")

        resolved = [ledger.lookup(cid) for cid in claim.cause_ids]
        if any(r is None for r in resolved):
            return Verdict(False, R_MACHINE_STATE, PROBE, rule="T1")

        for r in resolved:
            # The model may not assert that something outside the organisation broke. An
            # external cause counts only when a collector recorded it.
            if r.source == "external" and not r.evidenced:
                return Verdict(False, R_EXTERNAL_UNEVIDENCED, Q_EXTERNAL, rule="T1")
    else:
        resolved = [ledger.lookup(cid) for cid in claim.cause_ids]

    # ---- Rule 2: explanatory closure (T2) --------------------------------
    # The residue is what blocks premature termination. A claim that names a real human
    # change but leaves a significant anomaly unexplained is incomplete, and this is what
    # forces the discovery of second and third causes.
    if "T2" in rules:
        threshold = Severity.parse(cfg.min_severity)
        left = [
            a for a in residue
            if a.id not in claim.explains and a.severity >= threshold
        ]
        if left:
            top = worst(left)
            return Verdict(
                False, R_INCOMPLETE,
                "What explains {}: {}?".format(top.entity, top.kind),
                rule="T2",
            )

    # ---- Rule 3: timing sanity -------------------------------------------
    if "timing" in rules:
        for r in resolved:
            if r is not None and r.ts > incident.first_symptom_ts:
                return Verdict(False, R_POSTDATES, Q_PRECEDES, rule="timing")

    return Verdict(True, R_ACCEPTED, None, rule="T1+T2")


# --- 5.6.1 -------------------------------------------------------------------
def prune(candidates, residue: Iterable[Anomaly]):
    """Discard any candidate that would reduce no residue. Spec 5.6.1.

    The counter-measure to the over-investigation failure in 1.3. A co-occurring but innocent
    deployment explains nothing, therefore it is never followed. Candidates are eliminated by
    the residual test, never expanded by curiosity.

    `candidates` are objects with a `would_explain` set of anomaly ids.
    """
    ids = {a.id for a in residue}
    return [c for c in candidates if set(getattr(c, "would_explain", ()) or ()) & ids]


def grounded(claim: Claim, ledger: LedgerLike) -> bool:
    """Does every cause in this claim resolve to a recorded human-authored change?

    Only a grounded claim is permitted to reduce the residue. The control flow in spec 4.3
    subtracts `claim.explains` on the rejected path, and for a claim that named real changes
    but missed one that is exactly right -- it is what makes the investigation converge.

    But a claim rejected as machine state has not *explained* anything. It restated the
    anomaly as its own cause: "the metric dropped because the metric dropped." Subtracting
    that would quietly delete the residue which the Residue Rule exists to act on, and the
    Gate would then accept a single-cause answer for want of anything left to object to --
    reaching the right shape of answer for entirely the wrong reason. See DECISIONS.md D-010.
    """
    if not claim.cause_ids:
        return False
    return all(ledger.lookup(cid) is not None for cid in claim.cause_ids)


def residue_after(residue: Iterable[Anomaly], claim: Claim) -> list[Anomaly]:
    """The residue that survives a claim. Used by the loop after a rejection."""
    return [a for a in residue if a.id not in claim.explains]


def significant(residue: Iterable[Anomaly], cfg) -> list[Anomaly]:
    """Residue at or above the configured severity threshold."""
    threshold = Severity.parse(cfg.min_severity)
    return [a for a in residue if a.severity >= threshold]
