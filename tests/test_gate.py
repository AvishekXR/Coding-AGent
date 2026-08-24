"""The Gate. Spec 5.6 and Appendix E.

The Gate is the only novel component in this system, so it gets the most hostile tests. These
cover the four invariants of 5.6.2 plus the rule-by-rule behaviour of 5.6, using a stub ledger
so the Gate is exercised as the pure function it is meant to be.
"""
from __future__ import annotations

import ast
import socket
from dataclasses import dataclass, replace
from datetime import datetime, timedelta

import pytest

import config as cfg
from agent.gate import (
    ALL_RULES, R_ACCEPTED, R_EXTERNAL_UNEVIDENCED, R_INCOMPLETE, R_MACHINE_STATE,
    R_NO_CAUSE, R_POSTDATES, IncidentRef, gate, prune, residue_after, significant,
)
from agent.types import PROBE, Claim
from indexer.severity import Anomaly, Severity

SYMPTOM = datetime(2026, 8, 20, 9, 35)
INCIDENT = IncidentRef(id="test", first_symptom_ts=SYMPTOM)


@dataclass(frozen=True)
class Row:
    """Minimal stand-in for a ledger row."""

    id: str
    ts: datetime
    source: str = "git"
    evidenced: bool = True


class StubLedger:
    """Resolves only the ids it was given. Everything else is machine state, by definition."""

    def __init__(self, rows=()):
        self.rows = {r.id: r for r in rows}
        self.lookups: list[str] = []

    def lookup(self, change_id):
        self.lookups.append(change_id)
        cid = change_id[len("EXTERNAL:"):] if change_id.startswith("EXTERNAL:") else change_id
        return self.rows.get(cid)


def anomaly(aid, severity="high", entity="svc-a", kind="metric_drop", first_seen="09:35"):
    return Anomaly(
        id=aid, entity=entity, kind=kind, first_seen=first_seen, magnitude="-94%",
        severity=Severity.parse(severity), evidence_ref="ref:" + aid,
    )


HUMAN = Row("chg-1", SYMPTOM - timedelta(minutes=23))
HUMAN2 = Row("chg-2", SYMPTOM - timedelta(minutes=1))
LEDGER = StubLedger([HUMAN, HUMAN2])


# --- Rule 1: provenance terminal (T1) ----------------------------------------
def test_no_cause_named_is_rejected_with_the_probe():
    v = gate(Claim(), [], LEDGER, INCIDENT, cfg.DEFAULT)
    assert not v.accepted
    assert v.reason == R_NO_CAUSE
    assert v.next_question == PROBE
    assert v.rule == "T1"


def test_machine_state_is_rejected_with_the_probe():
    """The central behaviour of the whole system.

    Every statement a claim like this makes may be true. It is still rejected, because a
    machine state has no author, no rollback and no owner to page.
    """
    v = gate(Claim(cause_ids=["the queue is full"]), [], LEDGER, INCIDENT, cfg.DEFAULT)
    assert not v.accepted
    assert v.reason == R_MACHINE_STATE
    assert v.next_question == PROBE
    assert v.rule == "T1"


def test_the_probe_asks_the_one_question_that_walks_the_ladder_down():
    """Spec 2.4 -- the probe wording is load-bearing, not decorative."""
    for token in ("commit", "config edit", "feature-flag toggle", "schema migration",
                  "IAM change", "package update", "manual operation"):
        assert token in PROBE
    assert PROBE.startswith("What wrote that state?")


def test_a_partially_resolvable_cause_set_is_still_machine_state():
    """One real change plus one machine state is not a pass. `any(r is None)` is the check."""
    v = gate(Claim(cause_ids=["chg-1", "the disk is full"]), [], LEDGER, INCIDENT, cfg.DEFAULT)
    assert not v.accepted and v.reason == R_MACHINE_STATE


def test_external_cause_without_evidence_is_rejected():
    """Spec 5.6.2: the model may not assert an external incident without a ledger row."""
    led = StubLedger([Row("ext-1", SYMPTOM - timedelta(hours=1),
                          source="external", evidenced=False)])
    v = gate(Claim(cause_ids=["EXTERNAL:ext-1"]), [], led, INCIDENT, cfg.DEFAULT)
    assert not v.accepted
    assert v.reason == R_EXTERNAL_UNEVIDENCED
    assert "ledger id" in v.next_question


def test_external_cause_with_evidence_passes_t1():
    led = StubLedger([Row("ext-1", SYMPTOM - timedelta(hours=1),
                          source="external", evidenced=True)])
    v = gate(Claim(cause_ids=["EXTERNAL:ext-1"]), [], led, INCIDENT, cfg.DEFAULT)
    assert v.accepted


# --- Rule 2: explanatory closure (T2) ----------------------------------------
def test_a_real_change_that_leaves_residue_is_rejected_as_incomplete():
    """Spec 8.4 step 3 -- the whole point of the reference incident.

    T1 passes. The claim names a genuine human-authored change. It still fails, because an
    anomaly above the threshold remains unexplained. This is what forces the second cause.
    """
    residue = [anomaly("A1"), anomaly("A2", entity="svc-b", kind="authz_gap")]
    claim = Claim(cause_ids=["chg-1"], explains={"A1"}, confidence=0.8)
    v = gate(claim, residue, LEDGER, INCIDENT, cfg.DEFAULT)
    assert not v.accepted
    assert v.reason == R_INCOMPLETE
    assert v.rule == "T2"
    assert v.next_question == "What explains svc-b: authz_gap?"


def test_multi_cause_acceptance_is_the_normal_path():
    """Spec 5.6.2: a Gate that only ever accepts single causes fails the reference incident."""
    residue = [anomaly("A1"), anomaly("A2")]
    claim = Claim(cause_ids=["chg-1", "chg-2"], explains={"A1", "A2"}, confidence=0.86)
    v = gate(claim, residue, LEDGER, INCIDENT, cfg.DEFAULT)
    assert v.accepted, v.reason
    assert v.reason == R_ACCEPTED


def test_residue_below_the_threshold_does_not_block_termination():
    """Spec 5.8: sub-threshold residue is accepted but must be reported, never dropped."""
    residue = [anomaly("A1"), anomaly("A-low", severity="low")]
    claim = Claim(cause_ids=["chg-1"], explains={"A1"})
    v = gate(claim, residue, LEDGER, INCIDENT, cfg.DEFAULT)
    assert v.accepted
    assert [a.id for a in significant(residue_after(residue, claim), cfg.DEFAULT)] == []
    assert [a.id for a in residue_after(residue, claim)] == ["A-low"]


def test_the_next_question_targets_the_worst_residue_deterministically():
    """D-004: severity, then earliest onset, then id. Without total ordering the gate trace
    would vary between identical runs and become untestable."""
    residue = [
        anomaly("A-med", severity="medium", entity="e1", kind="k1"),
        anomaly("A-crit-late", severity="critical", entity="e2", kind="k2", first_seen="10:00"),
        anomaly("A-crit-early", severity="critical", entity="e3", kind="k3", first_seen="09:00"),
    ]
    claim = Claim(cause_ids=["chg-1"])
    seen = {gate(claim, residue, LEDGER, INCIDENT, cfg.DEFAULT).next_question
            for _ in range(20)}
    assert seen == {"What explains e3: k3?"}


# --- Rule 3: timing sanity ---------------------------------------------------
def test_a_cause_that_postdates_the_first_symptom_is_rejected():
    led = StubLedger([Row("late", SYMPTOM + timedelta(minutes=5))])
    v = gate(Claim(cause_ids=["late"], explains=set()), [], led, INCIDENT, cfg.DEFAULT)
    assert not v.accepted
    assert v.reason == R_POSTDATES
    assert v.rule == "timing"


def test_a_cause_exactly_at_the_first_symptom_is_allowed():
    """Boundary: the spec's condition is `>`, not `>=`. A change and the symptom it causes
    can share a timestamp at minute resolution."""
    led = StubLedger([Row("same", SYMPTOM)])
    assert gate(Claim(cause_ids=["same"]), [], led, INCIDENT, cfg.DEFAULT).accepted


# --- 5.6.2 invariants --------------------------------------------------------
def test_the_gate_makes_no_network_call(monkeypatch):
    """Invariant 1, enforced rather than trusted."""

    def explode(*a, **k):
        raise AssertionError("the Gate attempted network I/O")

    monkeypatch.setattr(socket, "socket", explode)
    monkeypatch.setattr(socket, "create_connection", explode)
    residue = [anomaly("A1")]
    assert gate(Claim(cause_ids=["chg-1"], explains={"A1"}),
                residue, LEDGER, INCIDENT, cfg.DEFAULT).accepted


def test_the_gate_imports_nothing_that_could_call_a_model():
    """Invariant 1, statically. Catches a future edit that the runtime test would miss
    because the code path happened not to execute."""
    tree = ast.parse((cfg.ROOT / "agent" / "gate.py").read_text(encoding="utf-8"))
    imported = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imported |= {a.name.split(".")[0] for a in node.names}
        elif isinstance(node, ast.ImportFrom) and node.module:
            imported.add(node.module.split(".")[0])
    forbidden = {"anthropic", "openai", "httpx", "requests", "urllib", "socket",
                 "http", "aiohttp", "boto3"}
    assert not (imported & forbidden), "gate.py imports {}".format(imported & forbidden)
    assert "proposer" not in imported


def test_every_rejection_carries_a_next_question():
    """Invariant 3. A rejection without a question stalls the loop."""
    led = StubLedger([HUMAN, Row("late", SYMPTOM + timedelta(minutes=1)),
                      Row("ext", SYMPTOM, source="external", evidenced=False)])
    claims = [
        Claim(),
        Claim(cause_ids=["machine state"]),
        Claim(cause_ids=["EXTERNAL:ext"]),
        Claim(cause_ids=["late"]),
        Claim(cause_ids=["chg-1"], explains=set()),
    ]
    residues = [[], [anomaly("A1")], [anomaly("A1"), anomaly("A2", severity="critical")]]
    for c in claims:
        for r in residues:
            v = gate(c, r, led, INCIDENT, cfg.DEFAULT)
            if not v.accepted:
                assert v.next_question, "no question for {}".format(v.reason)
                assert v.rule, "no rule recorded for {}".format(v.reason)


def test_the_gate_does_not_mutate_its_arguments():
    """Invariant 4. The loop reuses the residue after a rejection; mutation here would
    corrupt the next step in a way that is very hard to see."""
    residue = [anomaly("A1"), anomaly("A2")]
    claim = Claim(cause_ids=["chg-1"], explains={"A1"})
    before_residue = [a.to_dict() for a in residue]
    before_claim = claim.to_dict()
    gate(claim, residue, LEDGER, INCIDENT, cfg.DEFAULT)
    assert [a.to_dict() for a in residue] == before_residue
    assert claim.to_dict() == before_claim


def test_the_gate_is_deterministic():
    residue = [anomaly("A1"), anomaly("A2", severity="critical")]
    claim = Claim(cause_ids=["chg-1"], explains={"A1"})
    verdicts = {
        (v.accepted, v.reason, v.next_question, v.rule)
        for v in (gate(claim, residue, LEDGER, INCIDENT, cfg.DEFAULT) for _ in range(50))
    }
    assert len(verdicts) == 1


def test_rules_are_checked_in_specification_order():
    """T1 before T2 before timing. A claim failing all three must report T1, because the
    probe is the question that walks the ladder down -- asking about residue first would
    skip the rung."""
    led = StubLedger([])
    v = gate(Claim(cause_ids=["machine state"]), [anomaly("A1")], led, INCIDENT, cfg.DEFAULT)
    assert v.rule == "T1"

    led2 = StubLedger([Row("late", SYMPTOM + timedelta(minutes=5))])
    v2 = gate(Claim(cause_ids=["late"]), [anomaly("A1")], led2, INCIDENT, cfg.DEFAULT)
    assert v2.rule == "T2", "residue must be checked before timing"


# --- the build-order progression (DECISIONS.md D-008) ------------------------
def test_phase_two_gate_rejects_machine_state_but_accepts_a_single_cause():
    """Spec 11.4 acceptance: with rule 1 only, the agent no longer terminates on machine
    state -- and still terminates too early, with one cause. That partial success is the
    correct outcome of phase 2 and is what motivates phase 3."""
    residue = [anomaly("A1"), anomaly("A2")]
    assert not gate(Claim(cause_ids=["machine state"]), residue, LEDGER, INCIDENT,
                    cfg.DEFAULT, rules=("T1",)).accepted
    assert gate(Claim(cause_ids=["chg-1"], explains={"A1"}), residue, LEDGER, INCIDENT,
                cfg.DEFAULT, rules=("T1",)).accepted


def test_phase_three_gate_rejects_the_same_single_cause():
    """Spec 11.5 acceptance: adding the Residue Rule is what turns the phase-2 partial
    success into the two-cause answer. Same claim, same ledger, different verdict."""
    residue = [anomaly("A1"), anomaly("A2")]
    claim = Claim(cause_ids=["chg-1"], explains={"A1"})
    assert gate(claim, residue, LEDGER, INCIDENT, cfg.DEFAULT, rules=("T1",)).accepted
    assert not gate(claim, residue, LEDGER, INCIDENT, cfg.DEFAULT, rules=ALL_RULES).accepted


# --- 5.6.1 pruning -----------------------------------------------------------
@dataclass
class Candidate:
    name: str
    would_explain: set


def test_pruning_discards_candidates_that_explain_nothing():
    """Spec 2.3: a co-occurring but innocent deployment explains nothing, therefore it is
    never followed. This is the counter-measure to the over-investigation failure of 1.3."""
    residue = [anomaly("A1"), anomaly("A2")]
    candidates = [
        Candidate("explains-something", {"A2"}),
        Candidate("innocent-co-deploy", set()),
        Candidate("explains-unrelated", {"A-other"}),
    ]
    kept = prune(candidates, residue)
    assert [c.name for c in kept] == ["explains-something"]


def test_pruning_with_empty_residue_keeps_nothing():
    assert prune([Candidate("x", {"A1"})], []) == []
