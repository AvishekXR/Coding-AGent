"""End-to-end acceptance tests for phases 2, 3 and 4. Spec sections 11.4, 11.5, 11.6.

The test that matters most in this file is
`test_phase3_incident_001_is_solved_with_both_causes_and_exactly_three_rejections`.
Spec 11.5 calls it "the run that proves the thesis", and 8.4 adds the condition that makes it
meaningful: a run reaching the correct answer *without* the expected rejections has not
exercised the design and must be investigated as a false pass. So the rejection sequence is
asserted, not just the answer.
"""
from __future__ import annotations

import pytest

import config as cfg
from agent.gate import ALL_RULES
from agent.runner import Runner
from eval.grade import grade, load_truth

TRUE_CAUSES = {
    ("platform-config", "overlays/prod/orders.yaml"),
    ("platform-iac", "modules/iam/dynamodb.tf"),
}


@pytest.fixture(scope="module")
def collected(injected_world):
    from collectors.run import collect_all
    from datetime import timedelta
    from util import parse_ts

    _, meta = injected_world
    collect_all(parse_ts(meta["window_start_ts"]) - timedelta(days=30),
                parse_ts(meta["window_end_ts"]))
    return meta


@pytest.fixture(scope="module")
def full_run(collected):
    return Runner(proposer_kind="heuristic", rules=ALL_RULES).run(run_id="acc-full")


@pytest.fixture(scope="module")
def rule1_only_run(collected):
    """Phase 2: the Gate with the provenance check only."""
    return Runner(proposer_kind="heuristic", rules=("T1",)).run(run_id="acc-t1")


def _named(run):
    return {(c["repo"], c["path"]) for c in run.package.cause_set}


# --- phase 2 (spec 11.4) -----------------------------------------------------
def test_phase2_no_longer_terminates_on_machine_state(rule1_only_run):
    """Spec 11.4 acceptance: zero high-confidence machine-state terminations."""
    run = rule1_only_run
    assert run.terminated_as == "accepted"
    for c in run.package.cause_set:
        assert c.get("repo"), "terminated on something with no repository: {}".format(c)


def test_phase2_produces_the_first_two_rejections_of_the_reference_trace(rule1_only_run):
    """Spec 8.4 steps 1 and 2: both are machine state, both rejected under T1 with the probe."""
    from agent.types import PROBE

    t1 = [s for s in rule1_only_run.gate_trace if not s["accepted"]]
    assert len(t1) >= 2, "expected at least two rejections, got {}".format(len(t1))
    assert all(s["rule"] == "T1" for s in t1[:2])
    assert all(s["next_question"] == PROBE for s in t1[:2])


def test_phase2_still_stops_too_early_which_is_the_point(rule1_only_run):
    """Spec 11.3/11.4: with provenance alone the agent reaches one cause and stops.

    That partial success is the correct outcome of phase 2 and is precisely what motivates
    phase 3. If this test ever starts failing because the run finds both causes, the Residue
    Rule is no longer what is doing the work and the thesis is untested.
    """
    named = _named(rule1_only_run)
    assert named, "phase 2 should still reach a real change"
    assert named != TRUE_CAUSES, \
        "rule T1 alone found both causes; the Residue Rule is not what is finding the second"


# --- phase 3 (spec 11.5) -- the run that proves the thesis -------------------
def test_phase3_incident_001_is_solved_with_both_causes_and_exactly_three_rejections(full_run):
    run = full_run
    assert run.terminated_as == "accepted", run.package.to_dict()
    assert _named(run) == TRUE_CAUSES, "named {}".format(_named(run))
    assert run.gate_rejections == 3, \
        "expected exactly 3 gate rejections (spec 8.4), got {}".format(run.gate_rejections)


def test_the_gate_trace_matches_the_reference_sequence(full_run):
    """Spec 8.4, rule by rule: T1, T1, T2, accept."""
    rules = [s["rule"] for s in full_run.gate_trace]
    assert rules == ["T1", "T1", "T2", "T1+T2"], rules


def test_step_three_is_rejected_for_the_unexplained_authorization_gap(full_run):
    """Spec 8.4: STEP 3 IS THE WHOLE POINT OF THIS INCIDENT.

    The claim names a genuine human-authored change and passes T1. Every surveyed product
    would emit it. Only the Residue Rule forces the investigation onward, and the specific
    thing left unexplained is that the write succeeded instead of being refused.
    """
    step3 = full_run.gate_trace[2]
    assert step3["accepted"] is False
    assert step3["rule"] == "T2"
    assert len(step3["cause_ids"]) == 1, "step 3 must name exactly one real change"
    assert "write_permitted_to_novel_resource" in step3["next_question"]


def test_the_second_cause_is_only_added_after_the_residue_rejection(full_run):
    """The causal claim about the system: depth comes from the Gate, not the proposer."""
    before = full_run.gate_trace[2]["cause_ids"]
    after = full_run.gate_trace[3]["cause_ids"]
    assert len(after) == len(before) + 1
    assert set(before) < set(after)


def test_no_innocent_change_is_named(full_run):
    """Spec 2.3, the Pruning Rule: a co-occurring innocent change explains nothing, so it is
    never followed. Fourteen other changes share this window."""
    assert len(full_run.package.cause_set) == 2, full_run.package.cause_set


def test_gate_events_are_persisted_for_every_step(full_run):
    """Spec 6: gate_events is not optional -- it is the primary debugging artifact."""
    from ledger.ledger import Ledger

    rows = Ledger().gate_events(full_run.run_id)
    assert len(rows) == full_run.steps
    assert [bool(r["accepted"]) for r in rows] == [False, False, False, True]
    assert all(r["claim"] for r in rows)
    assert all(r["reason"] for r in rows)


# --- phase 4 (spec 11.6) -----------------------------------------------------
def test_verification_reaches_tier_one_by_replaying_the_policy(full_run):
    """Spec 8.5: replay the pre-change policy and expect the call to be refused.

    This is the check that distinguishes the two-cause explanation from the one-cause one,
    and it cannot be done from telemetry -- it needs the policy text out of another team's
    repository.
    """
    v = full_run.package.verification
    assert v["tier"] == "T1"
    assert v["passed"] is True
    assert "REFUSED" in v["observed"]


def test_the_decision_package_has_every_mandatory_field(full_run):
    """Spec 5.8: every field is mandatory; a missing field is a bug, not an omission."""
    assert full_run.package.validate() == []


def test_the_rollback_hazard_is_present_and_specific(full_run):
    """Spec 8.3: reverting first permanently destroys 40 minutes of customer orders."""
    hazard = full_run.package.rollback_hazard.lower()
    assert hazard and "none" not in hazard[:20]
    assert "retention" in hazard or "ttl" in hazard
    assert "export" in hazard


def test_data_export_is_ordered_before_the_revert(full_run):
    """Spec 5.8: explicitly ordered steps when order matters -- rolling back before
    recovering data destroys data. Getting the order wrong is worse than no answer."""
    steps = [s.lower() for s in full_run.package.order_of_operations]
    assert len(steps) >= 2
    # Match the step whose *action* is the revert, not any step that mentions the word --
    # step 1 legitimately contains "reverting first destroys them" as a warning.
    export_at = next(i for i, s in enumerate(steps) if s.startswith("export"))
    revert_at = next(i for i, s in enumerate(steps)
                     if s.startswith("restore") or s.startswith("revert"))
    assert export_at < revert_at, "the revert is ordered before the export: {}".format(steps)


def test_the_security_finding_survives_the_functional_fix(full_run):
    """Spec 8.3: after the configuration is corrected the IAM wildcard remains live.

    It must be surfaced separately and must not be lost in the remediation -- which is the
    whole risk, because nobody revisits it once the graphs are green.
    """
    sec = full_run.package.security_implications.lower()
    assert sec and "none identified" not in sec
    assert "separately" in sec or "file this" in sec
    assert "widen" in sec or "scope" in sec


def test_the_permission_rescope_is_ordered_after_service_recovery(full_run):
    steps = [s.lower() for s in full_run.package.order_of_operations]
    verify_at = next(i for i, s in enumerate(steps) if "verify" in s)
    rescope = [i for i, s in enumerate(steps) if "re-scope" in s or "rescope" in s]
    assert rescope and min(rescope) > verify_at


def test_blast_radius_names_indirect_consumers(full_run):
    """Spec 8.6: every consumer of the shared module inherits the change."""
    blast = full_run.package.blast_radius
    assert blast["direct"]
    assert blast["indirect"], "a change to a shared module has indirect consumers"


def test_confidence_is_calibrated_and_falsifiable(full_run):
    c = full_run.package.confidence
    assert 0.0 < c["value"] <= 0.95
    assert c["would_change_my_mind"]
    assert c["cheapest_disambiguating_query"]
    assert c["framing"] == "hypothesis with evidence, not a verdict"


def test_owners_are_named_for_every_cause_and_affected_consumer(full_run):
    teams = {o.get("team") for o in full_run.package.owners}
    assert "Platform" in teams, "both causes belong to Platform"
    assert len(full_run.package.owners) >= 2
    assert all(o.get("oncall") for o in full_run.package.owners)


# --- the score ---------------------------------------------------------------
def test_the_run_scores_one_against_the_frozen_rubric(full_run):
    g = grade(full_run.package.to_dict(), load_truth("001"), full_run.run_metadata())
    assert all(g.gates.values()), g.notes
    assert round(g.score, 2) == 1.00, g.to_dict()


def test_the_run_stays_inside_its_budget(full_run):
    assert full_run.steps <= cfg.DEFAULT.budget.max_steps
    assert full_run.wall_seconds < cfg.DEFAULT.budget.max_wall_seconds
    assert full_run.tokens < cfg.DEFAULT.budget.max_tokens


def test_every_tool_call_in_the_run_was_audited(full_run):
    from ledger.ledger import Ledger
    from tools.api import READ_ONLY_IDENTITY

    rows = Ledger().audit_log(full_run.run_id)
    assert rows
    assert {r["identity"] for r in rows} == {READ_ONLY_IDENTITY}


def test_the_mechanism_contains_the_resolution_hop(full_run):
    """Spec 5.8: the causal chain from cause to symptom, one hop per sentence.

    The load-bearing sentence is the one that says what the running service actually read and
    where the value came from. Without it the package lists two diffs and four anomalies and
    leaves the reader to guess how one produced the other.
    """
    m = full_run.package.mechanism
    assert "fell through to the hardcoded fallback" in m
    assert "renamed rather than deleted" in m
    # Causes appear in time order, earliest first.
    assert m.index("09:12") < m.index("09:34")


def test_short_term_reverts_the_functional_cause_not_the_permission(full_run):
    """Reverting the permission first restores the guard rail and starts failing writes
    loudly -- a different outage -- while leaving the wrong destination in place."""
    st = full_run.package.short_term
    assert "orders.yaml" in st
    assert "dynamodb.tf" not in st
    assert "step 2, not step 1" in st


def test_the_unresolved_path_returns_a_frontier_not_a_guess():
    """Spec 2.1 T4: budget exhaustion must return UNRESOLVED with ranked hypotheses, the
    remaining residue and the cheapest disambiguating query -- never a confident guess."""
    from dataclasses import replace

    from agent.runner import Runner

    tight = replace(cfg.DEFAULT, budget=replace(cfg.DEFAULT.budget, max_steps=2))
    res = Runner(proposer_kind="heuristic", config=tight).run(run_id="acc-t4")
    assert res.terminated_as in ("budget", "unresolved")
    assert res.package.status == "unresolved"
    assert res.package.validate() == []
    f = res.package.frontier
    assert f["ranked_hypotheses"] and f["residue"] and f["cheapest_query"]
    assert res.package.confidence["value"] == 0.0, "an unresolved run must assert no confidence"
    assert not res.package.cause_set, "an unresolved run must not name a cause set"
