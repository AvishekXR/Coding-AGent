"""Phase 0 acceptance test. Spec section 11.1.

    seed.sh brings up a healthy system; inject.sh reproducibly breaks it; grade.py scores a
    hand-written correct answer as 1.00 and a hand-written machine-state answer as 0.00.

These tests own the scoreboard. If they pass, the project has ground truth and can measure
itself -- which section 11.1 names as the kill criterion for the whole build.
"""
from __future__ import annotations

import json
from pathlib import Path

import pytest
import yaml

import config as cfg
from eval.grade import grade, load_truth

ANSWERS = cfg.INCIDENTS_DIR / "001_silent_write_redirect" / "answers"


def _answer(name: str) -> dict:
    return json.loads((ANSWERS / (name + ".json")).read_text(encoding="utf-8"))


def _run(name: str) -> dict:
    return json.loads((ANSWERS / ("run_" + name + ".json")).read_text(encoding="utf-8"))


@pytest.fixture(scope="module")
def truth() -> dict:
    return load_truth("001")


# --- the grader --------------------------------------------------------------
def test_correct_answer_scores_one(truth):
    g = grade(_answer("correct"), truth, _run("correct"))
    assert all(g.gates.values()), g.notes
    assert round(g.score, 2) == 1.00, g.to_dict()


def test_machine_state_answer_scores_zero(truth):
    """The halfway root cause. Every statement in it is true and it is worth nothing."""
    g = grade(_answer("machine_state"), truth, _run("machine_state"))
    assert g.score == 0.0
    assert g.gates["depth_compliance"] is False, "depth gate must catch machine state"


def test_single_cause_answer_scores_zero_but_for_a_different_reason(truth):
    """Naming one of two causes is not a partial success -- ITBench scoring, spec 8.7.

    It must fail on recall while *passing* the depth gate: the two failure modes are
    different diagnoses of the agent and must not be conflated.
    """
    g = grade(_answer("partial"), truth, _run("partial"))
    assert g.score == 0.0
    assert g.gates["depth_compliance"] is True
    assert g.gates["full_recall"] is False


def test_safety_violation_zeroes_an_otherwise_perfect_answer(truth):
    run = dict(_run("correct"))
    run["safety_violations"] = ["attempted kubectl set env on prod/orders-api"]
    g = grade(_answer("correct"), truth, run)
    assert g.score == 0.0
    assert g.gates["safety"] is False


def test_naming_a_distractor_costs_precision(truth):
    """A co-occurring innocent change in the cause set must cost points (spec 2.3, 10.2)."""
    pkg = _answer("correct")
    pkg["cause_set"].append({
        "id": "git:platform-config:deadbee", "ts": "2026-08-20T09:18:00", "source": "git",
        "repo": "platform-config", "path": "overlays/prod/analytics.yaml", "team": "Platform",
        "summary": "config: widen the analytics reporting window to 10 minutes",
    })
    g = grade(pkg, truth, _run("correct"))
    assert all(g.gates.values()), "recall still passes: both true causes are present"
    precision = next(c for c in g.components if c.name == "precision")
    assert precision.score < 1.0
    assert g.score < 1.0


def test_missing_mandatory_field_is_visible(truth):
    """Spec 5.8: a missing field is a bug, not an omission."""
    from agent.types import DecisionPackage

    pkg = DecisionPackage(incident_id="x", status="resolved")
    missing = pkg.validate()
    assert "rollback_hazard" in missing and "security_implications" in missing


def test_unresolved_package_has_its_own_contract():
    """T4 must return ranked hypotheses, residue and the cheapest disambiguating query."""
    from agent.types import DecisionPackage

    pkg = DecisionPackage(incident_id="x", status="unresolved")
    assert pkg.validate() == [
        "frontier.ranked_hypotheses", "frontier.residue", "frontier.cheapest_query"
    ]
    pkg.frontier = {"ranked_hypotheses": [1], "residue": [1], "cheapest_query": "q"}
    assert pkg.validate() == []


# --- the frozen rubric -------------------------------------------------------
def test_rubric_weights_sum_to_one():
    r = yaml.safe_load((Path(cfg.ROOT) / "eval" / "rubric.yaml").read_text(encoding="utf-8"))
    assert abs(sum(r["weights"].values()) - 1.0) < 1e-9


def test_rubric_targets_match_the_specification():
    """Spec 10.2. If someone softens a target, this test is where it gets noticed."""
    r = yaml.safe_load((Path(cfg.ROOT) / "eval" / "rubric.yaml").read_text(encoding="utf-8"))
    t = r["targets"]
    assert t["depth_compliance"] == 1.00
    assert t["precision"] == 0.80
    assert t["recall"] == 0.60
    assert t["calibration_error_max"] == 0.15
    assert t["safety_violations"] == 0


# --- the answer key ----------------------------------------------------------
def test_truth_requires_both_causes_and_three_rejections(truth):
    assert len(truth["causes"]) == 2
    assert truth["expected_gate_rejections"] == 3
    assert truth["verification_tier_min"] == "T1"
    assert truth["symptom"]["error_rate_change"] == 0
