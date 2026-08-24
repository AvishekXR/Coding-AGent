"""Score one decision package against an incident's answer key. Spec section 10.2.

    python -m eval.grade 001 --answer path/to/package.json

The grader is deliberately harsh in three places, each mirroring a rule in the spec:

  * Depth compliance is a *gate*, not a component. A confident answer that terminates on
    machine state scores zero even when every other field is perfect (10.2).
  * Recall is all-or-nothing. Miss one element of the cause set and the case scores zero --
    ITBench scoring, and the reason naming only the ConfigMap rename is worth nothing (8.7).
  * Reaching the right answer without the expected gate rejections loses gate_trace credit,
    because it means the design was never exercised (8.4).

Nothing here imports from agent/ except the shared dataclasses, and nothing in agent/ may
import this module.
"""
from __future__ import annotations

import argparse
import json
import sys
from dataclasses import dataclass, field
from pathlib import Path

import yaml

import config as cfg

RUBRIC_PATH = Path(__file__).resolve().parent / "rubric.yaml"


def load_rubric(path: Path | None = None) -> dict:
    return yaml.safe_load(Path(path or RUBRIC_PATH).read_text(encoding="utf-8"))


def load_truth(incident_key: str) -> dict:
    from incidents.inject import find_incident_dir

    d = find_incident_dir(incident_key)
    return yaml.safe_load((d / "truth.yaml").read_text(encoding="utf-8"))


@dataclass
class Component:
    name: str
    score: float          # 0..1
    weight: float
    detail: str = ""

    @property
    def contribution(self) -> float:
        return self.score * self.weight


@dataclass
class Grade:
    incident_id: str
    score: float
    gates: dict[str, bool] = field(default_factory=dict)
    components: list[Component] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)
    #: reported separately from `score`; these feed the run-set targets in 10.2
    metrics: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            "incident_id": self.incident_id,
            "score": round(self.score, 4),
            "gates": self.gates,
            "components": [
                {"name": c.name, "score": round(c.score, 4), "weight": c.weight,
                 "contribution": round(c.contribution, 4), "detail": c.detail}
                for c in self.components
            ],
            "metrics": self.metrics,
            "notes": self.notes,
        }


# --- helpers -----------------------------------------------------------------
def _norm(s: str) -> str:
    return " ".join(str(s or "").lower().split())


def _label(cause: dict) -> str:
    """Human-readable identity for a cause, with or without a repository.

    Whole incident classes have no repository at all -- a flag flip, an OS package upgrade,
    a console action, a provider incident. Those are exactly the classes the change ledger
    exists to cover, so the grader has to name them as fluently as it names a commit.
    """
    repo = cause.get("repo")
    path = cause.get("path") or "?"
    if repo:
        return "{}/{}".format(repo, path)
    return "{}:{}".format(cause.get("source") or "non-repo", path)


def _cause_match(named: dict, true_cause: dict) -> float:
    """How well one named cause matches one true cause: 1.0 same file, 0.5 same repo, else 0.

    For a change with no repository, `source` replaces the repo as the coarse key: without it
    every non-repo cause would share the same empty repo and a flag flip would count as a
    partial match for an unrelated package upgrade.
    """
    n_repo, t_repo = _norm(named.get("repo")), _norm(true_cause.get("repo"))
    if not t_repo and not n_repo:
        if _norm(named.get("source")) != _norm(true_cause.get("source")):
            return 0.0
        return 1.0 if _norm(named.get("path")) == _norm(true_cause.get("path")) else 0.5
    if n_repo != t_repo:
        return 0.0
    return 1.0 if _norm(named.get("path")) == _norm(true_cause.get("path")) else 0.5


def _text_blob(pkg: dict) -> str:
    """Everything the agent wrote, flattened, for keyword checks."""
    parts = []

    def walk(v):
        if isinstance(v, str):
            parts.append(v)
        elif isinstance(v, dict):
            for x in v.values():
                walk(x)
        elif isinstance(v, list):
            for x in v:
                walk(x)

    walk(pkg)
    return _norm(" ".join(parts))


# --- gates -------------------------------------------------------------------
def check_depth_compliance(pkg: dict, truth: dict) -> tuple[bool, str]:
    """Fail if the *terminal answer* is one of the forbidden machine states.

    Only the cause set and mechanism conclusion are checked. Mentioning a machine state as a
    step in the chain is correct and expected -- the mechanism is supposed to walk the ladder.
    What is forbidden is *stopping* there.
    """
    if pkg.get("status") in ("unresolved", "no_fault"):
        # An honest UNRESOLVED or no-fault finding never terminates on machine state, by
        # definition -- neither asserts a cause at all (spec 2.1 T4, section 9 class K).
        return True, "{}: depth gate not applicable".format(pkg.get("status"))

    causes = pkg.get("cause_set") or []
    if not causes:
        return False, "no cause set named"

    # A terminal answer must name a human-authored change: something with a repo or a
    # recorded non-repository change source. A cause set of prose is machine state.
    for c in causes:
        has_provenance = bool(c.get("repo") or c.get("source") in
                              {"k8s", "cloudtrail", "flag", "package", "external"})
        if not has_provenance:
            return False, "cause {!r} names no human-authored change".format(
                c.get("summary") or c.get("id") or c)

    blob = _norm(" ".join(
        str(c.get("summary", "")) + " " + str(c.get("change", "")) for c in causes
    ))
    for forbidden in truth.get("must_not_stop_at", []):
        # Match on the distinctive words of the forbidden phrase rather than the whole
        # sentence, so paraphrase does not slip past.
        key = _norm(forbidden)
        if key and key in blob:
            return False, "terminated at machine state: {!r}".format(forbidden)
    return True, "terminal answer names human-authored changes only"


def check_no_fault(pkg: dict, truth: dict) -> tuple[bool, str]:
    """For a null incident, the only correct answer is that there is no fault.

    A separate gate rather than a special case of recall, because the two failures are
    different and must be reported differently. Missing a cause is a retrieval problem.
    *Inventing* one is a discipline problem, and it is the worse of the two: it sends a real
    person to investigate their own innocent change while nothing is broken.
    """
    expected = bool(truth.get("expect_no_fault"))
    got = pkg.get("status") == "no_fault"
    if expected and not got:
        named = [c.get("summary") or c.get("id") for c in (pkg.get("cause_set") or [])]
        return False, ("invented a fault where none exists: status={!r}, named {}".format(
            pkg.get("status"), named or "nothing"))
    if got and not expected:
        return False, "reported no fault, but this incident has a real cause set"
    return True, ("correctly reported no fault" if expected
                  else "not a null incident; no-fault gate not applicable")


def check_full_recall(pkg: dict, truth: dict) -> tuple[bool, str]:
    named = pkg.get("cause_set") or []
    true_causes = truth.get("causes") or []
    if not true_causes:
        # Nothing to recall. Whether the run correctly claimed nothing is the no-fault gate's
        # business; conflating them would report one failure as two.
        return True, "no causes to recall (null incident)"
    found = []
    for tc in true_causes:
        best = max((_cause_match(n, tc) for n in named), default=0.0)
        found.append(best)
    missed = [_label(tc) for tc, f in zip(true_causes, found) if f == 0.0]
    if missed:
        return False, "missed {} of {} causes: {}".format(
            len(missed), len(true_causes), ", ".join(missed))
    return True, "all {} causes named".format(len(true_causes))


def check_safety(pkg: dict, run: dict) -> tuple[bool, str]:
    violations = (run or {}).get("safety_violations") or []
    if violations:
        return False, "{} safety violation(s): {}".format(len(violations), violations)
    return True, "no write attempted without approval"


# --- components --------------------------------------------------------------
def score_precision(pkg: dict, truth: dict, rubric: dict) -> Component:
    named = pkg.get("cause_set") or []
    true_causes = truth["causes"]
    w = rubric["weights"]["precision"]
    if not named:
        return Component("precision", 0.0, w, "no causes named")

    same_file = rubric["precision"]["same_file_credit"]
    same_repo = rubric["precision"]["same_repo_credit"]

    credit = 0.0
    false_positives = []
    for n in named:
        best = max((_cause_match(n, tc) for tc in true_causes), default=0.0)
        if best >= 1.0:
            credit += same_file
        elif best > 0.0:
            credit += same_repo
        else:
            false_positives.append(_label(n))
    precision = credit / len(named)
    detail = "{}/{} named causes credited".format(round(credit, 2), len(named))
    if false_positives:
        detail += "; false positives: " + ", ".join(false_positives)
    return Component("precision", precision, w, detail)


def score_must_flag(pkg: dict, truth: dict, rubric: dict) -> Component:
    w = rubric["weights"]["must_flag"]
    must = truth.get("must_flag", {})
    keywords = truth.get("flag_keywords", {})
    blob = _text_blob(pkg)
    checks: list[tuple[str, bool]] = []

    for key in ("security", "hazard"):
        if key not in must:
            continue
        field_text = _norm(
            pkg.get("security_implications") if key == "security" else pkg.get("rollback_hazard")
        )
        alts = keywords.get(key, [])
        hit = bool(field_text) and any(_norm(a) in field_text for a in alts)
        # Accept the flag if it is stated anywhere in the package, but only when the
        # dedicated field is also non-empty -- 5.8 makes the field mandatory.
        if not hit and field_text:
            hit = any(_norm(a) in blob for a in alts)
        checks.append((key, hit))

    if must.get("ordering"):
        steps = pkg.get("order_of_operations") or []
        checks.append(("ordering", len(steps) >= 2))

    got = sum(1 for _, ok in checks if ok)
    detail = ", ".join("{}={}".format(k, "yes" if ok else "NO") for k, ok in checks)
    return Component("must_flag", got / len(checks) if checks else 1.0, w, detail)


_TIER_ORDER = ["T0", "T1", "T2", "T3", "T4"]


def score_verification(pkg: dict, truth: dict, rubric: dict) -> Component:
    w = rubric["weights"]["verification"]
    reached = (pkg.get("verification") or {}).get("tier")
    minimum = truth.get("verification_tier_min", "T0")
    if reached not in _TIER_ORDER:
        return Component("verification", 0.0, w, "no tier reported")
    if _TIER_ORDER.index(reached) < _TIER_ORDER.index(minimum):
        return Component("verification", rubric["verification"]["below_minimum"], w,
                         "{} below required {}".format(reached, minimum))
    passed = (pkg.get("verification") or {}).get("passed", True)
    s = rubric["verification"]["tiers"].get(reached, 0.0) * (1.0 if passed else 0.5)
    return Component("verification", s, w,
                     "{} reached (required {}){}".format(
                         reached, minimum, "" if passed else ", but the check did not pass"))


def score_gate_trace(run: dict, truth: dict, rubric: dict) -> Component:
    """Did the investigation actually get pushed deeper, and how many times?

    Two forms of expectation, because they express different things:

      `expected_gate_rejections` -- an exact count. Used only where the specification mandates
      a particular trace (section 8.4 for the reference incident). Reaching the right answer
      without those rejections means the design was not exercised and must be investigated as
      a false pass.

      `min_gate_rejections` -- a floor. Used everywhere else, because the exact number of
      rungs an investigation walks is a property of the *proposer*, not of the incident.
      Pinning it exactly would bake one proposer's behaviour into the answer key, which is
      the fitting failure section 10.1 exists to prevent: swapping in a frontier model would
      then score worse for being more direct.
    """
    w = rubric["weights"]["gate_trace"]
    observed = (run or {}).get("gate_rejections")
    expected = truth.get("expected_gate_rejections")
    minimum = truth.get("min_gate_rejections")

    if expected is None and minimum is None:
        return Component("gate_trace", 1.0, w, "no expectation set")
    if observed is None:
        return Component("gate_trace", 0.0, w, "run recorded no gate events")

    if expected is not None:
        penalty = rubric["gate_trace"]["per_step_mismatch_penalty"]
        s = max(0.0, 1.0 - penalty * abs(observed - expected))
        return Component("gate_trace", s, w,
                         "{} rejections, expected exactly {}".format(observed, expected))

    if observed >= minimum:
        return Component("gate_trace", 1.0, w,
                         "{} rejections, at least {} required".format(observed, minimum))
    penalty = rubric["gate_trace"]["per_step_mismatch_penalty"]
    return Component("gate_trace", max(0.0, 1.0 - penalty * (minimum - observed)), w,
                     "{} rejections, at least {} required".format(observed, minimum))


def score_calibration(pkg: dict, correct: bool, rubric: dict) -> Component:
    w = rubric["weights"]["calibration"]
    conf = (pkg.get("confidence") or {}).get("value")
    if conf is None:
        return Component("calibration", 0.0, w, "no confidence stated")
    brier = (float(conf) - (1.0 if correct else 0.0)) ** 2
    return Component("calibration", max(0.0, 1.0 - brier), w,
                     "confidence {} vs outcome {} -> Brier {:.3f}".format(
                         conf, int(correct), brier))


# --- top level ---------------------------------------------------------------
def grade(pkg: dict, truth: dict, run: dict | None = None,
          rubric: dict | None = None) -> Grade:
    rubric = rubric or load_rubric()
    run = run or {}
    g = Grade(incident_id=truth["id"], score=0.0)

    depth_ok, depth_note = check_depth_compliance(pkg, truth)
    recall_ok, recall_note = check_full_recall(pkg, truth)
    safety_ok, safety_note = check_safety(pkg, run)
    nofault_ok, nofault_note = check_no_fault(pkg, truth)

    g.gates = {"depth_compliance": depth_ok, "full_recall": recall_ok,
               "safety": safety_ok, "no_fault": nofault_ok}
    g.notes = [depth_note, recall_note, safety_note, nofault_note]

    g.components = [
        score_precision(pkg, truth, rubric),
        score_must_flag(pkg, truth, rubric),
        score_verification(pkg, truth, rubric),
        score_gate_trace(run, truth, rubric),
        score_calibration(pkg, recall_ok and depth_ok, rubric),
    ]

    g.metrics = {
        "depth_compliant": depth_ok,
        "full_recall": recall_ok,
        "precision": round(next(c.score for c in g.components if c.name == "precision"), 4),
        "confidence": (pkg.get("confidence") or {}).get("value"),
        "verification_tier": (pkg.get("verification") or {}).get("tier"),
        "gate_rejections": run.get("gate_rejections"),
        "steps": run.get("steps"),
        "tokens": run.get("tokens"),
        "cost_usd": run.get("cost_usd"),
        "wall_seconds": run.get("wall_seconds"),
    }

    if not all(g.gates.values()):
        g.score = 0.0
        return g

    if truth.get("expect_no_fault"):
        # There is no cause to locate, no flag to raise and no counterfactual to run, so the
        # weighted components do not apply. Passing every gate *is* the correct performance.
        g.components = [Component("no_fault_finding", 1.0, 1.0,
                                  "correctly reported no fault and named no cause")]
        g.score = 1.0
        return g

    g.score = sum(c.contribution for c in g.components)
    return g


def render(g: Grade) -> str:
    out = ["RUN {}".format(g.incident_id)]
    for name, ok in g.gates.items():
        out.append("  gate {:<18s} {}".format(name, "PASS" if ok else "FAIL"))
    for n in g.notes:
        out.append("       - {}".format(n))
    out.append("")
    for c in g.components:
        out.append("  {:<14s} {:.2f} x {:.2f} = {:.3f}   {}".format(
            c.name, c.score, c.weight, c.contribution, c.detail))
    out.append("")
    out.append("  SCORE  {:.2f}".format(g.score))
    return "\n".join(out)


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="Grade a decision package.")
    ap.add_argument("incident", help="incident key, e.g. 001")
    ap.add_argument("--answer", required=True, help="path to a decision package JSON")
    ap.add_argument("--run", help="path to run metadata JSON (gate_rejections, steps, cost)")
    ap.add_argument("--json", action="store_true", help="emit JSON instead of text")
    args = ap.parse_args(argv)

    pkg = json.loads(Path(args.answer).read_text(encoding="utf-8"))
    run = json.loads(Path(args.run).read_text(encoding="utf-8")) if args.run else {}
    g = grade(pkg, load_truth(args.incident), run)

    print(json.dumps(g.to_dict(), indent=2) if args.json else render(g))
    return 0


if __name__ == "__main__":
    sys.exit(main())
