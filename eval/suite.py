"""Run the whole incident range and report the metrics of spec section 10.2.

    python -m eval.suite                 # every incident
    python -m eval.suite --set dev       # development set only
    python -m eval.suite --set holdout   # held-out set only (spec 10.1)
    python -m eval.suite --json

Per-incident scores answer "did this one work". These are the numbers that say whether the
*system* works, and they are different questions: a set that scores well on average while
failing depth compliance once is worse than a lower-scoring set that never does, because a
confident answer terminating at machine state sends an engineer to a symptom.

Each metric below is reported against its target from 10.2, and the run is only "meeting
targets" when every one of them holds.
"""
from __future__ import annotations

import argparse
import json
import statistics
import sys
from dataclasses import dataclass, field
from datetime import timedelta
from pathlib import Path

import yaml

import config as cfg
from agent.gate import ALL_RULES
from agent.runner import Runner
from eval.grade import grade, load_rubric, load_truth
from util import parse_ts

HOLDOUT_PATH = Path(__file__).resolve().parent / "holdout.yaml"


def load_split() -> dict:
    return yaml.safe_load(HOLDOUT_PATH.read_text(encoding="utf-8"))


def all_incidents() -> list[str]:
    return sorted(
        d.name for d in cfg.INCIDENTS_DIR.iterdir()
        if d.is_dir() and (d / "truth.yaml").exists()
    )


@dataclass
class CaseResult:
    incident: str
    incident_class: str
    score: float
    gates: dict
    metrics: dict
    steps: int
    rejections: int
    tokens: int
    wall: float
    named: list
    notes: list = field(default_factory=list)


def run_case(incident_dir: str, proposer: str = "heuristic") -> CaseResult:
    """Seed, inject, collect, investigate and grade one incident from scratch."""
    from collectors.run import collect_all
    from incidents.inject import inject

    key = incident_dir.split("_")[0]
    meta = inject(key, reseed=True)
    collect_all(parse_ts(meta["window_start_ts"]) - timedelta(days=30),
                parse_ts(meta["window_end_ts"]))

    res = Runner(proposer_kind=proposer, rules=ALL_RULES).run()
    truth = load_truth(key)
    g = grade(res.package.to_dict(), truth, res.run_metadata())

    return CaseResult(
        incident=incident_dir,
        incident_class=str(truth.get("class", "?")),
        score=g.score,
        gates=dict(g.gates),
        metrics=dict(g.metrics),
        steps=res.steps,
        rejections=res.gate_rejections,
        tokens=res.tokens,
        wall=res.wall_seconds,
        named=[{"repo": c.get("repo"), "path": c.get("path"), "source": c.get("source")}
               for c in res.package.cause_set],
        notes=list(g.notes),
    )


def aggregate(results: list[CaseResult], rubric: dict) -> dict:
    """The run-set metrics of spec 10.2, each against its target."""
    n = len(results) or 1
    targets = rubric["targets"]

    depth_ok = sum(1 for r in results if r.gates.get("depth_compliance"))
    recall_ok = sum(1 for r in results if r.gates.get("full_recall"))
    safety_bad = sum(1 for r in results if not r.gates.get("safety"))

    precisions = [r.metrics.get("precision") for r in results
                  if r.metrics.get("precision") is not None]

    # Brier score over the whole set: (confidence - outcome)^2, outcome 1 when the cause set
    # was right. A well-calibrated 0.6 is worth more than an overconfident 0.9 (10.2).
    briers = []
    for r in results:
        conf = r.metrics.get("confidence")
        if conf is None:
            continue
        outcome = 1.0 if (r.gates.get("full_recall") and r.gates.get("depth_compliance")) else 0.0
        briers.append((float(conf) - outcome) ** 2)

    metrics = {
        "cases": len(results),
        "mean_score": round(statistics.fmean([r.score for r in results]), 4) if results else 0.0,
        "depth_compliance": round(depth_ok / n, 4),
        "recall": round(recall_ok / n, 4),
        "precision": round(statistics.fmean(precisions), 4) if precisions else 0.0,
        "calibration_error": round(statistics.fmean(briers), 4) if briers else None,
        "safety_violations": safety_bad,
        "total_tokens": sum(r.tokens for r in results),
        "total_wall_seconds": round(sum(r.wall for r in results), 1),
        "mean_steps": round(statistics.fmean([r.steps for r in results]), 2) if results else 0,
    }

    metrics["meets_targets"] = {
        "depth_compliance": metrics["depth_compliance"] >= targets["depth_compliance"],
        "precision": metrics["precision"] >= targets["precision"],
        "recall": metrics["recall"] >= targets["recall"],
        "calibration": (metrics["calibration_error"] is not None
                        and metrics["calibration_error"] <= targets["calibration_error_max"]),
        "safety": metrics["safety_violations"] == targets["safety_violations"],
    }
    metrics["all_targets_met"] = all(metrics["meets_targets"].values())
    return metrics


def render(results: list[CaseResult], metrics: dict, rubric: dict, which: str) -> str:
    targets = rubric["targets"]
    out = ["=" * 92,
           "INCIDENT RANGE -- {} set, {} cases".format(which, len(results)),
           "=" * 92, ""]
    out.append("  {:<4} {:<40} {:>5}  {:>6} {:>5}  {}".format(
        "cls", "incident", "score", "steps", "rej", "gates"))
    out.append("  " + "-" * 88)
    for r in sorted(results, key=lambda r: (r.incident_class, r.incident)):
        failed = [k for k, v in r.gates.items() if not v]
        out.append("  {:<4} {:<40} {:>5.2f}  {:>6} {:>5}  {}".format(
            r.incident_class, r.incident[:40], r.score, r.steps, r.rejections,
            "ok" if not failed else "FAIL: " + ",".join(failed)))
    out += ["", "  " + "-" * 88, "", "METRICS  (spec 10.2)", ""]

    rows = [
        ("depth compliance", metrics["depth_compliance"], targets["depth_compliance"], ">="),
        ("precision", metrics["precision"], targets["precision"], ">="),
        ("recall", metrics["recall"], targets["recall"], ">="),
        ("calibration error", metrics["calibration_error"],
         targets["calibration_error_max"], "<="),
        ("safety violations", metrics["safety_violations"], targets["safety_violations"], "=="),
    ]
    for name, value, target, op in rows:
        key = {"depth compliance": "depth_compliance", "precision": "precision",
               "recall": "recall", "calibration error": "calibration",
               "safety violations": "safety"}[name]
        ok = metrics["meets_targets"][key]
        shown = "n/a" if value is None else (
            "{:.2f}".format(value) if isinstance(value, float) else str(value))
        out.append("  {:<20} {:>8}   target {} {:<6}  {}".format(
            name, shown, op, target, "MET" if ok else "NOT MET"))

    out += ["", "  mean score {:.3f}   mean steps {}   tokens {:,}   wall {}s".format(
        metrics["mean_score"], metrics["mean_steps"], metrics["total_tokens"],
        metrics["total_wall_seconds"])]
    out.append("")
    out.append("  ALL TARGETS MET" if metrics["all_targets_met"] else "  TARGETS NOT MET")

    if which == "holdout":
        out += ["", "  " + "!" * 88,
                "  These incidents were authored and debugged during the same build, by the",
                "  author who wrote the solver. The split mechanism is real; for this set it is",
                "  bookkeeping rather than a control, because nothing here was ever unseen.",
                "  See eval/holdout.yaml. Do not quote this as a held-out result.",
                "  " + "!" * 88]
    return "\n".join(out)


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="Run the whole incident range.")
    ap.add_argument("--set", dest="which", default="all",
                    choices=["all", "dev", "holdout"])
    ap.add_argument("--proposer", default="heuristic", choices=["heuristic", "llm"])
    ap.add_argument("--json", action="store_true")
    args = ap.parse_args(argv)

    split = load_split()
    if args.which == "holdout":
        names = list(split["holdout"])
    elif args.which == "dev":
        names = list(split["development"])
    else:
        names = all_incidents()

    known = set(all_incidents())
    missing = [n for n in names if n not in known]
    if missing:
        raise SystemExit("holdout.yaml names incidents that do not exist: {}".format(missing))

    rubric = load_rubric()
    results = [run_case(n, proposer=args.proposer) for n in names]
    metrics = aggregate(results, rubric)

    if args.json:
        print(json.dumps({
            "set": args.which, "proposer": args.proposer, "metrics": metrics,
            "cases": [vars(r) for r in results],
        }, indent=2, default=str))
        return 0

    print(render(results, metrics, rubric, args.which))
    return 0 if metrics["all_targets_met"] else 1


if __name__ == "__main__":
    sys.exit(main())
