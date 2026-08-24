"""Run an incident end to end and grade it.

    python -m eval.run 001                  # seed, inject, collect, investigate, grade
    python -m eval.run 001 --no-setup       # reuse the existing world and ledger
    python -m eval.run 001 --proposer llm   # use a frontier model instead of the offline one
    python -m eval.run 001 --rules T1       # phase-2 Gate: provenance check only

This is the harness entry point. Nothing here is imported by the solving half.
"""
from __future__ import annotations

import argparse
import json
import sys
from datetime import timedelta

import config as cfg
from agent.gate import ALL_RULES
from agent.runner import Runner
from eval.grade import grade, load_truth, render
from util import parse_ts


def setup(incident: str) -> dict:
    from collectors.run import collect_all
    from incidents.inject import inject

    meta = inject(incident, reseed=True)
    collect_all(parse_ts(meta["window_start_ts"]) - timedelta(days=30),
                parse_ts(meta["window_end_ts"]))
    return meta


def render_trace(res) -> str:
    out = ["GATE TRACE  (the primary debugging artifact -- spec section 6)"]
    for s in res.gate_trace:
        verdict = "ACCEPT" if s["accepted"] else "REJECT"
        out.append("  step {} [{}] {:<6} {}".format(
            s["step"], verdict, s["rule"], s["reason"]))
        for cid in s["cause_ids"]:
            out.append("        cause: {}".format(cid))
        if s["next_question"]:
            out.append("        asks : {}".format(" ".join(s["next_question"].split())[:100]))
    return "\n".join(out)


def render_package(pkg) -> str:
    d = pkg.to_dict()
    out = ["DECISION PACKAGE  (hypothesis with evidence, not a verdict -- spec 5.8)", ""]
    out.append("CAUSE SET ({} required)".format(len(d["cause_set"])))
    for c in d["cause_set"]:
        out.append("  {} {:<4} {:<16} {}".format(
            c["ts"][11:16], c["source"], c["repo"] or "-", c["path"] or "-"))
        out.append("      {}".format((c["summary"] or "")[:96]))
        out.append("      {} / {}".format(c["author"] or "?", c["team"] or "?"))
    for label, key in (("MECHANISM", "mechanism"), ("SHORT TERM", "short_term"),
                       ("LONG TERM", "long_term"), ("ROLLBACK HAZARD", "rollback_hazard"),
                       ("SECURITY", "security_implications")):
        out += ["", label]
        for line in _wrap(d[key]):
            out.append("  " + line)
    out += ["", "ORDER OF OPERATIONS  (order matters)"]
    for i, s in enumerate(d["order_of_operations"], 1):
        wrapped = _wrap(s, width=92)
        out.append("  {}. {}".format(i, wrapped[0]))
        out += ["     " + w for w in wrapped[1:]]
    out += ["", "BLAST RADIUS"]
    for k in ("direct", "indirect"):
        for item in d["blast_radius"].get(k, []):
            out.append("  {:<9} {}".format(k, item[:90]))
    v, c = d["verification"], d["confidence"]
    out += ["", "VERIFICATION  tier {}  passed={}".format(v["tier"], v["passed"])]
    out.append("  command  {}".format(v["command"][:96]))
    for line in _wrap(v["observed"]):
        out.append("  {}".format(line))
    out += ["", "CONFIDENCE  {}".format(c["value"])]
    for line in _wrap("would change my mind: " + c["would_change_my_mind"]):
        out.append("  " + line)
    out += ["", "OWNERS"]
    for o in d["owners"]:
        out.append("  {:<10} {:<14} {:<18} {}".format(
            o.get("team") or "?", o.get("oncall") or "?", o.get("slack") or "?",
            (o.get("scope") or "")[:44]))
    if d["unexplained"]:
        out += ["", "UNEXPLAINED  (accepted below threshold, never silently dropped)"]
        for u in d["unexplained"]:
            out.append("  {} {} {}".format(u["severity"], u["entity"], u["kind"]))
    return "\n".join(out)


def render_no_fault(pkg) -> str:
    """Class K has its own rendering. Labelling it UNRESOLVED would misrepresent it as a
    failed investigation when it is a positive finding: there is nothing here."""
    out = ["NO FAULT FOUND  (spec section 9, class K)", ""]
    for line in _wrap(pkg.mechanism):
        out.append("  " + line)
    if pkg.unexplained:
        out += ["", "OBSERVED BUT BELOW THRESHOLD  (ordinary variation, not an incident)"]
        for u in pkg.unexplained:
            out.append("  {:<9} {:<15} {:<32} {}".format(
                u["severity"], u["entity"], u["kind"], u["magnitude"]))
    else:
        out += ["", "No anomaly of any severity was detected in the window."]
    c = pkg.confidence
    out += ["", "WHAT WOULD CHANGE THIS"]
    for line in _wrap(c.get("would_change_my_mind", "")):
        out.append("  " + line)
    out += ["", "NEXT STEP"]
    for line in _wrap(c.get("cheapest_disambiguating_query", "")):
        out.append("  " + line)
    return "\n".join(out)


def render_frontier(pkg) -> str:
    f = pkg.frontier
    out = ["UNRESOLVED  (spec 2.1 T4 -- the honest exit)", "",
           "why: {}".format(f.get("why_unresolved"))]
    out.append("")
    out.append("RANKED HYPOTHESES CONSIDERED AND REJECTED")
    for h in f.get("ranked_hypotheses", []):
        out.append("  {} [{}] {}".format(
            h.get("cause_id"), h.get("rule"), h.get("rejected_because")))
    out += ["", "REMAINING RESIDUE"]
    for a in f.get("residue", []):
        out.append("  {:<9} {:<15} {:<34} {}".format(
            a["severity"], a["entity"], a["kind"], a["magnitude"]))
    out += ["", "CHEAPEST DISAMBIGUATING QUERY"]
    for line in _wrap(f.get("cheapest_query", "")):
        out.append("  " + line)
    return "\n".join(out)


def _wrap(text: str, width: int = 96) -> list[str]:
    import textwrap

    return textwrap.wrap(" ".join(str(text or "").split()), width=width) or [""]


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="Run and grade one incident.")
    ap.add_argument("incident")
    ap.add_argument("--no-setup", action="store_true",
                    help="reuse the existing world and ledger")
    ap.add_argument("--proposer", default="heuristic", choices=["heuristic", "llm"])
    ap.add_argument("--rules", nargs="*", default=None,
                    help="active Gate rules, e.g. --rules T1  (default: all)")
    ap.add_argument("--json", action="store_true")
    args = ap.parse_args(argv)

    if not args.no_setup:
        setup(args.incident)

    rules = tuple(args.rules) if args.rules else ALL_RULES
    res = Runner(proposer_kind=args.proposer, rules=rules).run()
    pkg = res.package

    g = grade(pkg.to_dict(), load_truth(args.incident), res.run_metadata())

    if args.json:
        print(json.dumps({"run": res.run_metadata(), "package": pkg.to_dict(),
                          "grade": g.to_dict()}, indent=2, default=str))
        return 0

    print("=" * 98)
    print("RUN {}   proposer={}   gate rules={}".format(
        res.incident_id, args.proposer, ",".join(rules)))
    print("=" * 98)
    print()
    print(render_trace(res))
    print()
    print("-" * 98)
    print()
    if pkg.status == "resolved":
        print(render_package(pkg))
    elif pkg.status == "no_fault":
        print(render_no_fault(pkg))
    else:
        print(render_frontier(pkg))
    print()
    print("-" * 98)
    print()
    print(render(g))
    print()
    print("  steps {}   gate rejections {}   tool tokens {}   wall {:.1f}s".format(
        res.steps, res.gate_rejections, res.tokens, res.wall_seconds))
    return 0


if __name__ == "__main__":
    sys.exit(main())
