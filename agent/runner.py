"""The control loop. Spec section 4.3.

    run(incident):
        brief    = causal_indexer.build(incident.window)   # L1, no LLM
        residue  = set(brief.anomalies)
        evidence = [brief]

        for step in range(cfg.max_steps):
            if budget.exhausted():
                return unresolved(frontier(evidence, residue))   # T4
            claim   = proposer.propose(incident, evidence, residue)   # L2
            verdict = gate(claim, residue, ledger, cfg)               # L3
            if verdict.accepted:
                proof = verifier.confirm(claim, max_tier=cfg.tier)    # L4
                return decision_package(claim, proof, residue)        # L5
            evidence.append(tools.answer(verdict.next_question))
            residue = residue - claim.explains

        return unresolved(frontier(evidence, residue))

Two details in that pseudocode carry more weight than they look:

  * `residue = residue - claim.explains` runs on the **rejected** path. A rejected claim can
    still have explained something true, and subtracting it is what makes the investigation
    converge instead of circling. It is also what makes the Gate's next question change from
    step to step.
  * budget exhaustion returns UNRESOLVED **with a frontier**, never a confident guess
    (spec 2.1 T4). The honest exit is a first-class outcome here, not an error path.
"""
from __future__ import annotations

import time
import uuid
from dataclasses import dataclass, field
from typing import Any

import config as cfg
from agent.gate import (
    ALL_RULES, IncidentRef, gate, grounded, residue_after, significant,
)
from agent.proposer import HeuristicProposer, ProposalContext
from agent.types import Claim, DecisionPackage, Verdict
from indexer import anomalies as indexer
from indexer.rank import Ranker
from indexer.severity import Anomaly, worst
from ledger.ledger import Ledger
from tools.api import ToolContext, ToolError, Tools
from util import iso, parse_ts


@dataclass
class Budget:
    """Spec 5.9.3, enforced in code. Exhaustion triggers T4, never a guess."""

    max_steps: int
    max_wall_seconds: float
    max_spend_usd: float
    max_tokens: int
    started: float = field(default_factory=time.monotonic)
    steps: int = 0
    tokens: int = 0
    spend_usd: float = 0.0

    def exhausted(self) -> tuple[bool, str]:
        if self.steps >= self.max_steps:
            return True, "step cap reached ({})".format(self.max_steps)
        if self.wall_seconds >= self.max_wall_seconds:
            return True, "wall-clock cap reached ({}s)".format(self.max_wall_seconds)
        if self.spend_usd >= self.max_spend_usd:
            return True, "spend cap reached (${:.2f})".format(self.max_spend_usd)
        if self.tokens >= self.max_tokens:
            return True, "token cap reached ({})".format(self.max_tokens)
        return False, ""

    @property
    def wall_seconds(self) -> float:
        return time.monotonic() - self.started


@dataclass
class RunResult:
    run_id: str
    incident_id: str
    package: DecisionPackage
    steps: int
    gate_rejections: int
    gate_trace: list[dict]
    tokens: int
    cost_usd: float
    wall_seconds: float
    terminated_as: str            # accepted | unresolved | budget | error
    safety_violations: list[str] = field(default_factory=list)

    def run_metadata(self) -> dict:
        """The shape eval/grade.py expects as `--run`."""
        return {
            "id": self.run_id, "incident_id": self.incident_id, "steps": self.steps,
            "gate_rejections": self.gate_rejections, "tokens": self.tokens,
            "cost_usd": self.cost_usd, "wall_seconds": round(self.wall_seconds, 2),
            "terminated_as": self.terminated_as,
            "safety_violations": self.safety_violations,
        }


class Runner:
    #: How many times an identical claim may be proposed before the run is declared a dead
    #: end rather than a budget exhaustion. Two allows one honest retry after new evidence.
    MAX_CLAIM_REPEATS = 2

    def __init__(self, ledger: Ledger | None = None, config=None,
                 proposer_kind: str = "heuristic", rules=ALL_RULES,
                 failing_entity: str | None = None, proposer=None):
        self.ledger = ledger or Ledger()
        self.cfg = config or cfg.DEFAULT
        self.rules = rules
        self.proposer_kind = proposer_kind
        self.failing_entity = failing_entity
        self._proposer_override = proposer

    # -- setup ---------------------------------------------------------------
    def _incident_meta(self) -> dict:
        import json

        p = cfg.STATE_DIR / "incident.json"
        if not p.exists():
            raise SystemExit("no incident injected; run: python -m incidents.inject 001")
        return json.loads(p.read_text(encoding="utf-8"))

    def _infer_failing_entity(self, brief) -> str:
        """The entity whose anomaly is most severe, unless one was named explicitly.

        Inferred rather than configured so that the runner has no per-incident setup.
        """
        if self.failing_entity:
            return self.failing_entity
        top = worst(brief.anomalies)
        return top.entity if top else "unknown"

    # -- the loop ------------------------------------------------------------
    def run(self, run_id: str | None = None) -> RunResult:
        run_id = run_id or ("run-" + uuid.uuid4().hex[:8])
        meta = self._incident_meta()

        brief = indexer.build(meta, config=self.cfg)
        residue: list[Anomaly] = list(brief.anomalies)
        failing_entity = self._infer_failing_entity(brief)

        ranker = Ranker(self.ledger)
        ctx = ToolContext(ledger=self.ledger, run_id=run_id, incident_id=meta["id"])
        tools = Tools(ctx, ranker=ranker.as_tool_ranker(
            failing_entity, meta["first_symptom_ts"]))

        proposer = self._proposer_override or (
            HeuristicProposer(tools, ranker=ranker, failing_entity=failing_entity)
            if self.proposer_kind == "heuristic"
            else self._build_llm(tools)
        )

        incident = IncidentRef(id=meta["id"],
                               first_symptom_ts=parse_ts(meta["first_symptom_ts"]))
        budget = Budget(
            max_steps=self.cfg.budget.max_steps,
            max_wall_seconds=self.cfg.budget.max_wall_seconds,
            max_spend_usd=self.cfg.budget.max_spend_usd,
            max_tokens=self.cfg.budget.max_tokens,
        )

        # Class K. Checked before the loop, because a proposer handed an empty residue has
        # nothing to reason from and will either name nothing (looping on T1) or reach for
        # the nearest recent change (naming an innocent one). Neither is the right answer.
        if not significant(brief.anomalies, self.cfg):
            from agent.report import build_no_fault

            pkg = build_no_fault(meta, brief, self.cfg)
            return self._finish(run_id, meta, pkg, budget, 0, [], ctx, "no_fault")

        evidence: list[dict] = [{"tool": "causal_brief", "args": {},
                                 "result": brief.to_dict()}]
        standing: list[str] = []
        last_rejection: dict | None = None
        gate_trace: list[dict] = []
        rejections = 0
        repeats: dict[tuple, int] = {}
        t1_rejections = 0
        offered_states: list[str] = []
        last_claim: Claim | None = None

        while True:
            done, why = budget.exhausted()
            if done:
                pkg = self._unresolved(meta, brief, residue, evidence, why, gate_trace)
                return self._finish(run_id, meta, pkg, budget, rejections, gate_trace,
                                   ctx, "budget")

            budget.steps += 1
            pctx = ProposalContext(
                incident_id=meta["id"], alert=meta["alert"],
                window=(brief.window[0], brief.window[1]),
                first_symptom_ts=meta["first_symptom_ts"],
                residue=list(residue), all_anomalies=list(brief.anomalies),
                evidence=evidence,
                last_rejection=last_rejection, standing_causes=list(standing),
                step=budget.steps, k=self.cfg.hypotheses_per_step,
                t1_rejections=t1_rejections, offered_states=list(offered_states),
            )
            claims = proposer.propose(pctx)
            claim = claims[0] if claims else Claim()
            last_claim = claim
            budget.tokens = ctx.tokens_returned

            verdict = gate(claim, residue, self.ledger, incident, self.cfg, rules=self.rules)
            self.ledger.log_gate_event(
                run_id=run_id, step=budget.steps, accepted=verdict.accepted,
                reason=verdict.reason, next_question=verdict.next_question,
                claim=str(claim), rule=verdict.rule,
            )
            gate_trace.append({
                "step": budget.steps, "accepted": verdict.accepted, "rule": verdict.rule,
                "reason": verdict.reason, "next_question": verdict.next_question,
                "cause_ids": list(claim.cause_ids), "explains": sorted(claim.explains),
            })

            if verdict.accepted:
                pkg = self._accepted(meta, brief, claim, residue, tools, failing_entity)
                return self._finish(run_id, meta, pkg, budget, rejections, gate_trace,
                                   ctx, "accepted")

            # Step repetition. Spec 5.9.3 requires retry limits, and the MAST taxonomy in
            # Appendix A measures step repetition in 15.7% of multi-agent traces. A proposer
            # that cannot answer the outstanding question will re-propose the same claim
            # forever, collecting an identical rejection each time. Burning the whole budget
            # on that produces a T4 exit that blames the budget for what is really a dead
            # end, so the dead end is named instead.
            signature = (tuple(sorted(claim.cause_ids)), tuple(sorted(claim.explains)))
            repeats[signature] = repeats.get(signature, 0) + 1
            if repeats[signature] > self.MAX_CLAIM_REPEATS:
                pkg = self._unresolved(
                    meta, brief, residue, evidence,
                    "no progress: the same claim was proposed {} times and rejected "
                    "identically ({}). The investigation has a dead end, not an exhausted "
                    "budget.".format(repeats[signature], verdict.reason),
                    gate_trace,
                )
                return self._finish(run_id, meta, pkg, budget, rejections, gate_trace,
                                   ctx, "unresolved")

            rejections += 1
            if verdict.rule == "T1":
                t1_rejections += 1
                # Remember which observed states have already been offered, so the ladder
                # walks downward instead of re-proposing the same rung.
                offered_states = list(dict.fromkeys(offered_states + list(claim.cause_ids)))
            last_rejection = {"reason": verdict.reason, "rule": verdict.rule,
                              "next_question": verdict.next_question}
            # A rejected claim that named real changes keeps them: the Residue Rule rejects
            # for incompleteness, not for being wrong (spec 2.2).
            if verdict.rule in ("T2",):
                standing = list(dict.fromkeys(standing + list(claim.cause_ids)))
            evidence.append(self._answer(tools, verdict, brief, evidence))
            # Only a grounded claim may reduce the residue (see agent.gate.grounded).
            if grounded(claim, self.ledger):
                residue = residue_after(residue, claim)

    # -- helpers -------------------------------------------------------------
    def _build_llm(self, tools):
        from agent.proposer import LLMProposer

        return LLMProposer(tools)

    def _answer(self, tools: Tools, verdict: Verdict, brief, evidence) -> dict:
        """Answer the Gate's question with a tool call.

        Note what is *not* happening here: the question text is never used to choose the tool.
        Tool selection is driven by the rule that fired, which is generated by our own
        deterministic Gate -- never by content read from logs or tickets (spec 5.9.2).
        """
        try:
            if verdict.rule in ("T1", "T2", "timing"):
                res = tools.changes_between(brief.window[0], brief.window[1], limit=200)
                return {"tool": "changes_between",
                        "args": {"t0": brief.window[0], "t1": brief.window[1]},
                        "result": res}
        except ToolError as e:
            # Spec 5.9.3: recorded as unknown, not reasoned over as data.
            return {"tool": "changes_between", "args": {}, "result": {},
                    "error": "TOOL_FAILED: {}".format(e)}
        return {"tool": "none", "args": {}, "result": {}}

    def _accepted(self, meta, brief, claim: Claim, residue, tools, failing_entity):
        from agent.report import build_package
        from agent.verifier import Verifier

        proof = Verifier(self.ledger, max_tier=self.cfg.max_verification_tier).confirm(
            claim, brief.anomalies)
        return build_package(
            meta=meta, brief=brief, claim=claim, proof=proof,
            residue=residue_after(residue, claim), ledger=self.ledger, tools=tools,
            failing_entity=failing_entity, config=self.cfg,
        )

    def _unresolved(self, meta, brief, residue, evidence, why, gate_trace):
        """T4. Ranked live hypotheses, remaining residue, cheapest disambiguating query."""
        from agent.report import build_unresolved

        return build_unresolved(
            meta=meta, brief=brief, residue=residue, evidence=evidence,
            reason=why, gate_trace=gate_trace, ledger=self.ledger, config=self.cfg,
        )

    def _finish(self, run_id, meta, pkg, budget, rejections, gate_trace, ctx,
                terminated_as) -> RunResult:
        result = RunResult(
            run_id=run_id, incident_id=meta["id"], package=pkg, steps=budget.steps,
            gate_rejections=rejections, gate_trace=gate_trace,
            tokens=ctx.tokens_returned, cost_usd=round(budget.spend_usd, 4),
            wall_seconds=budget.wall_seconds, terminated_as=terminated_as,
        )
        self.ledger.save_run({
            "id": run_id, "incident_id": meta["id"], "started_at": iso(parse_ts(
                meta["opened_at_ts"])),
            "steps": result.steps, "tokens": result.tokens, "cost_usd": result.cost_usd,
            "wall_seconds": result.wall_seconds, "terminated_as": terminated_as,
            "cause_ids": [c.get("id") for c in pkg.cause_set],
            "verification_tier": (pkg.verification or {}).get("tier"),
            "confidence": (pkg.confidence or {}).get("value"),
            "score": None, "depth_compliant": None,
            "notes": "gate rejections: {}".format(rejections),
        })
        return result
