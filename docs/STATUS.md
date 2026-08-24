# Build status

Against the build order in specification §11, as of 2026-08-23.

| Phase | Scope | State | Evidence |
|---|---|---|---|
| 0 | Scoreboard: world, incident 001, frozen rubric, grader | **Done** | `tests/test_phase0.py`, `tests/test_world.py` |
| 1 | Change ledger, reverse index, phase-1 tools | **Done** | `tests/test_phase1.py` |
| 2 | The Gate, rule 1 only + control loop + gate_events | **Done** | `tests/test_acceptance.py` (phase-2 tests) |
| 3 | The Residue Rule, causal indexer, pruning | **Done** | `tests/test_acceptance.py` (phase-3 tests) |
| 4 | Verification tiers, decision package, safety layer | **Done** | `tests/test_acceptance.py`, `tests/test_safety.py` |
| 5 | Range expansion to classes A–L, blind evaluation | **Not started** | — |

170 tests pass. All 16 items of the Appendix E checklist that can be verified mechanically
are verified; a script that re-checks them lives in the commit for phase 4.

## The reference run

```
step 1  REJECT T1     machine state (metric drop)      -> the provenance probe
step 2  REJECT T1     machine state (writes ceased)    -> the provenance probe
step 3  REJECT T2     the ConfigMap rename             -> what explains the authz gap?
step 4  ACCEPT T1+T2  both changes, residue empty

SCORE 1.00   precision 1.00   must_flag 3/3   verification T1   gate_trace 3/3   Brier 0.020
```

Matching the worked run in §10.3 and the required gate sequence in §8.4.

## What is deliberately not built

Per §12, and each still with the trigger that would justify revisiting it:

| Not built | Revisit when |
|---|---|
| Model fine-tuning | inference cost becomes the binding constraint |
| Graph database | a graph query is measurably the bottleneck |
| Multi-agent framework | a single-loop acceptance test fails for a reason a framework would fix |
| Vector store / episodic memory | phase 5, once the range has real history |
| Dashboard or web UI | after the blind evaluation |
| Automatic fix application | never without an explicit approval gate |

## Honest gaps

These are limitations, not oversights. Each is stated because a build report that only lists
what works is not a report.

1. **No model has been run.** `ANTHROPIC_API_KEY` is not set on this machine, so every number
   above comes from `HeuristicProposer` — the deterministic offline proposer of D-003/D-009.
   It contains no incident-specific knowledge (enforced by
   `tests/test_no_incident_leakage.py`) and it is deliberately naive, so the depth in the
   trace is attributable to the Gate rather than to a prompt. But it is not a frontier model,
   and **the numbers are therefore not the numbers §10.2 asks for**. `LLMProposer` is written
   and wired; `python -m eval.run 001 --proposer llm` will exercise it once a key is present.

2. **The baseline of §11.2 has not been measured.** It requires pointing a plain agent at the
   incident with no Gate, and that needs a model. `eval/baseline_001.md` does not exist yet.
   Without it there is no measured "before" to compare the Gate against — the phase-2 versus
   phase-3 comparison in `tests/test_acceptance.py` is evidence that the Residue Rule changes
   the outcome, but it is not the same claim.

3. **One incident, one class.** Incident 001 (class D) is built. §9 asks for at least three
   incidents per class and at least eight in each of C and D before a blind evaluation. With
   n=1 there is no basis for any accuracy claim, and by construction the world was authored
   alongside the solver, which §10.1 names as the largest risk in the project.

4. **Separated authorship has not happened.** §10.1 requires that one person own incident
   authoring and never see the agent's internals. Here the same author wrote both. The
   structural defences are in place — the solving half cannot import `incidents/` or read
   `truth.yaml`, and 40 tests enforce it — but that constrains *code*, not the author's
   knowledge. The mitigation is real and partial; it is not the control the spec asks for.

5. **Collectors for k8s audit, CloudTrail, flags, packages and external events** are not
   built (§11.7). The ledger currently spans git and IaC, which is what incident 001 needs;
   class E (the Datadog shape, a change that exists in no repository) is unsolvable until the
   package and OS collectors exist.

6. **External benchmarks not run.** §10.1 requires AIOpsLab, ITBench and OpenRCA for
   calibration before trusting internal numbers. Not attempted.

7. **The simulated world is a simulator** (D-001). No Docker, kind or LocalStack on this
   machine. The incident is emergent rather than staged — real git history, a real IAM
   evaluator, a real fallback in real code — but a simulator cannot surprise you the way a
   real cluster does, and that is exactly the property that makes real evaluation valuable.
