# DECISIONS.md

Every ambiguity in the build specification resolved under the rule in §0.3, in order of
precedence: (1) preserve the Termination Rule and Residue Rule exactly, (2) simplest to
implement and delete, (3) easiest to test automatically.

---

## D-001 — Local environment: deterministic simulator instead of kind + LocalStack
**Date:** 2026-08-23
**Question:** §7 specifies kind (Kubernetes in Docker) and LocalStack as the local stand-ins.
Neither Docker, kind, kubectl nor a container runtime is available on the build machine
(verified: `docker`, `kind`, `kubectl` all absent; Python 3.10, git and ripgrep present).
**Choice:** Build `env/` as a deterministic in-process simulator of the same world:

| Spec component | Implemented as |
|---|---|
| Four teams' repositories | **Real git repositories** in `env/repos/`, real commits at controlled timestamps |
| Kubernetes ConfigMaps + rollouts | `env/sim/cluster.py` — object store rendered from the `platform-config` repo, emits real k8s audit events |
| DynamoDB + TTL | `env/sim/dynamo.py` — table store with per-item TTL |
| IAM | `env/sim/iam.py` — real ARN wildcard matching and Allow/Deny evaluation |
| CloudTrail | `env/sim/cloudtrail.py` — control-plane event JSONL |
| Logs and metrics | JSONL under `env/state/telemetry/` (§7 explicitly permits this for phase 1) |

**Why this is not a shortcut:** the incident is *not* hand-written telemetry. `orders-api` is
real code that really reads `ORDERS_TABLE`, really falls through to its hardcoded default, the
IAM engine really evaluates `orders-*` against `orders-staging`, and `orders_created` really
drops because the rows genuinely landed in the other table. The failure is *emergent*, which is
what makes the evaluation meaningful.

**Cost of being wrong / how to reverse:** the simulator is confined behind the collector
interfaces (`collectors/*.py`) and the seven tool contracts (§5.4). Swapping in real
kind + LocalStack is a change to the collectors and `env/seed.py` only. Nothing in
`ledger/`, `indexer/`, `agent/` or `eval/` knows the world is simulated.

---

## D-002 — Repository root plays the role of `hisev/`
**Date:** 2026-08-23
**Question:** §7.1 shows the tree rooted at `hisev/`. The build folder is `High SEV/`.
**Choice:** The repository root *is* `hisev/`. Subdirectory names match §7.1 exactly so the
tree can be diffed against the specification by eye. Each is a Python package; everything runs
from the repository root (`python -m agent.runner`, etc.).

---

## D-003 — Two Proposer backends, one of which needs no network
**Date:** 2026-08-23
**Question:** §5.5 requires the Proposer to be a frontier model. But the acceptance tests of
§11 must be runnable, repeatedly and deterministically, in CI with no API key — and §10.1
demands the harness be built *before* the agent.
**Choice:** `agent/proposer.py` exposes one interface with two implementations:
- `LLMProposer` — the real one. Frontier model, no training, per §5.5. Used for every
  score of record.
- `HeuristicProposer` — deterministic, no network. Ranks ledger changes by reverse-index
  overlap with the current residue plus temporal precedence. Used by `tests/` to prove the
  *loop and Gate* behave correctly, and to run acceptance tests offline.

**Anti-gaming constraint (§10.1):** `HeuristicProposer` contains **no incident-specific
knowledge** — no table names, no key names, no repo names, no answers. It may not import
anything from `incidents/`. A test enforces this (`tests/test_no_incident_leakage.py`).
Numbers reported as results always name which proposer produced them.

---

## D-004 — Severity is an ordered enum, not a float
**Date:** 2026-08-23
**Question:** §5.6 compares `a.severity >= cfg.min_severity` and §5.4.4 uses the string
`min_severity="medium"`.
**Choice:** `indexer/anomalies.py` defines `Severity(IntEnum)` = info(0) < low(1) < medium(2)
< high(3) < critical(4). Strings parse to it. `>=` is then exact and total, and
`max(left, key=...)` in the Gate has a well-defined winner. Ties broken by earliest
`first_seen`, then by `id`, so the Gate is fully deterministic.

---

## D-005 — `inject.sh` is `inject.py`
**Date:** 2026-08-23
**Question:** §11.1 and §7.1 name `incidents/001/inject.sh` and `env/seed.sh`.
**Choice:** Implemented as `inject.py` and `env/seed.py`. The build machine is Windows; POSIX
shell is available but not guaranteed on a reviewer's machine, and the injection must set
precise author/committer timestamps and drive the simulator — which is Python work either way.
Thin `.sh` wrappers are provided so the spec's command names still work.

---

## D-006 — Every timestamp handed to git carries an explicit UTC offset
**Date:** 2026-08-23
**Question:** Not raised by the specification. Found while building the phase-0 world tests.
**The trap:** `git log --since/--until` parse a bare ISO timestamp (`2026-08-20T08:00:00`) in
the **machine's local timezone**. The build machine is at UTC+05:45, so an incident-window
query was shifted by 5 hours 45 minutes and returned **zero commits** — while every commit was
correctly stored in UTC. Nothing errors. The ledger simply comes back empty.

**Why this matters more than it looks:** an empty change list is indistinguishable, from the
agent's point of view, from an incident with no human cause. The Gate would correctly refuse
to terminate, the loop would exhaust its budget, and the system would report UNRESOLVED — a
*plausible* failure that has nothing to do with the reasoning being tested. It would look like
the thesis failing rather than a timezone bug, on any machine not set to UTC.

**Choice:** the world's internal clock is naive UTC everywhere. Awareness is added only at the
boundary with git, via `util.git_ts()`, which every collector and test must use. A test
(`tests/test_util.py::test_git_window_is_timezone_independent`) pins the behaviour.

---

## D-007 — The reverse index uses ripgrep when present, pure Python otherwise
**Date:** 2026-08-23
**Question:** §5.2 specifies "a ripgrep sweep across all checked-out repositories". `rg` is
not installed on the build machine (`shutil.which("rg")` returns None).
**Choice:** `ledger/index.py` detects ripgrep and uses it when available; otherwise it runs an
identical sweep in pure Python with the same output contract, the same regex, and the same
skip rules. Both paths are exercised by the same tests.
**Why not just require ripgrep:** the reverse index is load-bearing. Without it the agent
cannot cross a repository boundary, which makes the entire target incident class (§1.4)
unsolvable. A hard dependency on an optional binary turns "rg is not installed" into
"the system cannot solve the problem it was built for", with no useful error. At real
repository scale ripgrep is much faster and remains the preferred path.

---

## D-008 — The Gate takes a `rules` parameter so the build order is demonstrable
**Date:** 2026-08-23
**Question:** §11.4 says phase 2 implements "the provenance-terminal check only", and §11.5
adds the Residue Rule in phase 3. Taken literally that means writing `gate()` twice.
**Choice:** `gate()` is written once, complete, and takes `rules=("T1","T2","timing")`.
Phase 2's acceptance test runs it with `rules=("T1",)`.
**Why this is better than two implementations:** it turns the build order into evidence.
`tests/test_gate.py` now contains two tests over the *same claim and the same ledger*: with
rule 1 only the single-cause claim is **accepted**, and with the Residue Rule added the
identical claim is **rejected**. That pair is a direct demonstration of the thesis in §2.2 --
that the Residue Rule is what converts a plausible one-cause answer into the two-cause one.
Two separate implementations could not show that, because they would differ in more than the
rule under test.

---

## D-009 — The offline Proposer is deliberately naive
**Date:** 2026-08-23
**Question:** How should `HeuristicProposer` (D-003) behave, given it must contain no
incident-specific knowledge?
**Choice:** It implements the *naive* policy §1.1 describes: restate the most severe anomaly
as if it were the cause, and only escalate when the Gate makes it. Each escalation is driven
entirely by the Gate's `next_question` -- the probe sends it looking for provenance, an
unexplained-residue rejection sends it looking for a second cause.
**Why:** this is the strongest available demonstration of the thesis. A deliberately naive
proposer plus the Gate reaches the correct multi-cause answer, which shows the depth is coming
from the Gate rather than from a clever prompt. It also makes the offline acceptance tests
meaningful instead of tautological: the proposer cannot pass them by knowing the answer,
because it does not know the answer.

---

## D-010 — Only a *grounded* claim may reduce the residue
**Date:** 2026-08-23
**Question:** §4.3's control flow runs `residue = residue - claim.explains` on the rejected
path. Does that apply to a claim rejected as machine state?
**Choice:** No. `agent.gate.grounded()` gates the subtraction: the residue shrinks only when
every cause in the claim resolves to a ledger row.
**Why:** a claim rejected under T1 has not explained anything — it restated the anomaly as its
own cause ("the metric dropped because the metric dropped"). Subtracting it deletes exactly
the residue the Residue Rule exists to act on. Observed directly during the build: with the
literal subtraction, the naive opening claims erased two of four anomalies, and the Gate then
accepted a **single-cause** answer at step 3 because nothing was left to object to. It reached
a plausible answer for entirely the wrong reason, which is the most dangerous kind of pass.
For a claim that named real changes but missed one, subtraction is still correct and is what
makes the loop converge.

---

## D-011 — Coupling uses the sharpest available evidence, and does not widen past it
**Date:** 2026-08-23
**Question:** How should the Proposer decide that a change could explain an anomaly?
**Choice:** Strict precedence in `HeuristicProposer._coupled_paths`: (1) if the anomaly names
an identifier (an ARN, a configuration key), only files carrying that identifier count;
(2) otherwise the configuration resolution chain for its entity; (3) only if neither yields
anything, broad literal and dependency links.
**Why:** widening is not free. Every extra file that counts as "coupled" is an anomaly the
Proposer believes it has explained, and §5.5 states that overclaiming is worse than
underclaiming because it hides the gap leading to the remaining cause. Observed during the
build: with dependency links applied unconditionally, an unrelated configuration edit appeared
to account for the authorization anomaly, the residue emptied, and the Gate accepted a
one-cause answer. Adding evidence made the system *worse* until precedence was imposed.

---

## D-012 — `why_this_value` is the tool that does the work, and it is directional
**Date:** 2026-08-23
**Question:** §11.6 schedules `why_this_value` for phase 4, but incident 001 could not be
solved correctly without it. Build it early?
**Choice:** Yes, built with phase 3.
**Why it is not interchangeable with the reverse index:** every other retrieval path here is
*associative* — it reports that two files mention the same name — and association is symmetric,
so it cannot distinguish the file that supplied a value from a file that merely mentions it.
In this incident the wrong destination is named in three places and only one is implicated. A
resolution chain is *directional*: it can report the hop that was supposed to supply a value
and did not. That absence has no audit event, emits no metric, and appears in no diff. §5.4.3
calls this the tool no surveyed vendor offers; building the rest first made it clear why the
incident is unsolvable without it.

---

## D-013 — Step repetition ends the run as a dead end, not as budget exhaustion
**Date:** 2026-08-23
**Question:** Not raised by the specification. §5.9.3 requires retry limits and Appendix A
records step repetition in 15.7% of multi-agent traces.
**Observed:** a Proposer that cannot answer the outstanding question re-proposed an identical
claim and collected an identical rejection until the step cap, then exited T4 blaming the
budget. The exit was honest about being unresolved but wrong about why.
**Choice:** `Runner.MAX_CLAIM_REPEATS = 2`. An identical (cause_ids, explains) signature
proposed a third time ends the run as UNRESOLVED with the frontier, and the stated reason names
the dead end. A T4 that misattributes its own cause is a misleading handoff to a human.
