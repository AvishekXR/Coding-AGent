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
