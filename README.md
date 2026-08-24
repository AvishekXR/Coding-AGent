# HiSev Resolver

An incident-resolution agent that does not stop at the halfway root cause.

Implementation of `HiSev_Resolver_Build_Specification.docx` v1.0 (23 August 2026).

## The one-sentence thesis

Existing tooling terminates an investigation on **machine state** ("the queue is full",
"the env var is missing"). Machine state has no author, no rollback and no owner to page.
This system enforces, *in deterministic code*, that an investigation may only terminate at a
**human-authored change**, and only when nothing significant is left unexplained.

That check is `agent/gate.py`. It is the only novel component here and it never calls a model.

## Layout (spec §7.1)

| Path | What it is | LLM? |
|---|---|---|
| `env/` | The simulated company: 4 git repos, cluster, cloud, telemetry | No |
| `collectors/` | Fill the change ledger from git, IaC, k8s audit, CloudTrail | No |
| `ledger/` | SQLite change ledger + cross-repo reverse index | No |
| `indexer/` | Causal brief builder — anomaly extraction, log compression | No |
| `tools/` | The seven bounded MCP tools of §5.4 | No |
| `agent/` | Control loop, Proposer, **the Gate**, Verifier, decision package | Partial |
| `incidents/` | Seeded incidents + `truth.yaml` answer keys | No |
| `eval/` | Frozen rubric + grader (§10.2) | No |
| `safety/` | Read-only identity, audit log, budgets, injection defence | No |

## Quickstart

```bash
python -m env.seed          # bring the simulated world up, healthy
python -m eval.run 001      # inject incident 001, investigate, grade
```

See `DECISIONS.md` for every ambiguity resolved under spec §0.3.
