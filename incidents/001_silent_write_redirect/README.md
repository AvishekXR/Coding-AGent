# Incident 001 — the silent write redirect

**Class D** — cross-team change plus a latent consumer weakness. Spec section 8.

Two approved, individually harmless changes from the same team, 22 minutes apart, together
redirect production orders into the staging table with no error of any kind.

## Timeline (2026-08-20)

| Time | Event |
|---|---|
| 09:12 | **Cause 1.** Platform widens an IAM resource ARN, `orders-prod` → `orders-*`, to remove duplication. Reviewed, approved, harmless alone. |
| 09:34 | **Cause 2.** Platform renames a ConfigMap key, `ORDERS_TABLE` → `ORDERS_TABLE_NAME`, for naming consistency. Reviewed, approved, harmless alone. |
| 09:35 | Rollout. Pods re-read env, no longer find `ORDERS_TABLE`, fall through to the 2023 hardcoded default `orders-staging`. **First symptom.** |
| 10:14 | Detected — 40 minutes later, from the business metric `orders_created`, not from any infrastructure alert. |

## Why it is hard

- **Silent.** Every response is 201. Latency normal. Zero 5xx. Zero `AccessDenied`.
- **Multi-cause.** Neither change is sufficient. Naming one scores zero.
- **No deploy in the failing service.** `orders-api` is untouched for two weeks.
- **Cross-change-type.** One cause is Terraform, the other a Kubernetes ConfigMap.
- **Rollback hazard.** `orders-staging` has a 24h TTL holding ~4,000 real orders.
- **Security finding.** The IAM wildcard survives the functional fix.

## The step that is the whole point

At **step 3** the investigation names the ConfigMap rename. That is a genuine human-authored
change, it passes T1, and it looks like a complete answer — it is what every surveyed product
would emit. Only the Residue Rule rejects it, because it leaves one anomaly unexplained:

> writes to `orders-staging` succeeded instead of returning `AccessDenied`

That unexplained residue is what forces the discovery of the IAM change.

## Distractors in the window

Ten innocent changes and two console actions share the incident window. Several rank *higher*
than the true causes on a naive "recent + production + related service" heuristic:

- **09:18** — a real prod ConfigMap edit, same repo and overlay directory as cause 2, sixteen
  minutes earlier, on the very service whose metric breaks.
- **09:26** — a change inside the downstream consumer, `analytics-etl`.
- **09:40, 09:47, 09:55, 10:03** — all postdate the first symptom and must be rejected by the
  Gate's timing rule.

## Run it

```bash
python -m incidents.inject 001
```
