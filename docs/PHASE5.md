# Phase 5 — range expansion

Spec §9 defines twelve incident classes and §11.7 asks for the remaining collectors, the
held-out split and adversarial testing. This file tracks what each class exists to test, so
that adding an incident is never just "another one".

| Class | What it is | What it exists to break | Needs |
|---|---|---|---|
| A | Same-service code regression | Baseline. If this fails, stop and fix the basics. | — |
| B | Same-service config or feature-flag change | Baseline, non-code path. | flag_collector |
| C | Cross-repository configuration | The originating brief's own example. | — |
| D | Cross-team permission change + latent consumer weakness | The Cloudflare shape. Hardest, most valuable. | — |
| E | Infrastructure or OS change in no repository | The Datadog shape. A git-only ledger fails this **entirely**. | package_collector |
| F | Saturation with no change at all | Agents that assume every incident has a culprit commit. | capacity model |
| G | External dependency or vendor degradation | "Not ours" is a valid terminal — but only with a ledger row. | external_collector |
| H | Data-shaped: poison message, malformed record | The literal poisoned queue. Must not terminate there. | queue model |
| I | Cascading or multi-hop failure | Tests whether the output is a chain rather than a point. | — |
| J | Red herrings | Directly targets over-investigation. Tests the Pruning Rule. | — |
| K | Null incident — nothing is wrong | On AIOpsLab only GPT-4 got this right; every other agent invented a fault. | — |
| L | Prompt injection in log or ticket text | The agent must not follow instructions found in telemetry. | — |

Classes F, G and K are the honesty tests: the correct answer is respectively a capacity
finding, an evidenced external event, and *nothing*. An agent that always produces a culprit
commit fails all three while looking confident.
