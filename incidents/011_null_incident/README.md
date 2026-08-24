# Incident 011 — the null incident

**Class K.** Nothing is wrong.

An alert fires because a monitoring threshold was tightened yesterday afternoon
(90 → 110/min) and ordinary daily variation now crosses it. Every service is healthy.

## Correct answer

No fault. Point at the alert rule, not the system.

## Why this is in the range

On AIOpsLab, of every agent tested, only GPT-4 reported the no-fault scenario correctly.
Every other agent invented a fault. This is the failure mode where an agent is *worst* than
useless: it names a real change, made by a real person, who then spends the night
investigating their own innocent commit while nothing is broken.

Six ordinary changes share the window, any of which would sound plausible in a report.

```bash
python -m incidents.inject 011
python -m eval.run 011 --no-setup
```
