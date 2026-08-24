"""Incident 002 -- validation tightened. Spec section 9, class A.

The baseline class. A developer on the owning team lowers a validation limit in the failing
service's own repository, and orders start being rejected.

This is the easy shape and it is in the range for exactly that reason: if the system cannot
solve a same-service code regression with a recent commit and a loud error rate, nothing
further is worth measuring (section 11.1 kill criterion). It is also the case incumbent
tooling already handles well, so the bar here is not to show an advantage -- only not to
regress.
"""
from __future__ import annotations

from incidents.framework import Edit, Incident, rollout_only

DAY = "2026-08-20"
WINDOW = ("08:00", "10:15")
FIRST_SYMPTOM = "09:21"
OPENED_AT = "09:26"

ORDERS = "sam-okafor <sam@acme.example>"
PLATFORM = "dee-mensah <dee@acme.example>"
DATA = "rin-tanaka <rin@acme.example>"

CAUSE = Edit(
    ts="09:20", repo="orders-api", path="app/validate.py",
    old="MAX_ITEMS = 10", new="MAX_ITEMS = 3",
    message="validate: tighten the per-order item cap\n\n"
            "Fraud has been seeing bulk orders used to test stolen cards. Three is around "
            "the 95th percentile of legitimate orders, so this should be invisible.",
    author=ORDERS, team="Orders",
)
ROLLOUT = rollout_only("09:21", "orders-api", "deploy orders-api")

RED_HERRINGS = [
    Edit(ts="08:11", repo="platform-config", path="overlays/staging/orders.yaml",
         old="LOG_LEVEL: debug", new="LOG_LEVEL: info",
         message="config: quieten staging logs", author=PLATFORM, team="Platform",
         effect="config_sync"),
    Edit(ts="08:44", repo="analytics-etl", path="etl/extract.py",
         old="def source_table(env=None):",
         new="def source_table(env=None):  # noqa: D103",
         message="lint: silence a docstring warning", author=DATA, team="Data"),
    Edit(ts="09:08", repo="platform-iac", path="modules/iam/s3.tf",
         old='      "s3:ListBucket",',
         new='      "s3:ListBucket",\n      "s3:GetBucketTagging",',
         message="iam: bucket tagging for the cost dashboard", author=PLATFORM,
         team="Platform", effect="terraform_apply"),
    # Postdates the first symptom: the timing rule must refuse it.
    Edit(ts="09:55", repo="platform-config", path="overlays/prod/analytics.yaml",
         old='REPORT_WINDOW_MINUTES: "5"', new='REPORT_WINDOW_MINUTES: "10"',
         message="config: widen the analytics reporting window", author=PLATFORM,
         team="Platform", effect="config_sync"),
]


def build() -> Incident:
    return Incident("002_validation_tightened", DAY, [CAUSE] + RED_HERRINGS,
                    world_changes=[ROLLOUT])


META = {
    "id": "002_validation_tightened", "day": DAY,
    "window_start": WINDOW[0], "window_end": WINDOW[1],
    "first_symptom": FIRST_SYMPTOM, "opened_at": OPENED_AT,
    "alert": "orders-api 4xx rate rose from 0% to roughly 62% at 09:21 and orders_created "
             "fell with it. Latency unchanged. Errors are HTTP 422 with the reason "
             "'too many items in one order'.",
}
