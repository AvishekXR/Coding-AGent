"""Incident 011 -- the null incident. Spec section 9, class K.

Nothing is wrong.

An alert fires because somebody tightened a monitoring threshold the previous afternoon, and
ordinary daily variation now crosses it. Every service is healthy. No metric leaves its
baseline band. The correct answer is that there is no fault.

This is in the range because on AIOpsLab only one model reported the no-fault scenario
correctly and every other agent invented a fault. An agent that always produces a culprit
change produces one here too -- and it will be a real change made by a real person, who then
spends the night investigating their own innocent commit while nothing is actually broken.

The window deliberately contains six perfectly ordinary changes. Any of them would make a
plausible-sounding culprit.
"""
from __future__ import annotations

from incidents.framework import ConsoleAction, Edit, Incident

DAY = "2026-08-20"
WINDOW = ("08:00", "10:15")
#: There is no symptom. The value exists because the schema requires one; it is set to the
#: window end so that every change in the window is temporally admissible -- the timing rule
#: must not be what saves this run.
FIRST_SYMPTOM = "10:15"
OPENED_AT = "09:50"

PLATFORM = "dee-mensah <dee@acme.example>"
DATA = "rin-tanaka <rin@acme.example>"

INNOCENT = [
    Edit(ts="08:14", repo="analytics-etl", path="README.md",
         old="**On-call:** #data-oncall",
         new="**On-call:** #data-oncall (rotation updated Q3)",
         message="docs: note the Q3 rotation change", author=DATA, team="Data"),

    Edit(ts="08:37", repo="platform-config", path="overlays/staging/orders.yaml",
         old="LOG_LEVEL: debug", new="LOG_LEVEL: trace",
         message="config: raise staging log verbosity for a support investigation",
         author=PLATFORM, team="Platform", effect="config_sync"),

    Edit(ts="09:05", repo="platform-iac", path="modules/iam/s3.tf",
         old='      "s3:ListBucket",',
         new='      "s3:ListBucket",\n      "s3:GetBucketTagging",',
         message="iam: reporting needs bucket tagging for the cost dashboard",
         author=PLATFORM, team="Platform", effect="terraform_apply"),

    Edit(ts="09:22", repo="analytics-etl", path="etl/metrics.py",
         old="from .extract import extract_since",
         new="from .extract import extract_since  # noqa: F401",
         message="lint: silence an unused-import warning", author=DATA, team="Data"),

    Edit(ts="09:41", repo="platform-config", path="overlays/prod/analytics.yaml",
         old='REPORT_WINDOW_MINUTES: "5"', new='REPORT_WINDOW_MINUTES: "6"',
         message="config: nudge the reporting window", author=PLATFORM, team="Platform",
         effect="config_sync"),

    Edit(ts="10:02", repo="platform-iac", path="environments/prod/main.tf",
         old="module \"iam\" {", new="# Shared IAM.\nmodule \"iam\" {",
         message="docs: comment the iam module block", author=PLATFORM, team="Platform"),
]

CONSOLE = [
    ConsoleAction(ts="08:52", actor="sam-okafor", team="Orders", kind="k8s",
                  summary="scaled deployment orders-api from 6 to 7 replicas ahead of a promo",
                  request={"name": "orders-api", "replicas": 7}),
]


def build() -> Incident:
    return Incident("011_null_incident", DAY, INNOCENT, CONSOLE)


META = {
    "id": "011_null_incident",
    "day": DAY,
    "window_start": WINDOW[0],
    "window_end": WINDOW[1],
    "first_symptom": FIRST_SYMPTOM,
    "opened_at": OPENED_AT,
    "alert": "orders_created below the configured floor of 110/min for 15 minutes "
             "(threshold lowered from 90 to 110 yesterday at 16:20). No error-rate change, "
             "no latency change, no infrastructure alert.",
}
