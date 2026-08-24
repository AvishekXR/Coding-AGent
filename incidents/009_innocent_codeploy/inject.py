"""Incident 009 -- red herrings. Spec section 9, class J.

Directly targets the over-investigation failure of section 1.3. On ITBench, models that
investigated *longer* scored *worse*, and the benchmark authors' explanation was that
over-investigating agents surface co-occurring mechanisms and symptoms as false positives.

So this window is stacked against curiosity. The real cause is a quiet ConfigMap key rename at
08:52. Four minutes before the first symptom, an entirely innocent deploy of the failing
service lands -- a genuine code change, in the right repository, at almost exactly the right
time, by the team that owns the service. It is the single most attractive wrong answer
available and it explains nothing.

There are eight other changes besides. The Pruning Rule (2.3) is what should discard them
without investigation: a candidate that would reduce no residue is scored and discarded, never
followed. A run that names the innocent deploy fails; a run that names it *alongside* the real
cause also fails, on precision.
"""
from __future__ import annotations

from incidents.framework import ConsoleAction, Edit, Incident, Rollout

DAY = "2026-08-20"
WINDOW = ("08:00", "10:15")
FIRST_SYMPTOM = "08:53"
OPENED_AT = "09:04"

PLATFORM = "dee-mensah <dee@acme.example>"
DATA = "rin-tanaka <rin@acme.example>"
ORDERS = "sam-okafor <sam@acme.example>"

CAUSE = Edit(
    ts="08:52", repo="platform-config", path="overlays/prod/orders.yaml",
    old="ORDERS_TABLE: orders-prod",
    new="ORDERS_TABLE_ID: orders-prod",
    message="config: rename the table key for consistency with billing",
    author=PLATFORM, team="Platform", effect="config_sync",
)
ROLLOUT = Rollout(ts="08:53", deployment="orders-api", note="config sync rollout")

RED_HERRINGS = [
    # The most attractive wrong answer in the set: a real deploy of the failing service,
    # by the team that owns it, minutes before the symptom, that changes no behaviour.
    Edit(ts="08:49", repo="orders-api", path="app/store.py",
         old="    def put(self, order, at):",
         new="    def put(self, order, at):  # noqa: D102",
         message="orders-api v2.14.1: lint pass and dependency bump",
         author=ORDERS, team="Orders"),

    Edit(ts="08:05", repo="analytics-etl", path="README.md",
         old="**On-call:** #data-oncall", new="**On-call:** #data-oncall (Q3 rotation)",
         message="docs: note the Q3 rotation", author=DATA, team="Data"),
    Edit(ts="08:18", repo="platform-iac", path="modules/iam/s3.tf",
         old='      "s3:ListBucket",',
         new='      "s3:ListBucket",\n      "s3:GetBucketTagging",',
         message="iam: bucket tagging for the cost dashboard", author=PLATFORM,
         team="Platform", effect="terraform_apply"),
    Edit(ts="08:31", repo="platform-config", path="overlays/staging/orders.yaml",
         old="LOG_LEVEL: debug", new="LOG_LEVEL: info",
         message="config: quieten staging logs", author=PLATFORM, team="Platform",
         effect="config_sync"),
    Edit(ts="08:44", repo="analytics-etl", path="etl/metrics.py",
         old="from .extract import extract_since",
         new="from .extract import extract_since  # noqa: F401",
         message="lint: silence an unused-import warning", author=DATA, team="Data"),
    # Everything below postdates the first symptom and must fall to the timing rule.
    Edit(ts="09:11", repo="platform-config", path="overlays/prod/analytics.yaml",
         old='REPORT_WINDOW_MINUTES: "5"', new='REPORT_WINDOW_MINUTES: "10"',
         message="config: widen the analytics reporting window", author=PLATFORM,
         team="Platform", effect="config_sync"),
    Edit(ts="09:26", repo="analytics-etl", path="etl/extract.py",
         old="def source_table(env=None):", new="def source_table(env=None):  # noqa: D103",
         message="lint: silence a docstring warning", author=DATA, team="Data"),
    Edit(ts="09:47", repo="platform-iac", path="environments/prod/main.tf",
         old='module "iam" {', new='# Shared IAM.\nmodule "iam" {',
         message="docs: comment the iam module block", author=PLATFORM, team="Platform"),
]

CONSOLE = [
    ConsoleAction(ts="08:38", actor="sam-okafor", team="Orders", kind="k8s",
                  summary="scaled deployment orders-api from 6 to 9 replicas for the promo",
                  request={"name": "orders-api", "replicas": 9}),
    ConsoleAction(ts="09:19", actor="dee-mensah", team="Platform", kind="cloudtrail",
                  event_name="AttachRolePolicy",
                  summary="attached ReadOnlyAccess to the on-call debugging role",
                  request={"roleName": "oncall-debug"}),
]


def build() -> Incident:
    return Incident("009_innocent_codeploy", DAY, [CAUSE] + RED_HERRINGS, CONSOLE,
                    world_changes=[ROLLOUT])


META = {
    "id": "009_innocent_codeploy", "day": DAY,
    "window_start": WINDOW[0], "window_end": WINDOW[1],
    "first_symptom": FIRST_SYMPTOM, "opened_at": OPENED_AT,
    "alert": "orders-api write failures since 08:53 with AccessDenied. A deploy of "
             "orders-api (v2.14.1) went out at 08:49, four minutes earlier.",
}
