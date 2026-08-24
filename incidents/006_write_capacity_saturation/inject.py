"""Incident 006 -- saturation with no change at all. Spec section 9, class F.

Nobody changed anything. A scheduled marketing campaign goes live and traffic doubles into a
provisioned write ceiling that has been the same number for a year. Writes start being
throttled.

This class exists to break agents that assume every incident has a culprit commit. There is no
commit, no config edit, no flag, no package upgrade and no console action. The window contains
four ordinary changes and a `git log` that looks entirely normal, and an agent that must
produce a culprit will produce one of those four -- sending a real person to investigate a
change that did nothing.

The correct terminal is the documented traffic event: it is recorded, evidenced, and it is
genuinely what changed. The correct *remediation* is capacity, not a revert, which is why the
decision package matters more here than the cause does.
"""
from __future__ import annotations

from incidents.framework import Edit, ExternalEvent, Incident, WorldMutation

DAY = "2026-08-20"
WINDOW = ("08:00", "10:15")
FIRST_SYMPTOM = "09:16"
OPENED_AT = "09:20"

PLATFORM = "dee-mensah <dee@acme.example>"
DATA = "rin-tanaka <rin@acme.example>"
ORDERS = "sam-okafor <sam@acme.example>"


def _provision_capacity(world) -> None:
    """The write ceiling. Present in the baseline too -- it is not a change."""
    world.capacity.writes_per_minute = 120


#: The campaign. Recorded in advance, and evidenced: this is a documented external event, not
#: an assertion. It is also the only thing in the window that actually changed.
CAUSE_EVENT = ExternalEvent(
    ts="09:15", provider="acme-marketing", component="orders-api",
    title="Scheduled campaign launch: autumn promotion, forecast 2x order volume",
    status="confirmed", url="https://calendar.acme.example/events/promo-autumn",
)

#: Traffic actually doubles. No human touched the system.
TRAFFIC_RAMP = WorldMutation(
    ts="09:15",
    fn=lambda world, at: setattr(world, "traffic_multiplier", 2.0),
    note="campaign traffic arrives",
)

RED_HERRINGS = [
    Edit(ts="08:31", repo="analytics-etl", path="etl/metrics.py",
         old="from .extract import extract_since",
         new="from .extract import extract_since  # noqa: F401",
         message="lint: silence an unused-import warning", author=DATA, team="Data"),
    Edit(ts="08:52", repo="orders-api", path="README.md",
         old="**On-call:** #orders-oncall",
         new="**On-call:** #orders-oncall (see the runbook)",
         message="docs: link the runbook", author=ORDERS, team="Orders"),
    Edit(ts="09:07", repo="platform-config", path="overlays/staging/orders.yaml",
         old="LOG_LEVEL: debug", new="LOG_LEVEL: info",
         message="config: quieten staging logs", author=PLATFORM, team="Platform",
         effect="config_sync"),
    Edit(ts="09:11", repo="platform-iac", path="modules/iam/s3.tf",
         old='      "s3:ListBucket",',
         new='      "s3:ListBucket",\n      "s3:GetBucketTagging",',
         message="iam: bucket tagging for the cost dashboard", author=PLATFORM,
         team="Platform", effect="terraform_apply"),
]


def build() -> Incident:
    return Incident("006_write_capacity_saturation", DAY, RED_HERRINGS,
                    world_changes=[CAUSE_EVENT, TRAFFIC_RAMP],
                    setup=_provision_capacity)


META = {
    "id": "006_write_capacity_saturation", "day": DAY,
    "window_start": WINDOW[0], "window_end": WINDOW[1],
    "first_symptom": FIRST_SYMPTOM, "opened_at": OPENED_AT,
    "alert": "orders-api 4xx rate rose to roughly 40% at 09:16 with HTTP 429 and "
             "'provisioned write capacity exceeded'. Write latency p99 rose from 45ms to "
             "around 1s. Request volume doubled at the same moment. No deploy.",
}
