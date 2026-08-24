"""Incident 010 -- a cascading, multi-hop failure. Spec section 9, class I.

The AWS shape (Appendix B.3). One change, three services degraded in sequence, each failing
for a different reason and each looking like its own incident from inside.

    09:26  the shared ConfigMap key that names the orders table is renamed
    09:27  orders-api rolls, loses the key, falls back to its hardcoded default and is
           refused by IAM                                      -> writes fail
    09:27  no rows land in the source table                    -> orders_created collapses
    09:27  no events are published                             -> the event stream goes silent

Three teams get paged, in three channels, about three different symptoms. Each has a plausible
local explanation and none of them is wrong: writes really are being denied, the metric really
has collapsed, the stream really is silent. All three are downstream of one line.

What this class tests is whether the **output is a chain rather than a point**. Naming the
cause is necessary and not sufficient: Appendix B.3 records the AWS incident's source being
identified in 54 minutes and the outage lasting 15 hours 32, so diagnosis was about 6% of it.
The value is in the blast radius and the ordered remediation -- knowing who else is affected
and what has to happen first.
"""
from __future__ import annotations

from incidents.framework import Edit, Incident, Rollout

DAY = "2026-08-20"
WINDOW = ("08:00", "10:15")
FIRST_SYMPTOM = "09:27"
OPENED_AT = "09:31"

PLATFORM = "dee-mensah <dee@acme.example>"
DATA = "rin-tanaka <rin@acme.example>"
ORDERS = "sam-okafor <sam@acme.example>"


def _wire_queue(world) -> None:
    from env.sim.pipeline import Queue

    # Nothing is malformed here. The stream simply stops receiving, which is a different
    # signature from the poisoned queue of class H and must not be confused with it.
    world.queue = Queue()


CAUSE = Edit(
    ts="09:26", repo="platform-config", path="overlays/prod/orders.yaml",
    old="ORDERS_TABLE: orders-prod",
    new="ORDERS_TABLE_REF: orders-prod",
    message="config: rename table keys to the _REF convention\n\n"
            "Third of four repos. Billing and inventory are already on _REF.",
    author=PLATFORM, team="Platform", effect="config_sync",
)
ROLLOUT = Rollout(ts="09:27", deployment="orders-api", note="config sync rollout")

RED_HERRINGS = [
    Edit(ts="08:22", repo="analytics-etl", path="etl/metrics.py",
         old="from .extract import extract_since",
         new="from .extract import extract_since  # noqa: F401",
         message="lint: silence an unused-import warning", author=DATA, team="Data"),
    Edit(ts="08:58", repo="orders-api", path="README.md",
         old="**On-call:** #orders-oncall",
         new="**On-call:** #orders-oncall (see the runbook)",
         message="docs: link the runbook", author=ORDERS, team="Orders"),
    Edit(ts="09:14", repo="platform-iac", path="modules/iam/s3.tf",
         old='      "s3:ListBucket",',
         new='      "s3:ListBucket",\n      "s3:GetBucketTagging",',
         message="iam: bucket tagging for the cost dashboard", author=PLATFORM,
         team="Platform", effect="terraform_apply"),
]


def build() -> Incident:
    return Incident("010_cascade_three_hops", DAY, [CAUSE] + RED_HERRINGS,
                    world_changes=[ROLLOUT], setup=_wire_queue)


META = {
    "id": "010_cascade_three_hops", "day": DAY,
    "window_start": WINDOW[0], "window_end": WINDOW[1],
    "first_symptom": FIRST_SYMPTOM, "opened_at": OPENED_AT,
    "alert": "Three pages in four minutes. orders-api: write failures with AccessDenied. "
             "analytics-etl: orders_created collapsed to the batch-importer floor. "
             "orders-queue: the event stream has gone silent. Three teams, three channels.",
}
