"""Incident 008 -- the poisoned queue. Spec section 9, class H.

The literal poisoned queue, and the reason it is in the range: **the system must not terminate
there.** "The queue is blocked" is the archetypal halfway root cause from section 1.1 -- a true
statement about machine state, with no author, no rollback and no owner to page.

Someone renames a field in the event orders-api publishes. The publisher is happy. The
consumer cannot parse the new shape, halts on the first bad record, and queue depth begins to
climb. Every visible signal is about the queue; the cause is a one-line rename in the
publisher, and it is what a person actually has to revert.

The upstream service is entirely healthy throughout: 201s, normal latency, zero errors. An
agent that reasons from "where are the errors" looks at the consumer and finds nothing to fix.
"""
from __future__ import annotations

from incidents.framework import Edit, Incident, Rollout, WorldMutation

DAY = "2026-08-20"
WINDOW = ("08:00", "10:15")
FIRST_SYMPTOM = "09:24"
OPENED_AT = "09:41"

ORDERS = "sam-okafor <sam@acme.example>"
PLATFORM = "dee-mensah <dee@acme.example>"
DATA = "rin-tanaka <rin@acme.example>"


def _wire_queue(world) -> None:
    """The consumer parses events by field name and halts on anything it cannot read."""
    from env.sim.pipeline import Queue

    world.queue = Queue(malformed_when=lambda event: "order_id" not in event)


CAUSE = Edit(
    ts="09:23", repo="orders-api", path="app/publish.py",
    old='        "order_id": order["order_id"],',
    new='        "id": order["order_id"],',
    message="publish: shorten the event key to id\n\n"
            "Aligning the orders event with the shorter key the other streams use. The value "
            "is identical; only the key name changes.",
    author=ORDERS, team="Orders",
)
ROLLOUT = Rollout(ts="09:24", deployment="orders-api", note="deploy orders-api")

RED_HERRINGS = [
    Edit(ts="08:33", repo="analytics-etl", path="etl/extract.py",
         old="def source_table(env=None):", new="def source_table(env=None):  # noqa: D103",
         message="lint: silence a docstring warning", author=DATA, team="Data"),
    Edit(ts="09:02", repo="platform-config", path="overlays/prod/analytics.yaml",
         old='REPORT_WINDOW_MINUTES: "5"', new='REPORT_WINDOW_MINUTES: "10"',
         message="config: widen the analytics reporting window", author=PLATFORM,
         team="Platform", effect="config_sync"),
    Edit(ts="09:48", repo="platform-iac", path="modules/iam/s3.tf",
         old='      "s3:ListBucket",',
         new='      "s3:ListBucket",\n      "s3:GetBucketTagging",',
         message="iam: bucket tagging for the cost dashboard", author=PLATFORM,
         team="Platform", effect="terraform_apply"),
]


def build() -> Incident:
    return Incident("008_poison_record_schema_rename", DAY, [CAUSE] + RED_HERRINGS,
                    world_changes=[ROLLOUT], setup=_wire_queue)


META = {
    "id": "008_poison_record_schema_rename", "day": DAY,
    "window_start": WINDOW[0], "window_end": WINDOW[1],
    "first_symptom": FIRST_SYMPTOM, "opened_at": OPENED_AT,
    "alert": "orders-queue depth climbing without bound since 09:24 and the consumer has "
             "stopped committing offsets. orders-api is healthy: 201s, normal latency, zero "
             "errors. Poison records detected in the stream.",
}
