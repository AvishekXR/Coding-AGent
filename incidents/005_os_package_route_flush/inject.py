"""Incident 005 -- an OS package update with no repository. Spec section 9, class E.

The Datadog shape (Appendix B.2). An automatic security update arrives through a legacy
channel baked into the base image, on its default early-morning window. It restarts the
network daemon, which force-deletes the routes the CNI plugin manages, and a large fraction of
nodes drop off the network.

Deploys involved: zero. Commits involved: zero. Pull requests: zero. CI runs: zero.

A change ledger built from version control and the deploy pipeline shows a **clean board** for
this entire incident, and an agent reading that board will report -- accurately, and uselessly
-- that nothing changed. The three innocent commits in the window are the only things such an
agent can offer, and every one of them is wrong.

This class is the argument for `package_collector` existing at all.
"""
from __future__ import annotations

from incidents.framework import Edit, Incident, PackageUpgrade

DAY = "2026-08-20"
WINDOW = ("08:00", "10:15")
FIRST_SYMPTOM = "09:06"
OPENED_AT = "09:09"

PLATFORM = "dee-mensah <dee@acme.example>"
DATA = "rin-tanaka <rin@acme.example>"
ORDERS = "sam-okafor <sam@acme.example>"

CAUSE = PackageUpgrade(
    ts="09:05",
    package="systemd-networkd",
    to_version="252.5-2ubuntu3.4",
    channel="legacy security channel baked into the base image",
    scope="fleet",
    actor="unattended-upgrades",
    team="Platform",
    # The daemon restart flushes routes the CNI plugin owns. 55% of nodes lose networking.
    route_health=0.45,
)

RED_HERRINGS = [
    Edit(ts="08:19", repo="analytics-etl", path="etl/metrics.py",
         old="from .extract import extract_since",
         new="from .extract import extract_since  # noqa: F401",
         message="lint: silence an unused-import warning", author=DATA, team="Data"),
    Edit(ts="08:47", repo="orders-api", path="README.md",
         old="**On-call:** #orders-oncall",
         new="**On-call:** #orders-oncall (escalate to #platform-oncall out of hours)",
         message="docs: add the out-of-hours escalation path", author=ORDERS, team="Orders"),
    Edit(ts="09:33", repo="platform-iac", path="modules/iam/s3.tf",
         old='      "s3:ListBucket",',
         new='      "s3:ListBucket",\n      "s3:GetBucketTagging",',
         message="iam: bucket tagging for the cost dashboard", author=PLATFORM,
         team="Platform", effect="terraform_apply"),
]


def build() -> Incident:
    return Incident("005_os_package_route_flush", DAY, RED_HERRINGS,
                    world_changes=[CAUSE])


META = {
    "id": "005_os_package_route_flush", "day": DAY,
    "window_start": WINDOW[0], "window_end": WINDOW[1],
    "first_symptom": FIRST_SYMPTOM, "opened_at": OPENED_AT,
    "alert": "orders-api 5xx rate rose to roughly 55% at 09:06. Errors are HTTP 504 with "
             "'no route to host'. No deploy, no commit and no pull request corresponds to "
             "the change. Multiple services are affected simultaneously.",
}
