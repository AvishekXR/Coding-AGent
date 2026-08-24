"""Incident 004 -- a sandbox endpoint in a dependency team's repository. Spec section 9, class C.

The originating brief's own example. Somebody on the Platform team, testing a provider
migration, points the shared production ConfigMap at the payment provider's *sandbox*
endpoint and does not put it back. The sandbox answers -- that is what makes this hard. It
answers with sandbox limits, and declines most production authorisations.

Nothing in `orders-api` changed. The service that is failing has no commits, no deploy and no
image change. Every signal an incumbent tool reasons about is clean, and the cause is one line
in a repository owned by another team that the on-call engineer has probably never opened.

The reverse index is the only thing that crosses that boundary: `orders-api` reads
`PAYMENTS_ENDPOINT`, and the file that supplies it lives in `platform-config`.
"""
from __future__ import annotations

from incidents.framework import Edit, Incident, Rollout

DAY = "2026-08-20"
WINDOW = ("08:00", "10:15")
FIRST_SYMPTOM = "09:29"
OPENED_AT = "09:33"

PLATFORM = "dee-mensah <dee@acme.example>"
DATA = "rin-tanaka <rin@acme.example>"
ORDERS = "sam-okafor <sam@acme.example>"

PAYMENTS_PROD = "https://api.payments-provider.example/v2/authorise"
PAYMENTS_SANDBOX = "https://sandbox.payments-provider.example/v2/authorise"


def _wire_payments(world) -> None:
    from env.sim.pipeline import Dependency

    world.payments = Dependency(
        name="payments",
        known={
            PAYMENTS_PROD: {"component": "api.payments-provider.example", "latency": 55},
            # The sandbox is up, healthy and answering. It simply refuses most real
            # authorisations, which is exactly what a sandbox is for.
            PAYMENTS_SANDBOX: {"component": "sandbox.payments-provider.example",
                               "latency": 70,
                               "declines": "sandbox authorisation ceiling"},
        },
        timeout_ms=500,
    )


CAUSE = Edit(
    ts="09:28", repo="platform-config", path="overlays/prod/orders.yaml",
    old="PAYMENTS_ENDPOINT: " + PAYMENTS_PROD,
    new="PAYMENTS_ENDPOINT: " + PAYMENTS_SANDBOX,
    message="config: point orders at the provider sandbox for migration testing\n\n"
            "Temporary, for the v2 endpoint migration dry run. Reverting after the test.",
    author=PLATFORM, team="Platform", effect="config_sync",
)
ROLLOUT = Rollout(ts="09:29", deployment="orders-api", note="config sync rollout")

RED_HERRINGS = [
    Edit(ts="08:16", repo="analytics-etl", path="README.md",
         old="**On-call:** #data-oncall", new="**On-call:** #data-oncall (Q3 rotation)",
         message="docs: note the Q3 rotation", author=DATA, team="Data"),
    # A change inside the failing service, before the symptom, that does nothing. This is
    # what a tool reasoning about the failing service's own history will find.
    Edit(ts="08:49", repo="orders-api", path="app/store.py",
         old='"""Persistence layer. Writes each accepted order to DynamoDB."""',
         new='"""Persistence layer. Writes each accepted order to DynamoDB (see ADR-31)."""',
         message="docs: reference ADR-31 in the store module", author=ORDERS, team="Orders"),
    Edit(ts="09:05", repo="platform-config", path="overlays/prod/analytics.yaml",
         old='REPORT_WINDOW_MINUTES: "5"', new='REPORT_WINDOW_MINUTES: "10"',
         message="config: widen the analytics reporting window", author=PLATFORM,
         team="Platform", effect="config_sync"),
    Edit(ts="09:52", repo="platform-iac", path="modules/iam/s3.tf",
         old='      "s3:ListBucket",',
         new='      "s3:ListBucket",\n      "s3:GetBucketTagging",',
         message="iam: bucket tagging for the cost dashboard", author=PLATFORM,
         team="Platform", effect="terraform_apply"),
]


def build() -> Incident:
    return Incident("004_staging_endpoint_in_shared_config", DAY, [CAUSE] + RED_HERRINGS,
                    world_changes=[ROLLOUT], setup=_wire_payments)


META = {
    "id": "004_staging_endpoint_in_shared_config", "day": DAY,
    "window_start": WINDOW[0], "window_end": WINDOW[1],
    "first_symptom": FIRST_SYMPTOM, "opened_at": OPENED_AT,
    "alert": "orders-api 4xx rate rose to 100% at 09:29. Every error is HTTP 402 with "
             "'payments declined: sandbox authorisation ceiling'. orders-api has no deploy, "
             "no commit and no image change today.",
}
