"""Incident 001 -- the silent write redirect. Spec section 8.

Two approved, individually harmless changes from the same team, 22 minutes apart, that
together redirect production orders into the staging table with no error of any kind.

    python -m incidents.inject 001

Ten innocent changes and two console actions share the window. Several of them are *better*
distractors than the causes on a naive ranking: the 09:18 prod ConfigMap edit touches the very
service whose metric is broken, and the 09:26 change lands in the consumer. Any ranker that
scores on "recent + prod + related service" prefers the wrong ones.
"""
from __future__ import annotations

from incidents.framework import ConsoleAction, Edit, Incident, rollout_only

DAY = "2026-08-20"
WINDOW = ("08:00", "10:15")
FIRST_SYMPTOM = "09:35"      # first minute whose writes land in the wrong table
OPENED_AT = "10:14"          # business-metric alert, 40 minutes later

PLATFORM = "dee-mensah <dee@acme.example>"
DATA = "rin-tanaka <rin@acme.example>"
ORDERS = "sam-okafor <sam@acme.example>"

# --- the two causes ----------------------------------------------------------

CAUSE_IAM = Edit(
    ts="09:12", repo="platform-iac", path="modules/iam/dynamodb.tf",
    old="""      "dynamodb:UpdateItem",
    ]
    resources = [
      "arn:aws:dynamodb:*:*:table/orders-prod",
    ]""",
    new="""      "dynamodb:UpdateItem",
    ]
    resources = [
      "arn:aws:dynamodb:*:*:table/orders-*",
    ]""",
    message="iam: collapse per-table orders ARNs into one prefix\n\n"
            "Every orders service needs the same four actions against its own table. Three\n"
            "near-identical statements is noise; one prefixed ARN covers them and removes\n"
            "the duplication. No new actions are granted.",
    author=PLATFORM, team="Platform", effect="terraform_apply",
)

CAUSE_CONFIG = Edit(
    ts="09:34", repo="platform-config", path="overlays/prod/orders.yaml",
    old="ORDERS_TABLE: orders-prod",
    new="ORDERS_TABLE_NAME: orders-prod",
    message="config: standardise table keys on the _NAME suffix\n\n"
            "Brings orders in line with the naming convention already used by billing and\n"
            "inventory. Value is unchanged.",
    author=PLATFORM, team="Platform", effect="config_sync",
)

# The rollout is what makes the rename take hold. A ConfigMap edit alone changes nothing in a
# running pod, which is why the first symptom trails the change by a minute.
ROLLOUT = rollout_only("09:35", "orders-api", "config sync rollout: orders-api")

# --- innocent changes sharing the window -------------------------------------

RED_HERRINGS = [
    Edit(ts="08:05", repo="analytics-etl", path="etl/extract.py",
         old='"""Pulls orders from the source table for the reporting pipeline."""',
         new='"""Pulls orders from the source table for the reporting pipeline.\n\n'
             'Scans are windowed; see metrics.py for the reporting window.\n"""',
         message="docs: expand the extract module docstring",
         author=DATA, team="Data"),

    Edit(ts="08:23", repo="platform-config", path="overlays/staging/orders.yaml",
         old="LOG_LEVEL: debug", new="LOG_LEVEL: info",
         message="config: quieten staging logs",
         author=PLATFORM, team="Platform", effect="config_sync"),

    Edit(ts="08:41", repo="platform-iac", path="modules/iam/s3.tf",
         old='      "s3:ListBucket",',
         new='      "s3:ListBucket",\n      "s3:GetBucketLocation",',
         message="iam: reporting needs GetBucketLocation for cross-region reads",
         author=PLATFORM, team="Platform", effect="terraform_apply"),

    Edit(ts="09:02", repo="analytics-etl", path="README.md",
         old="reporting metrics, including", new="reporting metrics including",
         message="docs: fix comma splice in README",
         author=DATA, team="Data"),

    # The strongest distractor in the set: a real production ConfigMap change, in the same
    # repository and the same overlay directory as the true cause, 16 minutes earlier,
    # affecting the exact service whose metric is about to break.
    Edit(ts="09:18", repo="platform-config", path="overlays/prod/analytics.yaml",
         old='REPORT_WINDOW_MINUTES: "5"', new='REPORT_WINDOW_MINUTES: "10"',
         message="config: widen the analytics reporting window to 10 minutes",
         author=PLATFORM, team="Platform", effect="config_sync"),

    Edit(ts="09:26", repo="analytics-etl", path="etl/extract.py",
         old="def extract_since(client, since, env=None):",
         new="def extract_since(client, since, env=None, retries=3):",
         message="etl: add a retry parameter to extract_since",
         author=DATA, team="Data"),

    # Everything below postdates the first symptom at 09:35 and must be rejected by the
    # Gate's timing-sanity rule (spec 5.6 rule 3) even if a proposer reaches for it.
    Edit(ts="09:40", repo="platform-iac", path="modules/iam/s3.tf",
         old="data \"aws_iam_policy_document\" \"reports_s3\" {",
         new="# Reporting bucket access.\ndata \"aws_iam_policy_document\" \"reports_s3\" {",
         message="iam: comment the reports policy document",
         author=PLATFORM, team="Platform", effect="terraform_apply"),

    Edit(ts="09:47", repo="platform-config", path="overlays/staging/orders.yaml",
         old='ORDER_MAX_ITEMS: "50"', new='ORDER_MAX_ITEMS: "75"',
         message="config: match staging item cap to prod",
         author=PLATFORM, team="Platform", effect="config_sync"),

    Edit(ts="09:55", repo="analytics-etl", path="etl/metrics.py",
         old="from .extract import extract_since",
         new="from .extract import extract_since  # noqa: F401",
         message="lint: silence an unused-import warning",
         author=DATA, team="Data"),

    Edit(ts="10:03", repo="platform-iac", path="environments/prod/main.tf",
         old="module \"iam\" {", new="# Shared IAM for every production service.\nmodule \"iam\" {",
         message="docs: comment the iam module block",
         author=PLATFORM, team="Platform"),
]

# Changes that exist in no repository at all.
CONSOLE = [
    ConsoleAction(ts="09:20", actor="sam-okafor", team="Orders", kind="k8s",
                  summary="scaled deployment orders-api from 6 to 8 replicas (traffic ramp)",
                  request={"name": "orders-api", "replicas": 8}),
    ConsoleAction(ts="09:50", actor="dee-mensah", team="Platform", kind="cloudtrail",
                  event_name="AttachRolePolicy",
                  summary="attached ReadOnlyAccess to the on-call debugging role",
                  request={"roleName": "oncall-debug", "policyArn": "arn:aws:iam::aws:policy/ReadOnlyAccess"}),
]


def build() -> Incident:
    edits = [CAUSE_IAM, CAUSE_CONFIG] + RED_HERRINGS
    return Incident("001_silent_write_redirect", DAY, edits, CONSOLE,
                    world_changes=[ROLLOUT])


META = {
    "id": "001_silent_write_redirect",
    "day": DAY,
    "window_start": WINDOW[0],
    "window_end": WINDOW[1],
    "first_symptom": FIRST_SYMPTOM,
    "opened_at": OPENED_AT,
    "alert": "orders_created down 94% over 15 minutes with no change in error rate "
             "(analytics-etl business metric). No infrastructure alert fired.",
}
