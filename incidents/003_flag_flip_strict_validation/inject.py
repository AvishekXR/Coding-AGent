"""Incident 003 -- a feature flag turned on. Spec section 9, class B.

Same service, non-code path. Somebody enables `orders.strict_validation` from the flag console
during a routine rollout, and the v2 rules behind it begin refusing half of production.

The point of this class is that **there is no commit**. The code that runs was merged weeks
ago and has not changed. `git log` across every repository shows nothing that explains this,
so an agent whose change ledger is built from version control alone will report that no change
was made -- confidently, and while half of all orders are being refused.

The flag console is the only place this change exists. That is why `flag_collector` is not
optional, and why the window contains a real, recent, innocent commit to the very file whose
rules are firing: it is what a git-only ledger will offer instead of the answer.
"""
from __future__ import annotations

from incidents.framework import Edit, FlagFlip, Incident

DAY = "2026-08-20"
WINDOW = ("08:00", "10:15")
FIRST_SYMPTOM = "09:18"
OPENED_AT = "09:24"

ORDERS = "sam-okafor <sam@acme.example>"
PLATFORM = "dee-mensah <dee@acme.example>"
DATA = "rin-tanaka <rin@acme.example>"

CAUSE = FlagFlip(ts="09:18", flag="orders.strict_validation", to=True,
                 actor="sam-okafor", team="Orders", scope="prod")

RED_HERRINGS = [
    Edit(ts="08:22", repo="analytics-etl", path="README.md",
         old="**On-call:** #data-oncall", new="**On-call:** #data-oncall (Q3 rotation)",
         message="docs: note the Q3 rotation", author=DATA, team="Data"),
    # The trap. A real commit, in the failing service, forty minutes before the symptom,
    # touching the exact file whose rules are now firing -- and it changed only a docstring.
    Edit(ts="08:38", repo="orders-api", path="app/validate.py",
         old='"""Order validation.', new='"""Order validation (see RFC-114).',
         message="docs: reference the validation RFC", author=ORDERS, team="Orders"),
    Edit(ts="09:02", repo="platform-iac", path="modules/iam/s3.tf",
         old='      "s3:ListBucket",',
         new='      "s3:ListBucket",\n      "s3:GetBucketLocation",',
         message="iam: cross-region reads for reporting", author=PLATFORM, team="Platform",
         effect="terraform_apply"),
]


def build() -> Incident:
    return Incident("003_flag_flip_strict_validation", DAY, RED_HERRINGS,
                    world_changes=[CAUSE])


META = {
    "id": "003_flag_flip_strict_validation", "day": DAY,
    "window_start": WINDOW[0], "window_end": WINDOW[1],
    "first_symptom": FIRST_SYMPTOM, "opened_at": OPENED_AT,
    "alert": "orders-api 4xx rate rose to roughly 50% at 09:18 with no deploy. Errors are "
             "HTTP 422 citing 'v2: item count above the per-order limit'. No commit in any "
             "repository corresponds to the change.",
}
