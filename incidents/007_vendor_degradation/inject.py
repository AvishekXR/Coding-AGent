"""Incident 007 -- an external provider degradation. Spec section 9, class G.

The payment provider's authorisation endpoint stops answering. Nothing inside the organisation
changed. The correct answer is "not ours" -- and that is a legitimate terminal, but only when
a collector recorded a corroborating row (spec 5.6.2). The model asserting it is not enough.

The window is built to test both halves of that rule:

  * At 09:04 a **different** provider posts an unconfirmed "investigating" notice about an
    unrelated component. It lands in the ledger unevidenced, and the Gate must refuse to
    terminate on it -- which is correct behaviour during the first twenty minutes of an
    incident, when a status page is the least reliable source in the building.
  * At 09:12 the payment provider confirms an identified incident on the component this
    system actually calls. That row is evidenced, and it is the answer.

An agent that treats any status-page mention as an explanation stops at 09:04 and blames the
wrong vendor. An agent that refuses external causes on principle never gets there at all and
sends someone hunting for a commit that does not exist.
"""
from __future__ import annotations

from incidents.framework import Edit, ExternalEvent, Incident, WorldMutation

DAY = "2026-08-20"
WINDOW = ("08:00", "10:15")
FIRST_SYMPTOM = "09:13"
OPENED_AT = "09:16"

PLATFORM = "dee-mensah <dee@acme.example>"
DATA = "rin-tanaka <rin@acme.example>"

PAYMENTS_PROD = "https://api.payments-provider.example/v2/authorise"
PAYMENTS_STAGING = "https://sandbox.payments-provider.example/v2/authorise"


def _wire_payments(world) -> None:
    """Give the world a payments dependency before traffic starts."""
    from env.sim.pipeline import Dependency

    world.payments = Dependency(
        name="payments",
        known={
            PAYMENTS_PROD: {"component": "api.payments-provider.example", "latency": 55},
            PAYMENTS_STAGING: {"component": "sandbox.payments-provider.example", "latency": 70,
                               "declines": "staging authorisation ceiling"},
        },
        timeout_ms=500,
    )


#: The unconfirmed notice. Unevidenced, and about a component nothing here calls.
DISTRACTOR_EVENT = ExternalEvent(
    ts="09:04", provider="acme-cloud", component="object-storage-eu",
    title="Elevated error rates in object storage (EU)",
    status="investigating", url="https://status.acme-cloud.example/incidents/8821",
)

#: The real one. Confirmed, and about the component this system calls on every request.
CAUSE_EVENT = ExternalEvent(
    ts="09:12", provider="payments-provider", component="api.payments-provider.example",
    title="Card authorisation API returning timeouts in eu-west",
    status="identified", url="https://status.payments-provider.example/incidents/4417",
)

RED_HERRINGS = [
    Edit(ts="08:26", repo="analytics-etl", path="README.md",
         old="**On-call:** #data-oncall", new="**On-call:** #data-oncall (Q3 rotation)",
         message="docs: note the Q3 rotation", author=DATA, team="Data"),
    Edit(ts="08:58", repo="platform-config", path="overlays/staging/orders.yaml",
         old="LOG_LEVEL: debug", new="LOG_LEVEL: info",
         message="config: quieten staging logs", author=PLATFORM, team="Platform",
         effect="config_sync"),
]


def build() -> Incident:
    return Incident(
        "007_vendor_degradation", DAY, RED_HERRINGS,
        world_changes=[DISTRACTOR_EVENT, CAUSE_EVENT],
        setup=_wire_payments,
    )


META = {
    "id": "007_vendor_degradation", "day": DAY,
    "window_start": WINDOW[0], "window_end": WINDOW[1],
    "first_symptom": FIRST_SYMPTOM, "opened_at": OPENED_AT,
    "alert": "orders-api 5xx rate rose to 100% at 09:13. Every error is HTTP 504 from the "
             "payment authorisation call, at the 500ms timeout. No deploy, no config change "
             "and no commit in any repository.",
}
