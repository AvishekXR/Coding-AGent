"""The simulated world must reproduce incident 001 exactly as spec section 8 describes it.

These are not tests of the agent. They are tests that the *exam* is the exam we think it is.
If the world stops being silent, or stops being multi-cause, the incident quietly stops
testing what it exists to test and every downstream number becomes meaningless. Spec 10.1
names this as the largest single risk in the project.
"""
from __future__ import annotations

from datetime import datetime

import pytest

from env.sim.dynamo import table_arn
from util import git_ts


def _series(rows, metric):
    return [(r["ts"], r["value"]) for r in rows if r["metric"] == metric]


# --- the symptom -------------------------------------------------------------
def test_business_metric_drops_by_the_documented_percentage(incident_day_metrics):
    """truth.yaml claims 94%. Measure it rather than trusting it."""
    created = _series(incident_day_metrics, "orders_created")
    pre = [v for ts, v in created if ts[11:16] < "09:35"]
    post = [v for ts, v in created if ts[11:16] >= "09:36"]
    assert pre and post
    drop = 100 * (pre[0] - post[-1]) / pre[0]
    assert round(drop) == 94, "measured drop {:.1f}%".format(drop)


def test_the_incident_is_silent(incident_day_metrics):
    """Spec 8.3: all responses 200, latency normal, no error in any log, no alert fires."""
    assert all(v == 0.0 for _, v in _series(incident_day_metrics, "http_5xx_rate"))
    assert all(v == 0 for _, v in _series(incident_day_metrics, "dynamodb_access_denied"))
    lat = [v for _, v in _series(incident_day_metrics, "latency_p99_ms")]
    assert max(lat) - min(lat) < 20, "latency must stay unremarkable"


def test_writes_move_cleanly_from_prod_to_staging(incident_day_metrics):
    prod = _series(incident_day_metrics, "dynamodb_writes.orders-prod")
    staging = _series(incident_day_metrics, "dynamodb_writes.orders-staging")
    assert prod and staging
    assert max(ts for ts, _ in prod) < min(ts for ts, _ in staging)
    assert len(staging) == 40, "spec 8.3: forty minutes of orders in the wrong table"


def test_forty_minutes_of_real_orders_sit_in_the_staging_table(injected_world):
    world, _ = injected_world
    assert world.db.count("orders-staging") == 4000


# --- the two causes ----------------------------------------------------------
def test_the_guard_rail_existed_and_was_removed(injected_world):
    """The T1 verification of spec 8.5, asserted directly against the world.

    This is the single fact that separates the two-cause explanation from the one-cause one:
    before 09:12 the fallback write would have been refused.
    """
    world, _ = injected_world
    allowed, reason = world.iam.evaluate(
        "orders-api", "dynamodb:PutItem", table_arn("orders-staging")
    )
    assert allowed, "after the IAM widening the write is permitted"
    assert "orders-*" in reason

    from env.sim.render import parse_iam_terraform
    import subprocess

    repo = world.repos / "platform-iac"
    before = subprocess.run(
        ["git", "-C", str(repo), "show", "HEAD~:modules/iam/dynamodb.tf"],
        capture_output=True, text=True,
    )
    # HEAD may not be the IAM commit; find the commit that changed the file at 09:12.
    rev = subprocess.run(
        ["git", "-C", str(repo), "log", "--format=%H %ad", "--date=format:%H:%M",
         "--", "modules/iam/dynamodb.tf"],
        capture_output=True, text=True,
    ).stdout.split("\n")
    sha = next(line.split()[0] for line in rev if line.strip().endswith("09:12"))
    before = subprocess.run(
        ["git", "-C", str(repo), "show", sha + "~:modules/iam/dynamodb.tf"],
        capture_output=True, text=True,
    ).stdout

    docs = parse_iam_terraform(before)
    stmt = docs["orders_dynamodb"].statements[0]
    assert stmt.resources == ("arn:aws:dynamodb:*:*:table/orders-prod",)
    assert not stmt.matches("dynamodb:PutItem", table_arn("orders-staging")), \
        "before 09:12 the write to orders-staging must be denied"


def test_the_config_key_was_renamed_not_deleted(injected_world):
    world, _ = injected_world
    env = world.cluster.env_for("orders-api")
    assert "ORDERS_TABLE" not in env
    assert env["ORDERS_TABLE_NAME"] == "orders-prod", \
        "the value is unchanged; only the key moved -- which is why review passed it"


def test_orders_api_is_untouched_for_two_weeks(injected_world):
    """Spec 8.3: any tool reasoning only about the failing service's changes finds nothing."""
    import subprocess

    world, meta = injected_world
    last = subprocess.run(
        ["git", "-C", str(world.repos / "orders-api"), "log", "-1", "--format=%ad",
         "--date=format:%Y-%m-%d"],
        capture_output=True, text=True,
    ).stdout.strip()
    incident_day = datetime.fromisoformat(meta["day"])
    gap = (incident_day - datetime.fromisoformat(last)).days
    assert gap >= 14, "orders-api last changed {} ({} days before)".format(last, gap)


# --- the distractors ---------------------------------------------------------
def test_the_window_contains_enough_innocent_changes_to_be_a_real_problem(injected_world):
    """A window holding only the two causes would make ranking trivial and the score a lie."""
    import subprocess

    world, meta = injected_world
    total = 0
    for repo in ("orders-api", "analytics-etl", "platform-iac", "platform-config"):
        out = subprocess.run(
            ["git", "-C", str(world.repos / repo), "log", "--format=%ad",
             "--date=format:%Y-%m-%d %H:%M",
             "--since", git_ts(meta["window_start_ts"]),
             "--until", git_ts(meta["window_end_ts"])],
            capture_output=True, text=True,
        ).stdout
        total += len([l for l in out.splitlines() if l.strip()])
    assert total >= 12, "only {} changes in the window".format(total)


@pytest.mark.parametrize("path", [
    "overlays/prod/analytics.yaml",   # same repo + overlay as a cause, 16 min earlier
    "overlays/staging/orders.yaml",   # same filename as a cause, wrong overlay
])
def test_high_quality_distractors_are_present(injected_world, path):
    import subprocess

    world, meta = injected_world
    out = subprocess.run(
        ["git", "-C", str(world.repos / "platform-config"), "log", "--format=%H",
         "--since", git_ts(meta["window_start_ts"]),
         "--until", git_ts(meta["window_end_ts"]), "--", path],
        capture_output=True, text=True,
    ).stdout
    assert out.strip(), "distractor {} missing from the window".format(path)
