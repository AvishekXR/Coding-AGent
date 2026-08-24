"""Phase 1 acceptance test. Spec section 11.3.

    ledger + reverse index + the phase-1 tools. Acceptance: for any incident window, a ranked
    change list with every true cause present in the top ten.

Also pins the two contracts everything downstream depends on:
  * `Ledger.lookup()` returns a row ONLY for a human-authored change. If it can be made to
    resolve a machine state, rule T1 collapses and this stops being a new kind of system.
  * every tool result is bounded, audited, and carries no raw log content.
"""
from __future__ import annotations

import json

import pytest
import yaml

import config as cfg
from indexer.rank import Ranker
from ledger.ledger import Ledger
from tools.api import READ_ONLY_IDENTITY, ToolContext, ToolError, Tools
from tools.bounded import token_cost

TRUE_CAUSES = {
    ("platform-config", "overlays/prod/orders.yaml"),
    ("platform-iac", "modules/iam/dynamodb.tf"),
}


@pytest.fixture(scope="module")
def built(injected_world):
    """Run the collectors over the injected incident, then hand back ledger + metadata."""
    from collectors.run import collect_all
    from util import parse_ts
    from datetime import timedelta

    _, meta = injected_world
    t0 = parse_ts(meta["window_start_ts"]) - timedelta(days=30)
    t1 = parse_ts(meta["window_end_ts"])
    collect_all(t0, t1)
    return Ledger(), meta


@pytest.fixture
def tools(built):
    ledger, meta = built
    return Tools(ToolContext(ledger=ledger, run_id="test", incident_id=meta["id"]))


# --- the ledger --------------------------------------------------------------
def test_both_causes_are_in_the_ledger(built):
    ledger, meta = built
    rows = ledger.changes_between(meta["window_start_ts"], meta["window_end_ts"], limit=500)
    found = {(c.repo, c.path) for c in rows}
    assert TRUE_CAUSES <= found, "missing {}".format(TRUE_CAUSES - found)


def test_the_ledger_spans_more_than_git(built):
    """Spec 5.1: an incident class is unsolvable if its change source is missing. A git-only
    ledger fails whole classes, so the multi-source path must be exercised from phase 1."""
    ledger, meta = built
    rows = ledger.changes_between(meta["window_start_ts"], meta["window_end_ts"], limit=500)
    assert {c.source for c in rows} >= {"git", "iac"}


def test_lookup_resolves_a_human_change(built):
    ledger, meta = built
    rows = ledger.changes_between(meta["window_start_ts"], meta["window_end_ts"], limit=500)
    cause = next(c for c in rows if (c.repo, c.path) in TRUE_CAUSES)
    got = ledger.lookup(cause.id)
    assert got is not None and got.repo == cause.repo


@pytest.mark.parametrize("machine_state_id", [
    "orders-api is writing to the wrong table",
    "ORDERS_TABLE environment variable missing",
    "the queue is full",
    "obs:env-missing",
    "",
])
def test_lookup_never_resolves_machine_state(built, machine_state_id):
    """THE load-bearing contract for rule T1 (spec 5.6).

    Machine state has no ledger row. If any of these resolved, the Gate would accept a
    halfway root cause and the whole thesis would be unenforceable.
    """
    ledger, _ = built
    assert ledger.lookup(machine_state_id) is None


def test_external_prefix_is_accepted_by_lookup(built):
    """Claim.cause_ids may carry 'EXTERNAL:<ledger_id>' (spec 5.5)."""
    ledger, meta = built
    rows = ledger.changes_between(meta["window_start_ts"], meta["window_end_ts"], limit=5)
    assert ledger.lookup("EXTERNAL:" + rows[0].id) is not None


# --- the reverse index -------------------------------------------------------
def test_reverse_index_crosses_repository_boundaries(built):
    """Spec 5.2: this is the component that lets the agent leave the failing repository."""
    ledger, _ = built
    ms = ledger.who_mentions("ORDERS_TABLE")
    assert {m.repo for m in ms} >= {"orders-api", "platform-config"}


def test_reverse_index_covers_config_iac_and_docs_not_only_source(built):
    """Spec 5.2, explicitly. In the reference incident the decisive mention is in Terraform."""
    ledger, _ = built
    kinds = {r[0] for r in ledger.conn.execute("SELECT DISTINCT kind FROM mentions")}
    assert kinds >= {"code", "config", "iac", "docs"}


def test_the_iac_mention_is_findable(built):
    ledger, _ = built
    ms = ledger.who_mentions("orders-prod", kinds=["iac"])
    assert any(m.path.endswith("dynamodb.tf") for m in ms)


def test_index_rows_carry_a_freshness_stamp(built):
    """Spec 5.1.2 and Appendix E: freshness stamps on ledger and index rows."""
    ledger, _ = built
    row = ledger.conn.execute(
        "SELECT indexed_at FROM mentions LIMIT 1").fetchone()
    assert row["indexed_at"]
    row = ledger.conn.execute("SELECT collected_at FROM changes LIMIT 1").fetchone()
    assert row["collected_at"]


# --- the tools ---------------------------------------------------------------
def test_every_tool_result_is_within_the_token_bound(tools, built):
    _, meta = built
    results = [
        tools.changes_between(meta["window_start_ts"], meta["window_end_ts"], limit=200),
        tools.who_mentions("ORDERS_TABLE"),
        tools.who_mentions("orders-prod"),
        tools.owner_of("platform-iac"),
    ]
    for r in results:
        assert token_cost(r) <= cfg.DEFAULT.max_tool_tokens, \
            "tool result of {} tokens exceeds the 2,000-token rule".format(token_cost(r))


def test_over_limit_returns_grouped_counts_and_a_handle_never_silent_truncation(tools, built):
    """Spec 5.4.1, verbatim: 'NEVER truncate silently.'"""
    _, meta = built
    r = tools.changes_between(meta["window_start_ts"], meta["window_end_ts"], limit=3)
    assert r["_truncated"] is True
    assert r["_handle"]
    assert r["total"] > r["returned"]
    assert "by_source" in r["summary"] and "by_team" in r["summary"]
    rest = tools.get_handle(r["_handle"], offset=0, limit=100)
    assert rest["total"] == r["total"], "the handle must hold the whole window"


def test_every_tool_call_is_audited_with_identity(tools, built):
    ledger, meta = built
    tools.owner_of("orders-api")
    rows = ledger.audit_log("test")
    assert rows, "no audit rows written"
    assert all(r["identity"] == READ_ONLY_IDENTITY for r in rows)
    assert all(r["incident_id"] == meta["id"] for r in rows)


def test_a_tool_failure_raises_rather_than_returning_something_reasonable(tools):
    """Spec 5.9.3: a malformed response is recorded as unknown, not reasoned over."""
    with pytest.raises(ToolError):
        tools.get_diff("no-such-change-id")


def test_tool_failures_are_audited_as_errors(tools, built):
    ledger, _ = built
    with pytest.raises(ToolError):
        tools.get_diff("no-such-change-id")
    outcomes = {r["outcome"] for r in ledger.audit_log("test")}
    assert "error" in outcomes


def test_get_diff_returns_the_real_diff_of_a_cause(tools, built):
    ledger, meta = built
    rows = ledger.changes_between(meta["window_start_ts"], meta["window_end_ts"], limit=500)
    cause = next(c for c in rows
                 if (c.repo, c.path) == ("platform-config", "overlays/prod/orders.yaml"))
    d = tools.get_diff(cause.id)
    assert "-  ORDERS_TABLE: orders-prod" in d["diff"]
    assert "+  ORDERS_TABLE_NAME: orders-prod" in d["diff"]


def test_who_mentions_has_no_repo_filter(tools):
    """Spec 5.4.2: scoping to one repository defeats the purpose."""
    import inspect

    params = inspect.signature(Tools.who_mentions).parameters
    assert "repo" not in params and "repos" not in params


# --- phase 1 acceptance ------------------------------------------------------
def test_every_true_cause_is_in_the_top_ten(built):
    """Spec 11.3 acceptance criterion, and 11.3's kill criterion in negative form:
    if a true cause is not even retrievable, no agent sophistication compensates."""
    ledger, meta = built
    changes = ledger.changes_between(
        meta["window_start_ts"], meta["window_end_ts"], limit=500)
    ranked = Ranker(ledger).rank(changes, "orders-api", meta["first_symptom_ts"])
    positions = {
        (r.change.repo, r.change.path): i
        for i, r in enumerate(ranked, start=1)
    }
    for cause in TRUE_CAUSES:
        assert positions[cause] <= 10, \
            "{} ranked {} -- outside the top ten".format(cause, positions[cause])


def test_changes_after_the_first_symptom_are_ranked_zero(built):
    """A change cannot cause a symptom that preceded it. Same fact as Gate rule 3."""
    ledger, meta = built
    from util import parse_ts

    changes = ledger.changes_between(
        meta["window_start_ts"], meta["window_end_ts"], limit=500)
    ranked = Ranker(ledger).rank(changes, "orders-api", meta["first_symptom_ts"])
    symptom = parse_ts(meta["first_symptom_ts"])
    for r in ranked:
        if r.change.ts > symptom:
            assert r.score == 0.0, "{} postdates the symptom but scored {}".format(
                r.change.id, r.score)


def test_the_ranker_is_not_secretly_perfect(built):
    """A ranker that puts both true causes at 1 and 2 is a ranker fitted to this incident.

    Retrieval is allowed to be imprecise -- that is what the Gate is for. This test exists to
    notice if someone 'improves' the ranker into a lookup table (spec 10.1).
    """
    ledger, meta = built
    changes = ledger.changes_between(
        meta["window_start_ts"], meta["window_end_ts"], limit=500)
    ranked = Ranker(ledger).rank(changes, "orders-api", meta["first_symptom_ts"])
    top_two = {(r.change.repo, r.change.path) for r in ranked[:2]}
    assert top_two != TRUE_CAUSES, \
        "ranking alone solves the incident; the Residue Rule would never be exercised"
