"""Decision package (L5). Spec section 5.8.

The deliverable handed to the on-call engineer. Every field is mandatory; a missing field is a
bug, not an omission. `rollback_hazard` and `security_implications` must be present even when
the answer is "none", because silence there is indistinguishable from not having checked.

Framing rule (5.8): the package is presented as a hypothesis with evidence, never as a
verdict. Speed to a wrong answer is negative value during a severity-one incident.

Two fields here do work that the rest of the system cannot do:

  * `order_of_operations` exists because for the largest incidents diagnosis is a small
    fraction of the outage (Appendix B.3: source identified in 54 minutes, 15 hours 32 to
    recover). Knowing the cause is not the same as knowing what to do first, and getting the
    order wrong can destroy data that the obvious rollback would have saved.
  * `security_implications` exists because a functional fix can make the symptom disappear
    while leaving a widened permission in place. Nobody comes back to it once the graphs
    are green, so it has to be filed separately, now.
"""
from __future__ import annotations

import re
from datetime import timedelta
from typing import Any

import config as cfg
from agent.types import Claim, DecisionPackage, Proof
from indexer.severity import Anomaly, Severity
from util import parse_ts

#: Signals that a change widened rather than narrowed an access scope. Used to decide whether
#: a security note is warranted, and deliberately conservative -- a false positive here costs
#: a sentence of prose, a false negative loses a live over-broad grant.
_WIDENING = re.compile(
    r"(wildcard|\*|widen|broaden|collapse|prefix|allow|grant|permission|polic|role|rbac)",
    re.I,
)
_DESTRUCTIVE_STORE = re.compile(r"(ttl|expir|retention|temporar|staging|scratch|ephemeral)", re.I)


def _owner(ledger, key: str | None) -> dict:
    if not key:
        return {}
    return ledger.owner_of(key) or {}


def _cause_rows(ledger, claim: Claim) -> list:
    rows = []
    for cid in claim.cause_ids:
        r = ledger.lookup(cid)
        if r is not None:
            rows.append(r)
    return rows


def build_package(meta: dict, brief, claim: Claim, proof: Proof, residue: list[Anomaly],
                  ledger, tools, failing_entity: str, config=None) -> DecisionPackage:
    """Assemble the full package for an accepted claim."""
    config = config or cfg.DEFAULT
    rows = _cause_rows(ledger, claim)

    cause_set = []
    for r in rows:
        own = _owner(ledger, r.repo)
        cause_set.append({
            "id": r.id, "ts": r.ts.isoformat(), "source": r.source, "author": r.author,
            "team": r.team or own.get("team"), "repo": r.repo, "path": r.path,
            "summary": r.summary,
        })

    blast = _blast_radius(brief, residue, ledger, tools, rows, failing_entity)
    hazard = _rollback_hazard(brief, residue, rows)
    security = _security_implications(rows, blast)
    order = _order_of_operations(rows, hazard, security)

    owners = []
    seen = set()
    for r in rows:
        own = _owner(ledger, r.repo)
        if own and r.repo not in seen:
            owners.append(dict(own, scope="{} {}".format(r.repo, r.path or "")))
            seen.add(r.repo)
    for entity in blast.get("direct", []):
        name = entity.split(" ")[0]
        own = _owner(ledger, name)
        if own and name not in seen:
            owners.append(dict(own, scope="{} (affected consumer)".format(name)))
            seen.add(name)

    unexplained = [
        dict(a.to_dict(), note="below the {} severity threshold; not investigated".format(
            config.min_severity))
        for a in residue
    ]

    return DecisionPackage(
        incident_id=meta["id"],
        status="resolved",
        cause_set=cause_set,
        mechanism=_mechanism(claim, rows, brief, tools, failing_entity),
        short_term=_short_term(rows, hazard),
        long_term=_long_term(rows, brief),
        order_of_operations=order,
        rollback_hazard=hazard or "None identified: no cause touches a store with a "
                                 "retention limit, and reverting in any order is safe.",
        blast_radius=blast,
        security_implications=security or "None identified: no cause widens a permission "
                                         "or grants new access.",
        confidence=_confidence(claim, proof, residue, rows),
        verification=proof.to_dict(),
        owners=owners,
        unexplained=unexplained,
    )


# --- field builders ----------------------------------------------------------
def _mechanism(claim: Claim, rows, brief, tools=None, failing_entity: str = "") -> str:
    """The causal chain in prose, one hop per sentence, ordered by time. Spec 5.8.

    Built here rather than taken from the Proposer. The report owns presentation, and the
    chain is fully determined by evidence the report already holds -- the ordered causes, the
    configuration resolution chain, and the anomalies in first-mover order. Deriving it means
    the prose cannot drift from the findings, which a model-written summary can.
    """
    hops: list[str] = []
    for r in sorted(rows, key=lambda r: r.ts):
        hops.append("At {}, {} changed {} in {}: {}.".format(
            r.ts.strftime("%H:%M"), r.author or "someone", r.path, r.repo,
            (r.summary or "").split("\n")[0].rstrip(".")))

    # The resolution hop: what the running service actually read, and from where. This is the
    # sentence that connects a configuration edit to a wrong value at runtime, and it is the
    # one a reader cannot reconstruct from the diffs alone.
    # Every entity that showed an anomaly, not only the one with the loudest metric. The
    # service whose configuration broke is often not the service whose graph moved most --
    # here the -94% is on a downstream consumer, while the missing key belongs upstream.
    # Asking only about the noisiest entity silently drops the most explanatory hop.
    entities: list[str] = []
    for a in sorted(brief.anomalies, key=lambda a: (a.first_seen, a.id)):
        if a.entity not in entities:
            entities.append(a.entity)
    if failing_entity and failing_entity not in entities:
        entities.insert(0, failing_entity)

    if tools is not None:
        for entity in entities:
          try:
            keys = tools.keys_read_by(entity).get("read_but_not_supplied", [])
            for key in keys[:2]:
                chain = tools.why_this_value(key, entity)
                terminal = chain.get("terminal") or {}
                if terminal.get("source_type") == "code_default":
                    hops.append(
                        "{} reads {}, which no configuration source now supplies, so it fell "
                        "through to the hardcoded fallback at {} and used {!r} instead."
                        .format(entity, key, terminal.get("source_ref"),
                                terminal.get("value"))
                    )
                    near = chain.get("near_miss_keys") or []
                    if near:
                        hops.append(
                            "The configuration does define {}, so the key was renamed rather "
                            "than deleted -- the value was never wrong, only unreachable."
                            .format(", ".join(near))
                        )
          except Exception:
            continue

    for a in sorted(brief.anomalies, key=lambda a: (a.first_seen, a.id)):
        hops.append("From {}, {} showed {} ({}).".format(
            a.first_seen[11:16], a.entity, a.kind.replace("_", " "), a.magnitude))

    if claim.mechanism and len(claim.mechanism) > 160:
        hops.append("Proposer's account: {}".format(claim.mechanism))
    return " ".join(hops)


def _short_term(rows, hazard: str) -> str:
    """Mitigation to stop the bleeding now -- separate from the real fix (spec 5.8).

    Targets the change that is actually redirecting behaviour, not the one that widened a
    permission. Reverting the permission first would restore the guard rail and start failing
    writes loudly, which is a different outage; and it leaves the wrong destination in place.
    The functional cause is the one to undo first.
    """
    if not rows:
        return "No mitigation identified."
    functional = [r for r in rows if not _WIDENING.search(r.summary or "")]
    # Latest functional cause before the symptom is the proximate one.
    target = max(functional or rows, key=lambda r: r.ts)
    lead = "Revert {} in {} and roll the affected service".format(target.path, target.repo)
    if hazard:
        return ("{}. IMPORTANT: this is step 2, not step 1 -- see order_of_operations. "
                "Reverting first destroys data.".format(lead))
    return lead + "."


def _long_term(rows, brief) -> str:
    parts = []
    for r in rows:
        parts.append("Fix {} in {} properly rather than by revert.".format(r.path, r.repo))
    parts.append(
        "Guard rail for this class: a change to a shared configuration key or a shared "
        "permission scope should fail review unless every consumer found by the reverse "
        "index has been checked. The consumers are already known -- they were what made "
        "this diagnosable."
    )
    return " ".join(parts)


def _order_of_operations(rows, hazard: str, security: str) -> list[str]:
    """Explicitly ordered steps when order matters (spec 5.8).

    Data preservation precedes the functional fix, and re-scoping a permission comes last so
    that the mitigation is not blocked on a security review.
    """
    steps: list[str] = []
    if hazard:
        steps.append(
            "Export the affected records to durable storage BEFORE changing anything. "
            "The destination they landed in has a retention limit and reverting first "
            "destroys them."
        )
    functional = sorted(rows, key=lambda r: r.ts, reverse=True)
    for r in functional:
        if _WIDENING.search(r.summary or "") and security:
            continue  # permission changes are handled after service is restored
        steps.append("Restore {} in {} and sync.".format(r.path, r.repo))
    steps.append("Verify the affected service is behaving correctly again before proceeding.")
    for r in functional:
        if _WIDENING.search(r.summary or "") and security:
            steps.append("Re-scope {} in {} back to its original narrow value.".format(
                r.path, r.repo))
    if hazard:
        steps.append("Reconcile the exported records into their correct destination, "
                     "de-duplicating on the record identifier.")
    return steps


def _rollback_hazard(brief, residue, rows) -> str:
    """Does the obvious rollback destroy something?

    Detected from the anomaly set rather than asserted: a novel destination that appeared
    mid-window, whose name or evidence indicates a store with a retention limit, is holding
    data that a revert will orphan.
    """
    for a in brief.anomalies:
        if a.kind not in ("novel_metric_series", "write_permitted_to_novel_resource"):
            continue
        target = a.evidence_ref or ""
        if not _DESTRUCTIVE_STORE.search(target) and not _DESTRUCTIVE_STORE.search(a.detail):
            continue
        return (
            "The records written since {} are sitting in {}, which is not their intended "
            "destination and is subject to a retention limit. Reverting the configuration "
            "first fixes new writes and permanently loses everything already written. "
            "Export before reverting -- see order_of_operations step 1."
        ).format(a.first_seen[11:16], target.split(":")[-1])
    return ""


def _security_implications(rows, blast) -> str:
    for r in rows:
        if not _WIDENING.search(r.summary or ""):
            continue
        indirect = len(blast.get("indirect", []))
        return (
            "The change at {} in {} ({}) widened an access scope, and correcting the "
            "functional problem does NOT undo it. The broadened grant stays live after the "
            "symptom disappears, which is exactly when it stops being looked at. File this "
            "separately from the incident fix and re-scope it explicitly.{}"
        ).format(
            r.ts.strftime("%H:%M"), r.repo, r.summary[:70],
            " {} indirect consumer(s) of the same shared module inherit it.".format(indirect)
            if indirect else "",
        )
    return ""


def _blast_radius(brief, residue, ledger, tools, rows, failing_entity) -> dict:
    """Every service, team and dataset touched, derived from the anomaly set and the
    reverse index rather than asserted."""
    direct: list[str] = []
    for a in brief.anomalies:
        label = "{} -- {} ({})".format(a.entity, a.kind, a.magnitude)
        if label not in direct:
            direct.append(label)

    indirect: list[str] = []
    for r in rows:
        if not r.path:
            continue
        try:
            # Who else references what this file references? That is the set of consumers
            # that inherit the change, and the reverse index already knows.
            lits = ledger.conn.execute(
                "SELECT DISTINCT literal FROM mentions WHERE repo = ? AND path = ?",
                (r.repo, r.path),
            ).fetchall()
            others: set[str] = set()
            for (lit,) in lits:
                for (repo,) in ledger.conn.execute(
                    "SELECT DISTINCT repo FROM mentions WHERE literal = ? AND repo != ?",
                    (lit, r.repo),
                ).fetchall():
                    others.add(repo)
            for o in sorted(others):
                label = "{} references literals changed by {}/{}".format(o, r.repo, r.path)
                if label not in indirect:
                    indirect.append(label)
        except Exception:
            continue

    return {"direct": direct, "indirect": indirect}


def _confidence(claim: Claim, proof: Proof, residue, rows) -> dict:
    """Calibrated 0-1, plus what would change my mind, plus the cheapest disambiguating query.

    Calibration here is mechanical rather than vibes-based: start from the verification tier
    actually reached, and subtract for anything still unexplained or unresolved. An
    overconfident 0.9 costs more on the Brier score than an honest 0.6 (spec 10.2).
    """
    base = {"T0": 0.55, "T1": 0.86, "T2": 0.9, "T3": 0.93, "T4": 0.95}.get(proof.tier, 0.5)
    if not proof.passed:
        base -= 0.25
    significant_left = [a for a in residue if a.severity >= Severity.medium]
    base -= 0.08 * len(significant_left)
    if not rows:
        base = min(base, 0.2)
    value = max(0.05, min(0.95, round(base, 2)))

    return {
        "value": value,
        "framing": "hypothesis with evidence, not a verdict",
        "would_change_my_mind": _falsifier(rows, proof),
        "cheapest_disambiguating_query": (
            proof.command if proof.tier != "T0"
            else "Replay the changed artifact as it stood before the change against the "
                 "exact call that succeeded, and check whether it would have been refused."
        ),
        "unexplained_above_threshold": [a.id for a in significant_left],
    }


def _falsifier(rows, proof: Proof) -> str:
    if not rows:
        return "Any recorded human-authored change in the window that this claim missed."
    r = min(rows, key=lambda r: r.ts)
    return (
        "Evidence that the affected service was restarted after {} with its previous "
        "configuration still present -- that would break the link between the change and "
        "the fallback. Also: any record of the same call succeeding before {}, which would "
        "mean the constraint was never in place and this cause set is one change too long."
    ).format(r.ts.strftime("%H:%M"), r.ts.strftime("%H:%M"))


# --- T4: the honest exit -----------------------------------------------------
def build_unresolved(meta: dict, brief, residue: list[Anomaly], evidence: list[dict],
                     reason: str, gate_trace: list[dict], ledger, config=None
                     ) -> DecisionPackage:
    """UNRESOLVED with a frontier. Spec 2.1 T4.

    Must return ranked live hypotheses, the remaining residue, and the single cheapest query
    that would disambiguate. It must never emit a confident guess -- an UNRESOLVED with a
    frontier is a useful handoff to a human; a confident wrong answer costs them the night.
    """
    config = config or cfg.DEFAULT

    considered: list[dict] = []
    for step in gate_trace:
        for cid in step.get("cause_ids", []):
            row = ledger.lookup(cid)
            considered.append({
                "cause_id": cid,
                "rejected_because": step.get("reason"),
                "rule": step.get("rule"),
                "resolves_to_a_recorded_change": row is not None,
                "summary": row.summary if row else "not a recorded human-authored change",
            })

    top = sorted(residue, key=lambda a: a.sort_key)
    cheapest = (
        "Ask what wrote the state behind {}: {}. Its own evidence names {} -- search every "
        "repository for that literal and look for a change to whatever file comes back."
        .format(top[0].entity, top[0].kind, (top[0].evidence_ref or "").split(":")[-1])
        if top else
        "No residue remains above the threshold; re-run with a lower severity threshold."
    )

    pkg = DecisionPackage(incident_id=meta["id"], status="unresolved")
    pkg.frontier = {
        "why_unresolved": reason,
        "ranked_hypotheses": considered or [
            {"cause_id": None, "rejected_because": "no claim named a recorded change",
             "rule": "T1", "resolves_to_a_recorded_change": False,
             "summary": "the investigation never reached a human-authored change"}
        ],
        "residue": [a.to_dict() for a in top],
        "cheapest_query": cheapest,
        "steps_taken": len(gate_trace),
    }
    pkg.mechanism = ("UNRESOLVED. {} No confident cause is being asserted; the frontier "
                     "below is where the investigation stopped.".format(reason))
    pkg.confidence = {"value": 0.0, "framing": "no cause asserted",
                      "would_change_my_mind": cheapest,
                      "cheapest_disambiguating_query": cheapest}
    return pkg
