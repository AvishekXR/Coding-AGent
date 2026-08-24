"""Verifier (L4). Spec section 5.7. Tiered counterfactual confirmation.

    T0  static and counterfactual reasoning only; nothing executed        always
    T1  re-run the specific artifact against captured inputs              usually
    T2  component sandbox: replay the captured bad input in isolation     often
    T3  scaled-down environment with the fault re-injected end to end     sometimes
    T4  full staging reproduction                                         rarely

Attempt the cheapest tier that applies, and always report which tier was reached. Full
environment reproduction is not achievable for most real high-severity causes -- production
cannot be reproduced in containers -- so designing around T3/T4 would mean verifying nothing.

**T1 is where the leverage is.** For an authorization-shaped cause, T1 verification is: rebuild
the policy artifact as it stood *before* the change, re-evaluate the exact decision that
telemetry recorded, and see whether it would have been refused. That is a sub-second check
which proves a causal link, and no telemetry-only tool can perform it, because it requires the
policy text out of another team's repository.

This module is one of the few permitted to touch the simulator (see
tests/test_no_incident_leakage.py): running a real counterfactual means executing a real
artifact against a real evaluator, which is the entire point of the tier.
"""
from __future__ import annotations

import re
import subprocess
from dataclasses import dataclass
from pathlib import Path

import config as cfg
from agent.types import Claim, Proof
from indexer.severity import Anomaly

TIERS = ["T0", "T1", "T2", "T3", "T4"]

#: Paths that look like a policy or permission artifact worth replaying.
_POLICY_HINT = re.compile(r"(iam|polic|permission|role|rbac)", re.I)
#: authz:<principal>:<resource>
_AUTHZ_REF = re.compile(r"^authz:(?P<principal>[^:]+):(?P<resource>.+)$")
_ACTION_RX = re.compile(r"\b([a-z0-9]+:[A-Z][A-Za-z0-9]+)\b")


@dataclass
class Verifier:
    ledger: object
    max_tier: str = "T2"
    repos: Path = cfg.REPOS_DIR

    def confirm(self, claim: Claim, anomalies: list[Anomaly] | None = None) -> Proof:
        """Attempt the cheapest applicable tier, up to `max_tier`."""
        anomalies = anomalies or []
        ceiling = TIERS.index(self.max_tier) if self.max_tier in TIERS else 2

        if ceiling >= 1:
            # Policy replay first: it proves a constraint was removed, which is a stronger
            # statement than "a value changed".
            proof = self._tier1_policy_replay(claim, anomalies)
            if proof is not None:
                return proof
            proof = self._tier1_artifact_replay(claim)
            if proof is not None:
                return proof

        return self._tier0(claim)

    # -- T0 -------------------------------------------------------------------
    def _tier0(self, claim: Claim) -> Proof:
        """Static reasoning only. Always available, and honest about being weak."""
        rows = [self.ledger.lookup(cid) for cid in claim.cause_ids]
        named = [r for r in rows if r is not None]
        detail = "; ".join(
            "{} @ {} ({}/{})".format(r.summary[:60], r.ts.strftime("%H:%M"), r.repo, r.path)
            for r in named
        )
        return Proof(
            tier="T0", passed=bool(named),
            observed=("{} cause(s) resolve to ledger rows preceding the first symptom: {}"
                      .format(len(named), detail) if named
                      else "no cause resolved to a ledger row"),
            expected="every cause resolves to a recorded human-authored change",
            command="ledger.lookup({})".format(", ".join(claim.cause_ids) or "-"),
        )

    # -- T1 -------------------------------------------------------------------
    def _tier1_policy_replay(self, claim: Claim,
                             anomalies: list[Anomaly]) -> Proof | None:
        """Rebuild a policy artifact as it stood before the change and re-decide.

        Returns None when the claim has no policy-shaped cause paired with a recorded
        authorization decision -- in which case T1 does not apply and the caller falls back.
        """
        authz = [a for a in anomalies if _AUTHZ_REF.match(a.evidence_ref or "")]
        if not authz:
            return None

        for cid in claim.cause_ids:
            row = self.ledger.lookup(cid)
            if row is None or not row.path or not _POLICY_HINT.search(row.path):
                continue
            ref = row.diff_ref or ""
            if not ref.startswith("git:"):
                continue
            _, repo, sha, path = (ref.split(":", 3) + ["", "", ""])[:4]
            before = self._file_at(repo, sha + "~", path or row.path)
            if before is None:
                continue

            for a in authz:
                m = _AUTHZ_REF.match(a.evidence_ref)
                principal, resource = m.group("principal"), m.group("resource")
                action = self._action_from(a)
                allowed_before, reason = self._evaluate(before, principal, action, resource)
                command = (
                    "replay_check(policy={}@{}~:{}, principal={}, action={}, resource={})"
                    .format(repo, sha[:7], path, principal, action, resource)
                )
                if not allowed_before:
                    return Proof(
                        tier="T1", passed=True,
                        observed=(
                            "Under the policy as it stood before this change, the recorded "
                            "call is REFUSED ({}). After the change the same call is "
                            "permitted. The constraint existed and this change removed it."
                            .format(reason)
                        ),
                        expected="the pre-change policy refuses the call that succeeded",
                        command=command,
                    )
                return Proof(
                    tier="T1", passed=False,
                    observed=("Under the pre-change policy the call is still permitted ({}), "
                              "so this change did not remove a constraint.".format(reason)),
                    expected="the pre-change policy refuses the call that succeeded",
                    command=command,
                )
        return None

    # -- primitives -----------------------------------------------------------
    def _file_at(self, repo: str, rev: str, path: str) -> str | None:
        r = subprocess.run(
            ["git", "-C", str(self.repos / repo), "show", "{}:{}".format(rev, path)],
            capture_output=True, text=True,
        )
        return r.stdout if r.returncode == 0 else None

    @staticmethod
    def _action_from(a: Anomaly) -> str:
        m = _ACTION_RX.search(a.detail or "")
        return m.group(1) if m else "unknown:Action"

    @staticmethod
    def _evaluate(policy_text: str, principal: str, action: str,
                  resource: str) -> tuple[bool, str]:
        """Evaluate a policy artifact against one decision.

        Uses the same evaluator the environment uses, which is the property that makes this a
        replay rather than a re-implementation. A second implementation of policy semantics
        would verify our understanding of the rules, not the rules.
        """
        from env.sim.iam import IAM, Policy
        from env.sim.render import POLICY_PRINCIPAL, parse_iam_terraform

        docs = parse_iam_terraform(policy_text)
        iam = IAM.__new__(IAM)
        iam._principals = {}
        iam.path = None
        attached = False
        for doc_name, policy in docs.items():
            target = POLICY_PRINCIPAL.get(doc_name)
            if target == principal:
                iam.put_policy(principal, policy)
                attached = True
        if not attached:
            return False, "no policy attached to {} in the pre-change artifact".format(principal)
        return iam.evaluate(principal, action, resource)


# --- T1, second strategy: re-parse the artifact and compare effective values --
def _python_constants(text: str) -> dict:
    """Module-level literal assignments, by executing the AST rather than the module.

    Parsing instead of importing matters: the artifact under test is a *previous* version of
    a file, and importing it would run whatever that version contained.
    """
    import ast as _ast

    out: dict[str, object] = {}
    try:
        tree = _ast.parse(text)
    except SyntaxError:
        return out
    for node in tree.body:
        if not isinstance(node, _ast.Assign):
            continue
        for target in node.targets:
            if isinstance(target, _ast.Name):
                try:
                    out[target.id] = _ast.literal_eval(node.value)
                except (ValueError, SyntaxError):
                    continue
    return out


def _yaml_values(text: str) -> dict:
    import yaml as _yaml

    try:
        doc = _yaml.safe_load(text)
    except Exception:
        return {}
    if isinstance(doc, dict) and isinstance(doc.get("data"), dict):
        return dict(doc["data"])
    return doc if isinstance(doc, dict) else {}


def _terraform_values(text: str) -> dict:
    from env.sim.render import parse_iam_terraform

    out = {}
    for name, policy in parse_iam_terraform(text).items():
        for s in policy.statements:
            out["{}/{}".format(name, s.sid or "stmt")] = list(s.resources)
    return out


def _effective_values(path: str, text: str) -> dict:
    if path.endswith(".py"):
        return _python_constants(text)
    if path.endswith((".yaml", ".yml")):
        return _yaml_values(text)
    if path.endswith((".tf", ".hcl")):
        return _terraform_values(text)
    return {}


def _artifact_replay(verifier, claim) -> "Proof | None":
    """Re-parse each changed artifact before and after, and report what actually changed.

    Spec 5.7 lists "re-parse the config, re-evaluate the policy or flag rule" as T1. The
    distinction from T0 is not cosmetic: T0 reasons about a diff, while this loads both
    versions of the artifact and compares the values they *evaluate to*. A diff that looks
    alarming can leave every effective value identical -- a reformat, a comment, a reordering
    -- and a diff that looks trivial can change one. Reading the text cannot tell those apart.
    """
    for cid in claim.cause_ids:
        row = verifier.ledger.lookup(cid)
        if row is None or not row.path:
            continue
        ref = row.diff_ref or ""
        if not ref.startswith("git:"):
            continue
        _, repo, sha, path = (ref.split(":", 3) + ["", "", ""])[:4]
        path = path or row.path
        before = verifier._file_at(repo, sha + "~", path)
        after = verifier._file_at(repo, sha, path)
        if before is None or after is None:
            continue

        b, a = _effective_values(path, before), _effective_values(path, after)
        if not b and not a:
            continue

        changed = {k: (b.get(k), a.get(k)) for k in set(b) | set(a) if b.get(k) != a.get(k)}
        command = "replay_check(parse={}@{}~ vs @{}: {})".format(
            repo, sha[:7], sha[:7], path)
        if changed:
            detail = "; ".join(
                "{}: {!r} -> {!r}".format(k, v[0], v[1]) for k, v in sorted(changed.items())
            )
            return Proof(
                tier="T1", passed=True,
                observed=("Re-parsing the artefact either side of this change gives different "
                          "effective values: {}. The change is behavioural, not cosmetic."
                          .format(detail)),
                expected="the artefact's effective values differ across the change",
                command=command,
            )
        return Proof(
            tier="T1", passed=False,
            observed=("Re-parsing the artefact either side of this change gives identical "
                      "effective values. Whatever the diff shows, this change altered no "
                      "value the running system reads -- it is unlikely to be the cause."),
            expected="the artefact's effective values differ across the change",
            command=command,
        )
    return None


Verifier._tier1_artifact_replay = lambda self, claim: _artifact_replay(self, claim)
