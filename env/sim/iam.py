"""A small but faithful AWS-style IAM policy evaluator.

This is deliberately *real*: the reference incident (spec section 8) turns entirely on whether
`arn:aws:dynamodb:*:*:table/orders-*` matches the resource `arn:aws:dynamodb:us-east-1:
000000000000:table/orders-staging`. If that matching were faked, the incident would prove
nothing. So wildcard semantics, explicit-deny precedence and default-deny are implemented
here as AWS defines them.

Evaluation order (AWS policy evaluation logic, simplified to the identity-policy case):
    1. An explicit Deny anywhere wins immediately.
    2. Otherwise an Allow that matches both action and resource permits the call.
    3. Otherwise: implicit deny.
"""
from __future__ import annotations

import fnmatch
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, Literal


class AccessDenied(Exception):
    """Raised when a simulated AWS call is not permitted. Mirrors botocore's error shape."""

    def __init__(self, principal: str, action: str, resource: str, reason: str):
        self.principal, self.action, self.resource, self.reason = (
            principal,
            action,
            resource,
            reason,
        )
        super().__init__(
            f"AccessDeniedException: User {principal} is not authorized to perform "
            f"{action} on resource {resource} ({reason})"
        )


@dataclass(frozen=True)
class Statement:
    effect: Literal["Allow", "Deny"]
    actions: tuple[str, ...]
    resources: tuple[str, ...]
    sid: str = ""

    def matches(self, action: str, resource: str) -> bool:
        return self._any_match(self.actions, action) and self._any_match(
            self.resources, resource
        )

    @staticmethod
    def _any_match(patterns: Iterable[str], value: str) -> bool:
        # IAM wildcards are `*` (any sequence) and `?` (any single char) -- exactly
        # fnmatch's semantics, except that IAM is case-sensitive for ARNs and fnmatch on
        # Windows is not. fnmatchcase pins the behaviour to be platform-independent.
        return any(fnmatch.fnmatchcase(value, p) for p in patterns)


@dataclass(frozen=True)
class Policy:
    name: str
    statements: tuple[Statement, ...]

    @staticmethod
    def from_dict(name: str, doc: dict) -> "Policy":
        stmts = []
        for s in doc.get("Statement", []):
            stmts.append(
                Statement(
                    effect=s["Effect"],
                    actions=tuple(_as_tuple(s.get("Action", []))),
                    resources=tuple(_as_tuple(s.get("Resource", []))),
                    sid=s.get("Sid", ""),
                )
            )
        return Policy(name=name, statements=tuple(stmts))


def _as_tuple(v) -> tuple[str, ...]:
    if isinstance(v, str):
        return (v,)
    return tuple(v)


class IAM:
    """Holds principal -> attached policies, and answers authorize()."""

    def __init__(self, path: Path):
        self.path = Path(path)
        self._principals: dict[str, list[Policy]] = {}
        if self.path.exists():
            self.load()

    # -- persistence ----------------------------------------------------------
    def load(self) -> None:
        raw = json.loads(self.path.read_text(encoding="utf-8"))
        self._principals = {
            principal: [Policy.from_dict(n, d) for n, d in policies.items()]
            for principal, policies in raw.items()
        }

    def save(self) -> None:
        out: dict[str, dict] = {}
        for principal, policies in self._principals.items():
            out[principal] = {
                p.name: {
                    "Version": "2012-10-17",
                    "Statement": [
                        {
                            "Sid": s.sid,
                            "Effect": s.effect,
                            "Action": list(s.actions),
                            "Resource": list(s.resources),
                        }
                        for s in p.statements
                    ],
                }
                for p in policies
            }
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.path.write_text(json.dumps(out, indent=2, sort_keys=True), encoding="utf-8")

    # -- mutation (used by the terraform-apply simulator only) ----------------
    def put_policy(self, principal: str, policy: Policy) -> None:
        existing = [p for p in self._principals.get(principal, []) if p.name != policy.name]
        self._principals[principal] = existing + [policy]

    def policies_for(self, principal: str) -> list[Policy]:
        return list(self._principals.get(principal, []))

    # -- evaluation -----------------------------------------------------------
    def evaluate(self, principal: str, action: str, resource: str) -> tuple[bool, str]:
        """Return (allowed, reason). Reason is human-readable and is what the Verifier reports."""
        policies = self._principals.get(principal)
        if not policies:
            return False, f"no policy attached to {principal}"

        for p in policies:
            for s in p.statements:
                if s.effect == "Deny" and s.matches(action, resource):
                    return False, f"explicit Deny in {p.name}/{s.sid or 'unnamed'}"

        for p in policies:
            for s in p.statements:
                if s.effect == "Allow" and s.matches(action, resource):
                    matched = next(
                        r for r in s.resources if Statement._any_match((r,), resource)
                    )
                    return True, f"Allow in {p.name}/{s.sid or 'unnamed'} via resource {matched}"

        return False, "implicit deny: no statement matches"

    def authorize(self, principal: str, action: str, resource: str) -> None:
        allowed, reason = self.evaluate(principal, action, resource)
        if not allowed:
            raise AccessDenied(principal, action, resource, reason)
