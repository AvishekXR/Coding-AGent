"""Shared machinery for authoring seeded incidents.

An incident is a list of `Edit`s applied to the world at controlled timestamps, some of which
are causal and most of which are not. Everything an incident author writes lives in one file
next to its `truth.yaml`; nothing here knows which edits are the causes.

Anti-gaming note (spec section 10.1): this module is imported by `incidents/` only. Nothing in
`agent/`, `indexer/`, `ledger/` or `tools/` may import it, and a test enforces that.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Callable, Literal

from env.seed import commit_all
from env.sim.render import apply_iac, parse_configmaps
from env.world import World

Effect = Literal["none", "terraform_apply", "config_sync", "rollout", "console"]


@dataclass
class Edit:
    """One human action in the world, at a timestamp.

    `repo`/`path`/`old`/`new` describe a real file edit committed to a real git repository.
    `effect` is what the organisation's automation does with it afterwards -- a terraform
    apply, a config sync, a pod rollout -- which is what makes the change take hold.
    """

    ts: str                      # "HH:MM" on the incident day
    repo: str
    path: str
    old: str
    new: str
    message: str
    author: str                  # "name <email>"
    team: str
    effect: Effect = "none"
    rollout: str | None = None   # deployment to restart, when effect == "rollout"

    def when(self, day: str) -> datetime:
        return datetime.fromisoformat("{}T{}:00".format(day, self.ts))


@dataclass
class ConsoleAction:
    """A change that exists in no repository at all: a console click, an IAM edit, a scale.

    Spec section 5.1 -- an incident class is unsolvable if its change source is missing from
    the ledger, and the Datadog shape (class E) has no commit anywhere.
    """

    ts: str
    actor: str
    team: str
    summary: str
    kind: Literal["cloudtrail", "k8s"] = "cloudtrail"
    event_name: str = "UpdateItem"
    request: dict = field(default_factory=dict)

    def when(self, day: str) -> datetime:
        return datetime.fromisoformat("{}T{}:00".format(day, self.ts))


class Incident:
    """Applies a set of edits to a seeded world while traffic runs through it."""

    def __init__(self, incident_id: str, day: str, edits: list[Edit],
                 console: list[ConsoleAction] | None = None):
        self.id = incident_id
        self.day = day
        self.edits = edits
        self.console = console or []

    # -- hook construction ----------------------------------------------------
    def hooks(self, repos: Path) -> dict[datetime, Callable]:
        """Build the timestamp -> callable map consumed by World.run_traffic."""
        out: dict[datetime, Callable] = {}
        for e in self.edits:
            ts = e.when(self.day)
            if ts in out:
                raise ValueError("two edits share timestamp {}".format(ts))
            out[ts] = _make_edit_hook(e, repos)
        for c in self.console:
            ts = c.when(self.day)
            if ts in out:
                raise ValueError("console action collides with an edit at {}".format(ts))
            out[ts] = _make_console_hook(c)
        return out


def _make_edit_hook(e: Edit, repos: Path) -> Callable:
    def apply(world: World, at: datetime) -> None:
        repo_dir = repos / e.repo
        path = repo_dir / e.path
        text = path.read_text(encoding="utf-8")
        if e.old not in text:
            raise ValueError(
                "edit at {} does not apply: {!r} not found in {}".format(e.ts, e.old, path)
            )
        path.write_text(text.replace(e.old, e.new, 1), encoding="utf-8")
        commit_all(repo_dir, e.message, at, e.author)

        if e.effect == "terraform_apply":
            apply_iac(repo_dir, world.iam)
            world.cloudtrail.record(
                at=at, event_name="PutRolePolicy", principal="terraform-ci",
                source="iam.amazonaws.com",
                request={"repo": e.repo, "path": e.path, "appliedBy": e.author},
            )
        elif e.effect == "config_sync":
            for doc in parse_configmaps(repo_dir, "prod"):
                world.cluster.apply_configmap(
                    name=doc["metadata"]["name"], namespace="prod", data=doc["data"],
                    at=at, user="system:config-sync",
                )
        elif e.effect == "rollout":
            world.cluster.rollout(e.rollout or "orders-api", at)

    return apply


def _make_console_hook(c: ConsoleAction) -> Callable:
    def apply(world: World, at: datetime) -> None:
        if c.kind == "cloudtrail":
            world.cloudtrail.record(
                at=at, event_name=c.event_name, principal=c.actor,
                source="console.amazonaws.com",
                request=dict(c.request, summary=c.summary),
            )
        else:
            world.audit.record(
                at=at, verb="update", user=c.actor, resource="deployments",
                namespace="prod", name=c.request.get("name", "unknown"),
                diff={"summary": c.summary},
            )

    return apply


def rollout_only(ts: str, deployment: str, note: str) -> Edit:
    """A pod restart with no file edit behind it.

    Modelled as a comment-only commit in platform-config so that the rollout has a real
    timestamp in the audit stream; the edit itself is inert.
    """
    return Edit(
        ts=ts, repo="platform-config", path="README.md",
        old="**On-call:** #platform-oncall",
        new="**On-call:** #platform-oncall\n\n<!-- {} -->".format(note),
        message=note, author="system-config-sync <sync@acme.example>", team="Platform",
        effect="rollout", rollout=deployment,
    )
