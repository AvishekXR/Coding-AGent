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
                 console: list[ConsoleAction] | None = None,
                 world_changes: list | None = None,
                 setup: Callable | None = None):
        self.id = incident_id
        self.day = day
        self.edits = edits
        self.console = console or []
        #: Flag flips, package upgrades, external events, capacity limits, raw mutations.
        self.world_changes = world_changes or []
        #: Run once before traffic starts -- for shaping the world the incident needs (a
        #: dependency endpoint table, a queue predicate) rather than for breaking it.
        self.setup = setup

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
        for w in self.world_changes:
            ts = w.when(self.day)
            # World changes compose rather than collide. An event and the effect it produces
            # genuinely share a timestamp -- a campaign launches and its traffic arrives in
            # the same minute -- and forcing the author to stagger them by a minute would put
            # a fictional gap into the evidence. Two *edits* at one timestamp remain an error,
            # because two commits in the same second is an authoring mistake.
            out[ts] = _compose(out[ts], w.apply) if ts in out else w.apply
        return out


def _compose(first: Callable, second: Callable) -> Callable:
    """Run two hooks at the same timestamp, in declaration order."""

    def both(world: World, at: datetime) -> None:
        first(world, at)
        second(world, at)

    return both


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
            # A rollout replaces the running process, so the new code takes effect here and
            # not at the commit. Without this reload a code change would be visible in git
            # and invisible in behaviour -- which is the one thing a simulated world must
            # never get wrong, because the whole point is that the incident is emergent.
            world._load_service_code()

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


@dataclass
class Rollout:
    """A pod restart. Not a commit, and deliberately not modelled as one.

    An earlier version of this helper faked a rollout with a comment-only commit that named
    the deployment in `platform-config/README.md`. That put the service's name into a file in
    another team's repository, the reverse index dutifully linked the two, and the agent began
    attributing the service's anomalies to a README.

    The lesson generalises beyond this bug: an authoring convenience that writes into indexed
    content is not neutral. It invents a relationship the real world does not have, and the
    solver has no way to tell scaffolding from evidence. Test-harness artefacts must stay out
    of anything the agent can read.

    A real rollout leaves a Kubernetes audit event and nothing else. So does this one.
    """

    ts: str
    deployment: str = "orders-api"
    note: str = "rollout"

    def when(self, day: str) -> datetime:
        return datetime.fromisoformat("{}T{}:00".format(day, self.ts))

    def apply(self, world: World, at: datetime) -> None:
        world.cluster.rollout(self.deployment, at)
        # The new process starts here, so this is where new code takes effect -- not at the
        # commit. Without the reload a code change is visible in git and invisible in
        # behaviour, and the incident stops being emergent.
        world._load_service_code()


def rollout_only(ts: str, deployment: str, note: str) -> "Rollout":
    """Constructor kept for the incidents that already call it by this name."""
    return Rollout(ts=ts, deployment=deployment, note=note)


# --- changes that exist outside any repository -------------------------------
@dataclass
class FlagFlip:
    """A feature-flag toggle. Class B.

    No commit, no pull request, no review. The fastest way to change production behaviour,
    and therefore disproportionately likely to be the answer.
    """

    ts: str
    flag: str
    to: bool
    actor: str
    team: str
    scope: str = "prod"

    def when(self, day: str) -> datetime:
        return datetime.fromisoformat("{}T{}:00".format(day, self.ts))

    def apply(self, world: World, at: datetime) -> None:
        world.flags.set(at, self.flag, self.to, self.actor, self.team, self.scope)


@dataclass
class PackageUpgrade:
    """An OS or package update. Class E -- the change that lives in no repository.

    `route_health` reproduces the Datadog shape: the update restarts a daemon which
    force-deletes routes another component owns, and nodes drop off the network. There is no
    commit to find and no deploy to correlate against.
    """

    ts: str
    package: str
    to_version: str
    channel: str
    scope: str = "fleet"
    actor: str = "unattended-upgrades"
    team: str = "Platform"
    route_health: float | None = None

    def when(self, day: str) -> datetime:
        return datetime.fromisoformat("{}T{}:00".format(day, self.ts))

    def apply(self, world: World, at: datetime) -> None:
        world.host.record(at, self.package, self.to_version, self.channel,
                          self.scope, self.actor, self.team)
        if self.route_health is not None:
            world.host.route_health = self.route_health


@dataclass
class ExternalEvent:
    """A documented event outside the organisation's control. Class G.

    `status` decides whether the collector marks the row evidenced. A status page saying
    "investigating" is a report of an event, not a confirmation of one, and the Gate refuses
    to terminate on an unevidenced row -- which is correct during the first twenty minutes of
    an incident, when a status page is the least reliable source in the building.
    """

    ts: str
    provider: str
    component: str
    title: str
    status: str = "investigating"
    url: str = ""

    def when(self, day: str) -> datetime:
        return datetime.fromisoformat("{}T{}:00".format(day, self.ts))

    def apply(self, world: World, at: datetime) -> None:
        world.external.record(at, self.provider, self.component, self.title,
                              self.status, self.url)


@dataclass
class CapacityChange:
    """A throughput ceiling being reached. Class F -- saturation with no change at all.

    Nobody edits anything here. The ceiling was always there; traffic grew into it. Modelled
    as a world fact rather than a ledger row precisely so that the ledger has nothing to
    offer, and an agent that assumes every incident has a culprit commit has to manufacture
    one or admit there is none.
    """

    ts: str
    writes_per_minute: int | None

    def when(self, day: str) -> datetime:
        return datetime.fromisoformat("{}T{}:00".format(day, self.ts))

    def apply(self, world: World, at: datetime) -> None:
        world.capacity.writes_per_minute = self.writes_per_minute


@dataclass
class WorldMutation:
    """An arbitrary switch thrown in the world at a timestamp.

    The escape hatch for incidents whose mechanism does not fit the shapes above -- a queue
    predicate, a dependency endpoint table. Deliberately last: if a mutation shape recurs, it
    should become a named class so an incident author is not writing simulator internals.
    """

    ts: str
    fn: Callable
    note: str = ""

    def when(self, day: str) -> datetime:
        return datetime.fromisoformat("{}T{}:00".format(day, self.ts))

    def apply(self, world: World, at: datetime) -> None:
        self.fn(world, at)


#: Everything an incident can schedule that is not a file edit.
NON_REPO_CHANGES = (FlagFlip, PackageUpgrade, ExternalEvent, CapacityChange, WorldMutation)
