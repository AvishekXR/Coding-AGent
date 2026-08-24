"""The order request pipeline: the stages a request passes through, and how each can fail.

Incident 001 needed only one failure mode -- a write landing in the wrong place. The other
eleven classes in spec §9 need somewhere to break that is *not* that, and a world with a
single failure mode cannot host them: every incident would be a variation of the same shape,
and passing the range would mean nothing.

Six stages, each with a distinct observable signature:

    flag_gate   a feature flag selects a code path                     (class B)
    validate    the service's own validation code accepts or rejects   (class A)
    dependency  a downstream call, over an endpoint read from config   (class C, G, I)
    capacity    a write-throughput ceiling                             (class F)
    authorize   IAM evaluation                                         (class D)
    publish     a downstream queue that a consumer reads               (class H)

Every stage defaults to pass-through. A healthy world exercises all six and none of them
fails, which is what lets these be added without disturbing an existing incident: with no
switches thrown, the pipeline is exactly the write path it replaced.

The signatures are deliberately different from one another. A capacity ceiling throttles and
returns 429 with rising latency; a validation change returns 422 with flat latency; a
dependency timeout returns 504 with latency at the timeout value; a redirected write returns
201 and looks perfect. An agent that can only recognise one of these is not being tested by
the other five.
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any


@dataclass
class Outcome:
    """What happened to one request, and what it should look like in telemetry."""

    status: int
    stage: str                      # which stage decided the outcome
    table: str | None = None        # where it was written, if it was
    latency_ms: int = 40
    reason: str = ""
    published: bool = True

    @property
    def accepted(self) -> bool:
        return 200 <= self.status < 300


@dataclass
class HostState:
    """OS and package state. Class E -- a change that exists in no repository.

    `route_health` models the Datadog shape: a package update restarts a network daemon and
    force-deletes routes managed by something else, taking nodes off the network. There is no
    commit to find, which is the point.
    """

    packages: dict[str, str] = field(default_factory=dict)
    route_health: float = 1.0       # 1.0 healthy, 0.0 fully partitioned
    events: list[dict] = field(default_factory=list)

    def record(self, at: datetime, package: str, to_version: str, channel: str,
               scope: str = "fleet", actor: str = "unattended-upgrades",
               team: str = "Platform") -> None:
        self.packages[package] = to_version
        self.events.append({
            "ts": at.isoformat(), "action": "upgrade", "package": package,
            "to_version": to_version, "channel": channel, "scope": scope,
            "actor": actor, "team": team,
        })


@dataclass
class ExternalState:
    """Provider status. Class G -- "not ours" is valid, but only when evidenced."""

    degraded: dict[str, str] = field(default_factory=dict)   # component -> status
    events: list[dict] = field(default_factory=list)

    def record(self, at: datetime, provider: str, component: str, title: str,
               status: str, url: str = "") -> None:
        self.degraded[component] = status
        self.events.append({
            "ts": at.isoformat(), "provider": provider, "component": component,
            "title": title, "status": status, "url": url,
        })


@dataclass
class FlagState:
    """Feature flags. Class B -- a production change with no commit and no review."""

    values: dict[str, bool] = field(default_factory=dict)
    history: list[dict] = field(default_factory=list)

    def set(self, at: datetime, flag: str, to: bool, actor: str, team: str,
            scope: str = "prod") -> None:
        self.history.append({
            "ts": at.isoformat(), "flag": flag, "from": self.values.get(flag),
            "to": to, "actor": actor, "team": team, "scope": scope,
        })
        self.values[flag] = to


@dataclass
class Capacity:
    """A write-throughput ceiling. Class F -- saturation with no change at all.

    Provisioned capacity is a number nobody edited. Traffic grew into it. The correct terminal
    is a capacity finding or a documented traffic event, not a culprit commit -- and an agent
    that assumes every incident has one will manufacture it.
    """

    writes_per_minute: int | None = None    # None means unlimited

    def throttled(self, attempted: int) -> int:
        if self.writes_per_minute is None:
            return 0
        return max(0, attempted - self.writes_per_minute)


@dataclass
class Queue:
    """A downstream queue and its consumer. Class H -- the poisoned queue.

    `poison` holds records the consumer cannot parse. The queue being blocked is machine state
    and must never be a terminal answer: something *produced* the malformed record, and that
    something is a human-authored change.
    """

    depth: int = 0
    poison: list[dict] = field(default_factory=list)
    consumer_healthy: bool = True

    #: A predicate over a record that makes it unparseable to the consumer. Set by an
    #: incident; None means every record is fine.
    malformed_when: Any = None

    def is_malformed(self, record: dict) -> bool:
        return bool(self.malformed_when and self.malformed_when(record))

    def publish(self, record: dict, malformed: bool = False) -> None:
        self.depth += 1
        if malformed:
            self.poison.append(record)
            # A poison record halts the consumer: depth grows from here regardless of rate.
            self.consumer_healthy = False

    def drain(self, n: int) -> int:
        if not self.consumer_healthy:
            return 0
        drained = min(self.depth, n)
        self.depth -= drained
        return drained


@dataclass
class Dependency:
    """A downstream service reached over an endpoint read from configuration.

    Classes C, G and I all live here: a wrong endpoint (a staging URL in a dependency team's
    repository), an unreachable provider, and a cascade where one failure produces the next.
    """

    name: str
    #: Endpoints and what each one is. A staging endpoint answers -- that is what makes class C
    #: hard. It answers with staging's limits, which decline most production traffic.
    known: dict[str, dict] = field(default_factory=dict)
    timeout_ms: int = 500

    def call(self, endpoint: str, external: ExternalState) -> Outcome:
        spec = self.known.get(endpoint)
        if spec is None:
            return Outcome(status=502, stage="dependency", latency_ms=self.timeout_ms,
                           reason="no route to {}".format(endpoint))
        if spec.get("component") and external.degraded.get(spec["component"]):
            return Outcome(status=504, stage="dependency", latency_ms=self.timeout_ms,
                           reason="{} unreachable: provider reports {}".format(
                               self.name, external.degraded[spec["component"]]))
        if spec.get("declines"):
            return Outcome(status=402, stage="dependency", latency_ms=spec.get("latency", 60),
                           reason="{} declined: {}".format(self.name, spec["declines"]))
        return Outcome(status=200, stage="dependency", latency_ms=spec.get("latency", 55))


def load_state(root: Path) -> dict[str, Any]:
    """Read the extended world state, defaulting to healthy."""
    path = Path(root) / "pipeline.json"
    if not path.exists():
        return {}
    return json.loads(path.read_text(encoding="utf-8"))


def save_state(root: Path, host: HostState, external: ExternalState, flags: FlagState,
               capacity: Capacity, queue: Queue) -> None:
    """Persist state, and write the append-only streams the collectors read.

    The collectors are given files, not objects: `package_collector` and `external_collector`
    read JSONL exactly as they would read an unattended-upgrade log or a status-page feed in a
    real deployment. Nothing about the simulator leaks into them.
    """
    root = Path(root)
    root.mkdir(parents=True, exist_ok=True)
    (root / "pipeline.json").write_text(json.dumps({
        "host": {"packages": host.packages, "route_health": host.route_health},
        "external": {"degraded": external.degraded},
        "flags": {"values": flags.values},
        "capacity": {"writes_per_minute": capacity.writes_per_minute},
        "queue": {"depth": queue.depth, "poison": len(queue.poison),
                  "consumer_healthy": queue.consumer_healthy},
    }, indent=2), encoding="utf-8")

    for sub, name, rows in (
        ("host", "packages.jsonl", host.events),
        ("external", "events.jsonl", external.events),
        ("flags", "history.jsonl", flags.history),
    ):
        d = root.parent / sub
        d.mkdir(parents=True, exist_ok=True)
        with (d / name).open("a", encoding="utf-8") as fh:
            for r in rows:
                fh.write(json.dumps(r, sort_keys=True) + "\n")
        rows.clear()
