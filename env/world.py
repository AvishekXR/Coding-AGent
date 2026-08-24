"""The simulated company, composed.

`World` owns the cloud, the cluster, the repositories and the telemetry streams, and knows how
to run traffic through the *real* orders-api source code checked into env/repos/orders-api.
Nothing above this module (collectors, ledger, indexer, tools, agent) may import it -- they see
the world only through collectors and the seven tool contracts.
"""
from __future__ import annotations

import importlib.util
import json
import random
import sys
from dataclasses import dataclass
from datetime import datetime, timedelta
from pathlib import Path
from typing import Callable

import config as cfg
from env.sim.cloudtrail import CloudTrail, K8sAudit
from env.sim.cluster import Cluster, Deployment
from env.sim.dynamo import DynamoDB, table_arn
from env.sim.iam import IAM, AccessDenied
from env.sim.render import apply_iac, parse_configmaps

ORDERS_PRINCIPAL = "orders-api"

#: Orders per minute arriving at orders-api.
API_ORDERS_PER_MIN = 100
#: Orders per minute written directly to orders-prod by the legacy batch importer, which
#: reads no ConfigMap and is therefore unaffected by the incident. This residual traffic is
#: why the business metric drops by ~94% rather than 100%.
BATCH_ORDERS_PER_MIN = 6

#: Routine log lines emitted per minute across all services. Drives the compression test.
LOG_LINES_PER_MIN = 500


def _load_module(path: Path, name: str):
    """Import a module directly from the checked-out repository working tree."""
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise ImportError("cannot load {} from {}".format(name, path))
    mod = importlib.util.module_from_spec(spec)
    sys.modules[name] = mod
    spec.loader.exec_module(mod)
    return mod


class Telemetry:
    """Metrics and logs as JSONL. The causal indexer is the only consumer."""

    def __init__(self, root: Path):
        self.root = Path(root)
        self.root.mkdir(parents=True, exist_ok=True)
        self.metrics_path = self.root / "metrics.jsonl"
        self.logs_path = self.root / "logs.jsonl"
        self.authz_path = self.root / "authz.jsonl"
        self._m: list[str] = []
        self._l: list[str] = []
        self._a: list[str] = []

    def metric(self, at: datetime, entity: str, name: str, value: float) -> None:
        self._m.append(
            json.dumps({"ts": at.isoformat(), "entity": entity, "metric": name, "value": value})
        )

    def log(self, at: datetime, service: str, level: str, msg: str, **fields) -> None:
        row = {"ts": at.isoformat(), "service": service, "level": level, "msg": msg}
        row.update(fields)
        self._l.append(json.dumps(row))

    def authz(self, at: datetime, principal: str, action: str, resource: str,
              allowed: bool, reason: str) -> None:
        """Data-plane authorization decisions.

        The *absence* of denials here is observable, which is what lets the indexer notice a
        guard rail that quietly stopped firing. An anomaly detector that only looks at metrics
        going up cannot see this.
        """
        self._a.append(
            json.dumps({
                "ts": at.isoformat(), "principal": principal, "action": action,
                "resource": resource, "allowed": allowed, "reason": reason,
            })
        )

    def flush(self, append: bool = True) -> None:
        mode = "a" if append else "w"
        for path, buf in (
            (self.metrics_path, self._m), (self.logs_path, self._l), (self.authz_path, self._a)
        ):
            with path.open(mode, encoding="utf-8") as fh:
                fh.write("".join(line + "\n" for line in buf))
        self._m.clear()
        self._l.clear()
        self._a.clear()


@dataclass
class World:
    root: Path
    iam: IAM
    db: DynamoDB
    cluster: Cluster
    cloudtrail: CloudTrail
    audit: K8sAudit
    telemetry: Telemetry
    repos: Path

    @staticmethod
    def open(state_dir: Path | None = None, repos: Path | None = None) -> "World":
        state = Path(state_dir or cfg.STATE_DIR)
        iam = IAM(state / "cloud" / "iam.json")
        db = DynamoDB(state / "cloud" / "dynamodb", iam)
        audit = K8sAudit(state / "cluster" / "audit.jsonl")
        cluster = Cluster(state / "cluster", audit)
        return World(
            root=state, iam=iam, db=db, cluster=cluster,
            cloudtrail=CloudTrail(state / "cloud" / "cloudtrail.jsonl"),
            audit=audit, telemetry=Telemetry(state / "telemetry"),
            repos=Path(repos or cfg.REPOS_DIR),
        )

    def save(self) -> None:
        self.iam.save()
        self.db.save()
        self.cluster.save()
        self.telemetry.flush()

    # -- bring-up -------------------------------------------------------------
    def bootstrap(self, at: datetime) -> None:
        """Render repositories into live state and start the services. Healthy by construction."""
        apply_iac(self.repos / "platform-iac", self.iam)

        self.db.create_table("orders-prod", ttl_hours=None)
        # Staging carries a 24h TTL. This is the rollback hazard in spec 8.6 -- a real
        # property of the table here, not an assertion typed into a report.
        self.db.create_table("orders-staging", ttl_hours=24)

        for doc in parse_configmaps(self.repos / "platform-config", "prod"):
            self.cluster.apply_configmap(
                name=doc["metadata"]["name"], namespace="prod", data=doc["data"],
                at=at, user="system:config-sync",
            )
        self.cluster.deployments["orders-api"] = Deployment(
            name="orders-api", namespace="prod", service="orders-api",
            env_from=["orders-config"],
        )
        self.cluster.deployments["analytics-etl"] = Deployment(
            name="analytics-etl", namespace="prod", service="analytics-etl",
            env_from=["analytics-config"],
        )
        self.cluster.rollout("orders-api", at)
        self.cluster.rollout("analytics-etl", at)

    # -- traffic --------------------------------------------------------------
    def run_traffic(self, start: datetime, end: datetime, seed: int = 4471,
                    hooks: dict[datetime, Callable] | None = None) -> None:
        """Drive one minute of traffic at a time from `start` to `end`.

        `hooks` maps a timestamp to a callable(world, at) applied at the top of that minute --
        this is how an incident injects its changes mid-stream, so the telemetry either side
        of a change is generated by the same code path.
        """
        rng = random.Random(seed)
        api_mod = _load_module(self.repos / "orders-api" / "app" / "config.py", "oa_config")
        hooks = dict(hooks or {})
        at = start
        n = 0
        while at < end:
            due = sorted(t for t in hooks if at <= t < at + timedelta(minutes=1))
            for hook_ts in due:
                hooks.pop(hook_ts)(self, hook_ts)

            env = self.cluster.env_for("orders-api")
            # The real resolution, executed by the real repository code.
            table = api_mod.resolve_table_name(env)

            accepted = 0
            denied = 0
            for i in range(API_ORDERS_PER_MIN):
                n += 1
                order = {"order_id": "ord-{:07d}".format(n), "amount_cents": rng.randrange(500, 40000)}
                allowed, reason = self.iam.evaluate(
                    ORDERS_PRINCIPAL, "dynamodb:PutItem", table_arn(table)
                )
                if i == 0:
                    # Sample one authorization decision per minute, as a real data-event
                    # trail would. Recording all of them would be 100x the volume for no
                    # extra signal.
                    self.telemetry.authz(
                        at, ORDERS_PRINCIPAL, "dynamodb:PutItem", table_arn(table),
                        allowed, reason,
                    )
                try:
                    self.db.put_item(ORDERS_PRINCIPAL, table, order, at)
                    accepted += 1
                except AccessDenied:
                    denied += 1

            for _ in range(BATCH_ORDERS_PER_MIN):
                n += 1
                self.db.put_item(
                    "orders-batch-importer", "orders-prod",
                    {"order_id": "bat-{:07d}".format(n), "amount_cents": rng.randrange(500, 40000)},
                    at,
                )

            self._emit_minute(at, table, accepted, denied, rng)
            at += timedelta(minutes=1)
        self.telemetry.flush()

    def _emit_minute(self, at: datetime, table: str, accepted: int, denied: int,
                     rng: random.Random) -> None:
        nxt = at + timedelta(minutes=1)
        # The business metric, computed the way analytics-etl computes it: rows landing in the
        # source table it reads. It never looks at orders-api response codes, which is exactly
        # why this incident is invisible to every infrastructure alert.
        created = self.db.count("orders-prod", since=at) - self.db.count("orders-prod", since=nxt)
        self.telemetry.metric(at, "analytics-etl", "orders_created", created)
        self.telemetry.metric(at, "orders-api", "http_requests_total", API_ORDERS_PER_MIN)
        # Every request is a 201 unless a write was actually denied. This is what makes the
        # incident silent: the redirect produces no error of any kind.
        self.telemetry.metric(
            at, "orders-api", "http_5xx_rate",
            0.0 if not denied else round(denied / API_ORDERS_PER_MIN, 4),
        )
        self.telemetry.metric(at, "orders-api", "latency_p99_ms", 42 + rng.randrange(-4, 5))
        self.telemetry.metric(at, "orders-api", "dynamodb_writes." + table, accepted)
        self.telemetry.metric(at, "orders-api", "dynamodb_access_denied", denied)

        for i in range(LOG_LINES_PER_MIN):
            ts = at + timedelta(seconds=(60 * i) // LOG_LINES_PER_MIN)
            self.telemetry.log(
                ts, "orders-api", "INFO", "order accepted",
                order_id="ord-{:06d}".format(rng.randrange(10 ** 6)), status=201, table=table,
                duration_ms=38 + rng.randrange(0, 12),
            )
