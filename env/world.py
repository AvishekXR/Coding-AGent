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
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from pathlib import Path
from typing import Callable

import config as cfg
from env.sim.cloudtrail import CloudTrail, K8sAudit
from env.sim.cluster import Cluster, Deployment
from env.sim.dynamo import DynamoDB, table_arn
from env.sim.iam import IAM, AccessDenied
from env.sim.pipeline import (
    Capacity, Dependency, ExternalState, FlagState, HostState, Queue,
    load_state, save_state,
)
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
    #: Extended pipeline state. All healthy by default; an incident throws the switches.
    host: HostState = field(default_factory=HostState)
    external: ExternalState = field(default_factory=ExternalState)
    flags: FlagState = field(default_factory=FlagState)
    capacity: Capacity = field(default_factory=Capacity)
    queue: Queue | None = None
    payments: Dependency | None = None
    #: orders-api's own validation function, loaded from the repository when it exists.
    _validate: Callable | None = None

    @staticmethod
    def open(state_dir: Path | None = None, repos: Path | None = None) -> "World":
        state = Path(state_dir or cfg.STATE_DIR)
        iam = IAM(state / "cloud" / "iam.json")
        db = DynamoDB(state / "cloud" / "dynamodb", iam)
        audit = K8sAudit(state / "cluster" / "audit.jsonl")
        cluster = Cluster(state / "cluster", audit)
        w = World(
            root=state, iam=iam, db=db, cluster=cluster,
            cloudtrail=CloudTrail(state / "cloud" / "cloudtrail.jsonl"),
            audit=audit, telemetry=Telemetry(state / "telemetry"),
            repos=Path(repos or cfg.REPOS_DIR),
        )
        saved = load_state(state / "pipeline")
        if saved:
            w.host.packages = saved.get("host", {}).get("packages", {})
            w.host.route_health = saved.get("host", {}).get("route_health", 1.0)
            w.external.degraded = saved.get("external", {}).get("degraded", {})
            w.flags.values = saved.get("flags", {}).get("values", {})
            w.capacity.writes_per_minute = saved.get("capacity", {}).get("writes_per_minute")
        return w

    def save(self) -> None:
        self.iam.save()
        self.db.save()
        self.cluster.save()
        self.telemetry.flush()
        save_state(self.root / "pipeline", self.host, self.external, self.flags,
                   self.capacity, self.queue or Queue())

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
        self._load_service_code()

    def _load_service_code(self) -> None:
        """Bind the pipeline stages that live in repository source.

        Loaded rather than reimplemented, so that a commit changing validation genuinely
        changes what the running service does -- which is what makes a code regression
        (class A) a real incident rather than a described one.
        """
        vpath = self.repos / "orders-api" / "app" / "validate.py"
        if vpath.exists():
            mod = _load_module(vpath, "oa_validate")
            self._validate = getattr(mod, "validate_order", None)

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
        self._load_service_code()
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

            stats = self._run_minute(at, table, env, rng, n)
            n = stats["n"]
            self._emit_minute(at, table, stats, rng)
            at += timedelta(minutes=1)
        self.telemetry.flush()

    def _run_minute(self, at: datetime, table: str, env: dict, rng: random.Random,
                    n: int) -> dict:
        """One minute of requests through the full pipeline.

        Every stage below is pass-through in a healthy world. They exist so that the twelve
        incident classes of spec section 9 have distinct places to break: a world with one
        failure mode can only host one shape of incident, and passing a range of twelve
        variations on the same shape would mean nothing.
        """
        accepted = denied = rejected = throttled = declined = timed_out = 0
        latencies: list[int] = []

        # Stage 1 -- feature flag. Selects a code path; no commit behind it.
        strict = self.flags.values.get("orders.strict_validation", False)
        # Stage 4 -- capacity ceiling. A number nobody edited; traffic grew into it.
        over = self.capacity.throttled(API_ORDERS_PER_MIN)

        for i in range(API_ORDERS_PER_MIN):
            n += 1
            order = {"order_id": "ord-{:07d}".format(n),
                     "amount_cents": rng.randrange(500, 40000),
                     # Bounded below the baseline validation limits, so a healthy world has
                     # zero rejections. Validation only becomes visible when a change makes
                     # it stricter -- otherwise class A would be indistinguishable from noise.
                     "items": rng.randrange(1, 9)}

            # Stage 2 -- the service's own validation, executed from the repository.
            if self._validate is not None:
                ok, why = self._validate(order, strict=strict)
                if not ok:
                    rejected += 1
                    latencies.append(12)
                    self.telemetry.log(at, "orders-api", "WARN", "order rejected",
                                       order_id=order["order_id"], status=422, reason=why)
                    continue

            # Stage 3 -- downstream dependency over an endpoint read from configuration.
            if self.payments is not None:
                endpoint = env.get("PAYMENTS_ENDPOINT", "")
                out = self.payments.call(endpoint, self.external)
                if not out.accepted:
                    if out.status == 504:
                        timed_out += 1
                    else:
                        declined += 1
                    latencies.append(out.latency_ms)
                    self.telemetry.log(at, "orders-api", "ERROR", "payment call failed",
                                       order_id=order["order_id"], status=out.status,
                                       reason=out.reason)
                    continue
                latencies.append(out.latency_ms)

            if i >= API_ORDERS_PER_MIN - over:
                throttled += 1
                latencies.append(900 + rng.randrange(0, 200))
                self.telemetry.log(at, "orders-api", "WARN", "write throttled",
                                   order_id=order["order_id"], status=429,
                                   reason="provisioned write capacity exceeded")
                continue

            # Stage 5 -- authorization, then the write.
            allowed, reason = self.iam.evaluate(
                ORDERS_PRINCIPAL, "dynamodb:PutItem", table_arn(table))
            if i == 0:
                # Sample one authorization decision per minute, as a real data-event trail
                # would. Recording all of them would be 100x the volume for no extra signal.
                self.telemetry.authz(at, ORDERS_PRINCIPAL, "dynamodb:PutItem",
                                     table_arn(table), allowed, reason)
            try:
                self.db.put_item(ORDERS_PRINCIPAL, table, order, at)
                accepted += 1
                latencies.append(38 + rng.randrange(0, 12))
            except AccessDenied:
                denied += 1
                latencies.append(15)
                continue

            # Stage 6 -- publish downstream. A malformed record halts the consumer.
            malformed = self.queue.is_malformed(order) if self.queue else False
            if self.queue is not None:
                self.queue.publish(order, malformed=malformed)

        if self.queue is not None:
            self.queue.drain(API_ORDERS_PER_MIN)

        for _ in range(BATCH_ORDERS_PER_MIN):
            n += 1
            self.db.put_item(
                "orders-batch-importer", "orders-prod",
                {"order_id": "bat-{:07d}".format(n),
                 "amount_cents": rng.randrange(500, 40000)}, at)

        return {"n": n, "accepted": accepted, "denied": denied, "rejected": rejected,
                "throttled": throttled, "declined": declined, "timed_out": timed_out,
                "latencies": latencies or [40]}

    def _emit_minute(self, at: datetime, table: str, stats: dict,
                     rng: random.Random) -> None:
        nxt = at + timedelta(minutes=1)
        accepted, denied = stats["accepted"], stats["denied"]

        # The business metric, computed the way analytics-etl computes it: rows landing in the
        # source table it reads. It never looks at orders-api response codes, which is exactly
        # why the silent redirect is invisible to every infrastructure alert.
        created = self.db.count("orders-prod", since=at) - self.db.count("orders-prod", since=nxt)
        self.telemetry.metric(at, "analytics-etl", "orders_created", created)
        self.telemetry.metric(at, "orders-api", "http_requests_total", API_ORDERS_PER_MIN)

        # Each failure stage has its own response class, so that the classes of spec section 9
        # are distinguishable in telemetry rather than all looking like "errors are up".
        fail_5xx = stats["timed_out"]
        fail_4xx = stats["rejected"] + stats["declined"] + stats["throttled"] + denied
        self.telemetry.metric(at, "orders-api", "http_5xx_rate",
                              round(fail_5xx / API_ORDERS_PER_MIN, 4))
        self.telemetry.metric(at, "orders-api", "http_4xx_rate",
                              round(fail_4xx / API_ORDERS_PER_MIN, 4))
        lat = sorted(stats["latencies"])
        p99 = lat[min(len(lat) - 1, int(len(lat) * 0.99))]
        self.telemetry.metric(at, "orders-api", "latency_p99_ms",
                              p99 if p99 > 60 else 42 + rng.randrange(-4, 5))
        self.telemetry.metric(at, "orders-api", "dynamodb_writes." + table, accepted)
        self.telemetry.metric(at, "orders-api", "dynamodb_access_denied", denied)

        # Only emit a series when the stage is active. A metric that is flat at zero in both
        # baseline and window is noise; one that appears mid-window is a structural change,
        # and the novel-series detector is built to notice exactly that.
        for name, value in (("validation_rejected", stats["rejected"]),
                            ("payment_declined", stats["declined"]),
                            ("payment_timeout", stats["timed_out"]),
                            ("write_throttled", stats["throttled"])):
            if value:
                self.telemetry.metric(at, "orders-api", name, value)
        if self.queue is not None and (self.queue.depth or self.queue.poison):
            self.telemetry.metric(at, "orders-queue", "queue_depth", self.queue.depth)
            self.telemetry.metric(at, "orders-queue", "poison_records",
                                  len(self.queue.poison))
        if self.host.route_health < 1.0:
            self.telemetry.metric(at, "orders-api", "node_route_health",
                                  round(self.host.route_health, 3))

        self._emit_logs(at, table, rng)

    #: Routine line shapes and their share of log volume. Real services emit a handful of
    #: templates at wildly different rates; a single shape would make the compression ratio
    #: in the causal brief meaningless.
    LOG_MIX = (
        (0.82, "orders-api", "INFO", "order accepted"),
        (0.10, "orders-api", "INFO", "health check ok"),
        (0.05, "orders-api", "DEBUG", "cache lookup"),
        (0.02, "analytics-etl", "INFO", "batch flushed"),
        (0.01, "orders-api", "WARN", "slow downstream response"),
    )

    def _emit_logs(self, at: datetime, table: str, rng: random.Random) -> None:
        for i in range(LOG_LINES_PER_MIN):
            ts = at + timedelta(seconds=(60 * i) // LOG_LINES_PER_MIN)
            roll = rng.random()
            acc = 0.0
            for share, service, level, msg in self.LOG_MIX:
                acc += share
                if roll <= acc:
                    break
            fields = {"duration_ms": 38 + rng.randrange(0, 12)}
            if msg == "order accepted":
                # `table` is a field *value*, and the compressor drops values. That is not an
                # oversight: it is why this incident leaves no trace in the logs at all. The
                # destination changed, every line stayed the same shape, and no new pattern
                # appears for anyone to notice.
                fields.update(order_id="ord-{:06d}".format(rng.randrange(10 ** 6)),
                              status=201, table=table)
            elif msg == "health check ok":
                fields.update(endpoint="/healthz", status=200)
            elif msg == "cache lookup":
                fields.update(key="sku-{:05d}".format(rng.randrange(10 ** 5)),
                              hit=rng.random() > 0.2)
            elif msg == "batch flushed":
                fields.update(rows=rng.randrange(50, 500))
            else:
                fields.update(peer="pricing-api", status=200)
            self.telemetry.log(ts, service, level, msg, **fields)
