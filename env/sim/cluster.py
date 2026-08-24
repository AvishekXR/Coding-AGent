"""Kubernetes stand-in: ConfigMaps, Deployments, and the rollout that propagates env.

The propagation delay is the point. A ConfigMap edit does not change a running pod's
environment -- the pod must restart. That is why the incident's first symptom trails the
change that caused it, and why the Gate's timing-sanity rule (spec 5.6 rule 3) has to compare
against `first_symptom_ts` rather than against the alert time.
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path

from .cloudtrail import K8sAudit


@dataclass
class ConfigMap:
    name: str
    namespace: str
    data: dict[str, str]
    #: spec 5.1.2 -- freshness stamps on everything derived
    updated_at: str | None = None


@dataclass
class Deployment:
    name: str
    namespace: str
    service: str
    #: ConfigMaps whose keys are projected wholesale into the pod environment (envFrom)
    env_from: list[str] = field(default_factory=list)
    #: environment actually visible to the running pods; only changes on rollout
    pod_env: dict[str, str] = field(default_factory=dict)
    last_rollout: str | None = None


class Cluster:
    def __init__(self, root: Path, audit: K8sAudit):
        self.root = Path(root)
        self.audit = audit
        self.configmaps: dict[str, ConfigMap] = {}
        self.deployments: dict[str, Deployment] = {}
        self.root.mkdir(parents=True, exist_ok=True)
        self.load()

    # -- persistence ----------------------------------------------------------
    def load(self) -> None:
        p = self.root / "objects.json"
        if not p.exists():
            return
        raw = json.loads(p.read_text(encoding="utf-8"))
        self.configmaps = {k: ConfigMap(**v) for k, v in raw.get("configmaps", {}).items()}
        self.deployments = {k: Deployment(**v) for k, v in raw.get("deployments", {}).items()}

    def save(self) -> None:
        self.root.mkdir(parents=True, exist_ok=True)
        (self.root / "objects.json").write_text(
            json.dumps(
                {
                    "configmaps": {k: vars(v) for k, v in sorted(self.configmaps.items())},
                    "deployments": {k: vars(v) for k, v in sorted(self.deployments.items())},
                },
                indent=2,
            ),
            encoding="utf-8",
        )

    # -- API ------------------------------------------------------------------
    def apply_configmap(
        self, name: str, namespace: str, data: dict[str, str], at: datetime, user: str
    ) -> dict:
        """`kubectl apply` a ConfigMap. Emits a real audit event carrying the key-level diff."""
        old = self.configmaps.get(name)
        diff = _key_diff(old.data if old else {}, data)
        self.configmaps[name] = ConfigMap(
            name=name, namespace=namespace, data=dict(data), updated_at=at.isoformat()
        )
        self.audit.record(
            at=at, verb="update" if old else "create", user=user,
            resource="configmaps", namespace=namespace, name=name, diff=diff,
        )
        return diff

    def rollout(self, deployment: str, at: datetime, user: str = "system:deployment-controller") -> None:
        """Restart pods so they re-read env from their ConfigMaps. This is where env changes land."""
        d = self.deployments[deployment]
        env: dict[str, str] = {}
        for cm_name in d.env_from:
            cm = self.configmaps.get(cm_name)
            if cm:
                env.update(cm.data)
        d.pod_env = env
        d.last_rollout = at.isoformat()
        self.audit.record(
            at=at, verb="update", user=user, resource="deployments",
            namespace=d.namespace, name=deployment, diff={"rollout": "pods restarted"},
        )

    def env_for(self, service: str) -> dict[str, str]:
        """The environment the running process actually sees right now."""
        for d in self.deployments.values():
            if d.service == service:
                return dict(d.pod_env)
        return {}


def _key_diff(old: dict[str, str], new: dict[str, str]) -> dict:
    """Key-level diff. Deliberately reports added/removed keys, because a *rename* shows up
    as one of each -- which is the signal that cracks the reference incident."""
    added = sorted(set(new) - set(old))
    removed = sorted(set(old) - set(new))
    changed = sorted(k for k in set(old) & set(new) if old[k] != new[k])
    return {"added": added, "removed": removed, "changed": changed}
