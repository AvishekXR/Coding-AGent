"""Snapshot observed cluster configuration state. Spec 5.4.3 support, 5.1.2 freshness.

Records which keys are *actually* projected into each running service, and from which
ConfigMap. The interesting fact this captures is usually a negative one -- that a key the code
reads is not present anywhere in the running configuration. An absence has no audit event and
no metric; it can only be found by looking.
"""
from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path

import config as cfg
from ledger.ledger import Ledger
from util import iso


def collect(ledger: Ledger, state_dir: Path | None = None) -> int:
    state = Path(state_dir or cfg.STATE_DIR)
    objects = state / "cluster" / "objects.json"
    if not objects.exists():
        return 0

    raw = json.loads(objects.read_text(encoding="utf-8"))
    now = iso(datetime.utcnow())
    ledger.conn.execute("DELETE FROM config_state")
    written = 0

    configmaps = raw.get("configmaps", {})
    deployments = raw.get("deployments", {})

    # Which ConfigMaps each service actually projects, and what the pods really see.
    for dep in deployments.values():
        service = dep.get("service")
        for cm_name in dep.get("env_from", []):
            cm = configmaps.get(cm_name, {})
            for key, value in (cm.get("data") or {}).items():
                ledger.conn.execute(
                    """INSERT INTO config_state
                         (kind, name, namespace, key, value, source_ref, service, observed_at)
                       VALUES (?,?,?,?,?,?,?,?)""",
                    ("configmap", cm_name, cm.get("namespace"), key, value,
                     "configmap/{}".format(cm_name), service,
                     cm.get("updated_at") or now),
                )
                written += 1
        for key, value in (dep.get("pod_env") or {}).items():
            ledger.conn.execute(
                """INSERT INTO config_state
                     (kind, name, namespace, key, value, source_ref, service, observed_at)
                   VALUES (?,?,?,?,?,?,?,?)""",
                ("deployment_env", dep.get("name"), dep.get("namespace"), key, value,
                 "deployment/{}".format(dep.get("name")), service,
                 dep.get("last_rollout") or now),
            )
            written += 1
    ledger.commit()
    return written
