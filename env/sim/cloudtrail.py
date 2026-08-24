"""CloudTrail and Kubernetes-audit event streams.

These two streams are why the ledger can see changes that exist in *no repository* -- console
actions, IAM edits, ConfigMap mutations. Spec 5.1 is explicit that a git-only ledger shows a
clean board for whole incident classes (the Datadog shape, class E).
"""
from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path


class EventLog:
    """Append-only JSONL. One line per control-plane event."""

    def __init__(self, path: Path):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)

    def emit(self, **event) -> None:
        with self.path.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(event, sort_keys=True) + "\n")

    def read(self) -> list[dict]:
        if not self.path.exists():
            return []
        return [
            json.loads(line)
            for line in self.path.read_text(encoding="utf-8").splitlines()
            if line.strip()
        ]


class CloudTrail(EventLog):
    def record(
        self, at: datetime, event_name: str, principal: str, source: str, request: dict
    ) -> None:
        self.emit(
            eventTime=at.isoformat(),
            eventName=event_name,
            eventSource=source,
            userIdentity={"arn": principal, "type": "IAMUser"},
            requestParameters=request,
            awsRegion="us-east-1",
        )


class K8sAudit(EventLog):
    def record(
        self, at: datetime, verb: str, user: str, resource: str, namespace: str,
        name: str, diff: dict | None = None,
    ) -> None:
        self.emit(
            requestReceivedTimestamp=at.isoformat(),
            verb=verb,
            user={"username": user},
            objectRef={"resource": resource, "namespace": namespace, "name": name},
            annotations={"diff": json.dumps(diff)} if diff else {},
            stage="ResponseComplete",
            responseStatus={"code": 200},
        )
