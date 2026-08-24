"""DynamoDB stand-in: tables of JSON items, per-table TTL, IAM-enforced writes.

The TTL matters to the incident, not as decoration: `orders-staging` carries a 24h TTL, which
is why the decision package must order data export *before* the ConfigMap revert (spec 8.6).
`expired_at()` lets the Verifier and the report state the real deadline rather than assert one.
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path

from .iam import IAM

ACCOUNT = "000000000000"
REGION = "us-east-1"


def table_arn(name: str) -> str:
    return f"arn:aws:dynamodb:{REGION}:{ACCOUNT}:table/{name}"


@dataclass
class Table:
    name: str
    ttl_hours: int | None = None
    items: list[dict] = field(default_factory=list)

    @property
    def arn(self) -> str:
        return table_arn(self.name)

    def expired_at(self, now: datetime) -> list[dict]:
        """Items that will be gone by `now` given the TTL. Empty when no TTL is set."""
        if self.ttl_hours is None:
            return []
        cutoff = now - timedelta(hours=self.ttl_hours)
        return [i for i in self.items if _ts(i["_written_at"]) < cutoff]


def _ts(s: str) -> datetime:
    return datetime.fromisoformat(s)


class DynamoDB:
    """File-backed. One JSONL file per table plus a small metadata file."""

    def __init__(self, root: Path, iam: IAM):
        self.root = Path(root)
        self.iam = iam
        self.tables: dict[str, Table] = {}
        self.root.mkdir(parents=True, exist_ok=True)
        self.load()

    # -- persistence ----------------------------------------------------------
    def load(self) -> None:
        meta_path = self.root / "_tables.json"
        if not meta_path.exists():
            return
        meta = json.loads(meta_path.read_text(encoding="utf-8"))
        for name, m in meta.items():
            t = Table(name=name, ttl_hours=m.get("ttl_hours"))
            data = self.root / f"{name}.jsonl"
            if data.exists():
                t.items = [
                    json.loads(line)
                    for line in data.read_text(encoding="utf-8").splitlines()
                    if line.strip()
                ]
            self.tables[name] = t

    def save(self) -> None:
        self.root.mkdir(parents=True, exist_ok=True)
        (self.root / "_tables.json").write_text(
            json.dumps(
                {n: {"ttl_hours": t.ttl_hours} for n, t in sorted(self.tables.items())},
                indent=2,
            ),
            encoding="utf-8",
        )
        for name, t in self.tables.items():
            (self.root / f"{name}.jsonl").write_text(
                "".join(json.dumps(i, sort_keys=True) + "\n" for i in t.items),
                encoding="utf-8",
            )

    # -- API ------------------------------------------------------------------
    def create_table(self, name: str, ttl_hours: int | None = None) -> Table:
        t = Table(name=name, ttl_hours=ttl_hours)
        self.tables[name] = t
        return t

    def put_item(self, principal: str, table: str, item: dict, at: datetime) -> None:
        """Authorize, then write. Raises AccessDenied exactly as the real service would."""
        self.iam.authorize(principal, "dynamodb:PutItem", table_arn(table))
        if table not in self.tables:
            # A real DynamoDB PutItem to a missing table raises ResourceNotFound; in this
            # world every referenced table exists, so treat this as a simulator bug.
            raise KeyError(f"no such table: {table}")
        row = dict(item)
        row["_written_at"] = at.isoformat()
        self.tables[table].items.append(row)

    def count(self, table: str, since: datetime | None = None) -> int:
        t = self.tables.get(table)
        if not t:
            return 0
        if since is None:
            return len(t.items)
        return sum(1 for i in t.items if _ts(i["_written_at"]) >= since)
