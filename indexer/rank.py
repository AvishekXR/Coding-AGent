"""Candidate ranking. Part of the causal indexer (L1, spec 5.3). No LLM.

Ranks ledger changes by how plausibly they could have caused a failure in a given entity.
Three signals, all derived from data the background half already collected:

  1. **Temporal admissibility.** A change after the first symptom cannot have caused it. This
     is a hard zero, not a penalty -- it is the same fact the Gate checks as rule 3 (5.6), and
     ranking a post-symptom change highly would waste a step the budget cannot spare.
  2. **Literal coupling.** How strongly does the changed file share *specific* literals with
     the failing service? Shared table names, env keys and ARNs are how a change in another
     team's repository reaches this one. Weighted by inverse document frequency, so
     `ORDERS_TABLE` counts for far more than `aws-region`.
  3. **Blast breadth.** How many distinct repositories reference the literals this file
     touches? Shared configuration and IaC score higher, because the target incident class
     (1.4) lives precisely in changes that cross a team boundary.

**Anti-gaming (10.1):** this module knows nothing about any specific incident. It receives the
failing entity as a parameter, reads only the ledger and the reverse index, and may not import
anything from `incidents/`. Every signal above will also rank innocent co-occurring changes
highly -- a config edit that shares literals with the failing service looks identical to one
that caused the failure. That is expected and not a defect: ranking is retrieval, not
diagnosis. The Gate does diagnosis.
"""
from __future__ import annotations

import math
from dataclasses import dataclass
from datetime import datetime

from ledger.ledger import Change, Ledger
from util import parse_ts

#: Weights on the three signals. Deliberately blunt round numbers: a finely tuned ranker
#: fitted to one incident is exactly the failure spec 10.1 warns about.
W_COUPLING = 0.60
W_BREADTH = 0.25
W_RECENCY = 0.15


@dataclass
class Ranked:
    change: Change
    score: float
    reasons: dict

    def to_dict(self) -> dict:
        d = self.change.to_dict()
        d["rank_score"] = round(self.score, 4)
        d["rank_reasons"] = self.reasons
        return d


class Ranker:
    """Holds the derived index views. Build once per run, then call `rank`."""

    def __init__(self, ledger: Ledger):
        self.ledger = ledger
        self._file_literals: dict[tuple[str, str], set[str]] = {}
        self._literal_repos: dict[str, set[str]] = {}
        self._literal_files: dict[str, int] = {}
        self._total_files = 0
        self._load()

    def _load(self) -> None:
        rows = self.ledger.conn.execute(
            "SELECT literal, repo, path FROM mentions"
        ).fetchall()
        files: set[tuple[str, str]] = set()
        for r in rows:
            key = (r["repo"], r["path"])
            files.add(key)
            self._file_literals.setdefault(key, set()).add(r["literal"])
            self._literal_repos.setdefault(r["literal"], set()).add(r["repo"])
        self._total_files = max(len(files), 1)
        for lit, _ in self._literal_repos.items():
            self._literal_files[lit] = sum(
                1 for k, lits in self._file_literals.items() if lit in lits
            )

    # -- signal helpers -------------------------------------------------------
    def literals_of(self, repo: str | None, path: str | None) -> set[str]:
        if not repo or not path:
            return set()
        return set(self._file_literals.get((repo, path), set()))

    def literals_of_entity(self, entity: str) -> set[str]:
        """Every literal mentioned anywhere in the failing entity's own repository."""
        out: set[str] = set()
        for (repo, _path), lits in self._file_literals.items():
            if repo == entity:
                out |= lits
        return out

    def idf(self, literal: str) -> float:
        """Rarer literals carry more signal. `ORDERS_TABLE` beats `aws-region`."""
        df = self._literal_files.get(literal, 1)
        return math.log(1.0 + self._total_files / max(df, 1))

    # -- ranking --------------------------------------------------------------
    def rank(self, changes: list[Change], failing_entity: str,
             first_symptom_ts: datetime | str | None = None) -> list[Ranked]:
        entity_lits = self.literals_of_entity(failing_entity)
        symptom = parse_ts(first_symptom_ts) if first_symptom_ts else None

        earliest = min((c.ts for c in changes), default=None)
        span = ((symptom - earliest).total_seconds()
                if symptom and earliest and symptom > earliest else 1.0) or 1.0

        max_coupling = 0.0
        raw: list[tuple[Change, float, float, float, list[str]]] = []
        for c in changes:
            lits = self.literals_of(c.repo, c.path)
            shared = lits & entity_lits
            coupling = sum(self.idf(l) for l in shared)
            max_coupling = max(max_coupling, coupling)

            repos_touched: set[str] = set()
            for l in lits:
                repos_touched |= self._literal_repos.get(l, set())
            breadth = min(len(repos_touched) / 4.0, 1.0)

            if symptom is None:
                recency = 0.5
            elif c.ts > symptom:
                recency = 0.0
            else:
                age = (symptom - c.ts).total_seconds()
                recency = max(0.0, 1.0 - age / span)

            top_shared = sorted(shared, key=self.idf, reverse=True)[:4]
            raw.append((c, coupling, breadth, recency, top_shared))

        out: list[Ranked] = []
        for c, coupling, breadth, recency, top_shared in raw:
            norm_coupling = coupling / max_coupling if max_coupling else 0.0
            admissible = symptom is None or c.ts <= symptom
            score = (
                W_COUPLING * norm_coupling
                + W_BREADTH * breadth
                + W_RECENCY * recency
            )
            if not admissible:
                # Hard zero: a change cannot cause a symptom that preceded it. Kept in the
                # list rather than dropped, so the agent can see it was considered.
                score = 0.0
            out.append(Ranked(change=c, score=score, reasons={
                "shared_literals": top_shared,
                "coupling": round(norm_coupling, 3),
                "breadth": round(breadth, 3),
                "precedes_first_symptom": admissible,
            }))

        out.sort(key=lambda r: (-r.score, r.change.ts, r.change.id))
        return out

    def as_tool_ranker(self, failing_entity: str,
                       first_symptom_ts: datetime | str | None = None):
        """Adapter for `Tools(ranker=...)`: list[Change] -> list[Change], ranked."""

        def ranker(changes: list[Change]) -> list[Change]:
            return [r.change for r in self.rank(changes, failing_entity, first_symptom_ts)]

        return ranker
