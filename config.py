"""Central configuration. Every budget and threshold the spec requires in code lives here.

Nothing in this file is incident-specific. Nothing here may be tuned per incident -- the
evaluation harness runs every incident against the same config, per the anti-gaming rules
in spec section 10.1.
"""
from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path

ROOT = Path(__file__).resolve().parent

# --- filesystem layout -------------------------------------------------------
ENV_DIR = ROOT / "env"
REPOS_DIR = ENV_DIR / "repos"
STATE_DIR = ENV_DIR / "state"
TELEMETRY_DIR = STATE_DIR / "telemetry"
CLOUD_DIR = STATE_DIR / "cloud"
CLUSTER_DIR = STATE_DIR / "cluster"
INCIDENTS_DIR = ROOT / "incidents"
RUNS_DIR = ROOT / "runs"
LEDGER_DB = STATE_DIR / "ledger.db"


@dataclass(frozen=True)
class Budget:
    """Spec section 5.9.3 -- hard caps enforced in code. Exhaustion triggers T4, never a guess."""

    max_steps: int = 12
    max_wall_seconds: float = 600.0
    max_spend_usd: float = 5.00
    max_tokens: int = 400_000
    #: retry cap per individual tool call (5.9.3)
    max_tool_retries: int = 2


@dataclass(frozen=True)
class Config:
    """Everything the Gate, the loop and the tools read at runtime."""

    budget: Budget = field(default_factory=Budget)

    #: Anomalies at or above this severity must be explained for T2 closure (5.6 rule 2).
    #: Anything below is allowed to remain, but is reported in `unexplained` (5.8).
    min_severity: str = "medium"

    #: Hard cap on the causal brief handed to the model (5.3). Not a target -- a limit.
    max_brief_tokens: int = 30_000

    #: Hard cap on any single tool result (0.2). Beyond this a tool returns a handle.
    max_tool_tokens: int = 2_000

    #: Highest verification tier the Verifier may attempt (5.7).
    max_verification_tier: str = "T2"

    #: Competing hypotheses generated per step (5.5).
    hypotheses_per_step: int = 3

    #: Read-only by default. Writing to a real environment is not implemented anywhere
    #: in this codebase; this flag exists so the safety layer can assert on it (5.9.1).
    read_only: bool = True

    @staticmethod
    def from_env() -> "Config":
        b = Budget(
            max_steps=int(os.getenv("HISEV_MAX_STEPS", 12)),
            max_wall_seconds=float(os.getenv("HISEV_MAX_WALL", 600.0)),
            max_spend_usd=float(os.getenv("HISEV_MAX_SPEND", 5.00)),
        )
        return Config(budget=b)


DEFAULT = Config()

# --- the simulated world's clock ---------------------------------------------
# A fixed date makes every run reproducible and every timestamp in the answer key stable.
INCIDENT_DATE = "2026-08-20"
