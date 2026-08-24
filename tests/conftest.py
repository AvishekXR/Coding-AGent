"""Shared fixtures.

`injected_world` builds the whole simulated company from nothing and applies incident 001. It
is session-scoped because it takes about twelve seconds; every world-level test shares one
build. Building it from scratch each session is deliberate -- it proves the world is
reproducible from an empty directory, which is the phase-0 acceptance criterion.
"""
from __future__ import annotations

import json

import pytest

import config as cfg


@pytest.fixture(scope="session")
def injected_world():
    """Seed the world, inject incident 001, and return (World, incident metadata)."""
    from env.world import World
    from incidents.inject import inject

    meta = inject("001", reseed=True)
    return World.open(), meta


@pytest.fixture(scope="session")
def metrics(injected_world):
    path = cfg.TELEMETRY_DIR / "metrics.jsonl"
    return [
        json.loads(line)
        for line in path.read_text(encoding="utf-8").splitlines() if line.strip()
    ]


@pytest.fixture(scope="session")
def incident_day_metrics(metrics, injected_world):
    _, meta = injected_world
    return [m for m in metrics if m["ts"].startswith(meta["day"])]
