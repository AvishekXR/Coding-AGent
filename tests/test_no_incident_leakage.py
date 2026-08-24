"""Anti-gaming enforcement. Spec section 10.1, and the constraint promised in DECISIONS.md D-003.

Spec 10 names fitting the self-authored test range as "the largest single risk in this
project" and 13 rates it the highest-probability failure by a wide margin. The structural
defence is that the solving half of the system cannot see the answers -- not by convention,
but because a test fails if it ever can.

Enforced here:
  1. No module in the solving half imports from `incidents/`.
  2. No module in the solving half reads `truth.yaml`, or names the answer-key fields.
  3. The deterministic proposer contains no incident-specific literals.
  4. The grader is not importable *from* the solving half.
"""
from __future__ import annotations

import ast
from pathlib import Path

import pytest

import config as cfg

#: The half of the system that solves incidents. It must be blind to the answers.
SOLVING_HALF = ("agent", "indexer", "ledger", "tools", "collectors", "safety")

#: Strings that only ever appear in an answer key or an incident author's file.
ANSWER_KEY_MARKERS = (
    "truth.yaml", "must_not_stop_at", "must_flag", "expected_gate_rejections",
    "distractors", "required_residue_anomaly", "flag_keywords",
)


def _py_files(package: str) -> list[Path]:
    return sorted((cfg.ROOT / package).rglob("*.py"))


def _all_solving_files() -> list[Path]:
    out: list[Path] = []
    for pkg in SOLVING_HALF:
        out.extend(_py_files(pkg))
    return out


def _imported_modules(path: Path) -> set[str]:
    tree = ast.parse(path.read_text(encoding="utf-8"))
    mods: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for a in node.names:
                mods.add(a.name.split(".")[0])
        elif isinstance(node, ast.ImportFrom) and node.module and node.level == 0:
            mods.add(node.module.split(".")[0])
    return mods


@pytest.mark.parametrize("path", _all_solving_files(), ids=lambda p: str(p.name))
def test_solving_half_does_not_import_incidents_or_eval(path):
    forbidden = {"incidents", "eval"}
    leaked = _imported_modules(path) & forbidden
    assert not leaked, "{} imports {} -- the solving half must be blind to the answers".format(
        path.relative_to(cfg.ROOT), leaked)


@pytest.mark.parametrize("path", _all_solving_files(), ids=lambda p: str(p.name))
def test_solving_half_never_names_the_answer_key(path):
    text = path.read_text(encoding="utf-8")
    hits = [m for m in ANSWER_KEY_MARKERS if m in text]
    assert not hits, "{} references answer-key field(s) {}".format(
        path.relative_to(cfg.ROOT), hits)


def test_solving_half_does_not_read_the_env_world_directly():
    """The agent sees the world only through collectors and the seven tool contracts.

    `env/` is the simulator. A solver that imported it could read cluster state or the IAM
    object graph directly and skip the retrieval problem entirely -- which would make every
    measured number meaningless. The Verifier is the one permitted exception (spec 5.7 runs
    real counterfactuals against a sandbox), and it is listed explicitly here.
    """
    allowed = {"agent/verifier.py", "collectors/iac_collector.py",
               "collectors/k8s_audit_collector.py", "collectors/cloudtrail_collector.py",
               "collectors/ownership.py", "collectors/git_collector.py",
               "collectors/run.py", "collectors/cluster_collector.py"}
    offenders = []
    for path in _all_solving_files():
        rel = path.relative_to(cfg.ROOT).as_posix()
        if rel in allowed:
            continue
        if "env" in _imported_modules(path):
            offenders.append(rel)
    assert not offenders, "{} import the simulator directly".format(offenders)


def test_the_deterministic_proposer_holds_no_incident_knowledge():
    """DECISIONS.md D-003: the offline proposer must be a real, generic proposer.

    If it knows the table names it is not a proposer, it is the answer key with extra steps,
    and every offline acceptance test becomes a tautology.
    """
    path = cfg.ROOT / "agent" / "proposer.py"
    if not path.exists():
        pytest.skip("proposer not built yet")
    text = path.read_text(encoding="utf-8").lower()
    banned = [
        "orders_table", "orders-prod", "orders-staging", "orders-api",
        "platform-config", "platform-iac", "analytics-etl", "dynamodb.tf",
        "orders.yaml", "silent_write_redirect",
    ]
    hits = [b for b in banned if b in text]
    assert not hits, "proposer.py contains incident-specific literals: {}".format(hits)


def test_the_gate_holds_no_incident_knowledge():
    path = cfg.ROOT / "agent" / "gate.py"
    if not path.exists():
        pytest.skip("gate not built yet")
    text = path.read_text(encoding="utf-8").lower()
    banned = ["orders", "platform-", "analytics", "dynamodb", "configmap"]
    hits = [b for b in banned if b in text]
    assert not hits, "gate.py contains incident-specific literals: {}".format(hits)


def test_the_rubric_is_committed_and_frozen():
    """Spec 10.1: the rubric is frozen and committed before the first run."""
    import subprocess

    r = subprocess.run(
        ["git", "-C", str(cfg.ROOT), "log", "--oneline", "--", "eval/rubric.yaml"],
        capture_output=True, text=True,
    )
    assert r.stdout.strip(), "eval/rubric.yaml is not committed to version control"
