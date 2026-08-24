"""Render repository content into live world state.

This closes the loop that makes the incident real rather than staged: the IAM policy the
simulator enforces is *parsed out of the Terraform file in platform-iac*, and the pod
environment is *parsed out of the YAML in platform-config*. Edit the repo, re-render, and the
running world changes accordingly -- exactly as a terraform apply and a config sync would.
"""
from __future__ import annotations

import re
from pathlib import Path

import yaml

from .iam import IAM, Policy, Statement

#: Which principal each Terraform policy document is attached to in environments/prod.
POLICY_PRINCIPAL = {
    "orders_dynamodb": "orders-api",
    "analytics_dynamodb": "analytics-etl",
    "reports_s3": "reporting-api",
    "batch_importer_dynamodb": "orders-batch-importer",
}

_DOC_RE = re.compile(r'data\s+"aws_iam_policy_document"\s+"(?P<name>[\w-]+)"\s*\{')
_STMT_RE = re.compile(r"\bstatement\s*\{")
_SCALAR_RE = re.compile(r'(?P<key>sid|effect)\s*=\s*"(?P<val>[^"]*)"')
_LIST_RE = re.compile(r"(?P<key>actions|resources)\s*=\s*\[(?P<body>[^\]]*)\]", re.S)


def _block_at(text: str, open_brace_idx: int) -> str:
    """Return the body of the brace-delimited block whose `{` is at open_brace_idx."""
    depth = 0
    for i in range(open_brace_idx, len(text)):
        if text[i] == "{":
            depth += 1
        elif text[i] == "}":
            depth -= 1
            if depth == 0:
                return text[open_brace_idx + 1 : i]
    raise ValueError(f"unbalanced braces starting at offset {open_brace_idx}")


def parse_iam_terraform(tf_text: str) -> dict[str, Policy]:
    """Parse `aws_iam_policy_document` blocks into Policy objects, keyed by document name."""
    out: dict[str, Policy] = {}
    for m in _DOC_RE.finditer(tf_text):
        body = _block_at(tf_text, m.end() - 1)
        statements = []
        for sm in _STMT_RE.finditer(body):
            sbody = _block_at(body, sm.end() - 1)
            scalars = {k.group("key"): k.group("val") for k in _SCALAR_RE.finditer(sbody)}
            lists = {
                lm.group("key"): re.findall(r'"([^"]+)"', lm.group("body"))
                for lm in _LIST_RE.finditer(sbody)
            }
            statements.append(
                Statement(
                    effect=scalars.get("effect", "Allow"),
                    actions=tuple(lists.get("actions", ())),
                    resources=tuple(lists.get("resources", ())),
                    sid=scalars.get("sid", ""),
                )
            )
        out[m.group("name")] = Policy(name=m.group("name"), statements=tuple(statements))
    return out


def apply_iac(repo_dir: Path, iam: IAM) -> list[str]:
    """Simulated `terraform apply`: render every IAM policy document onto its principal.

    Returns the list of principals whose effective policy was (re)written.
    """
    touched = []
    for tf in sorted((Path(repo_dir) / "modules" / "iam").glob("*.tf")):
        for doc_name, policy in parse_iam_terraform(tf.read_text(encoding="utf-8")).items():
            principal = POLICY_PRINCIPAL.get(doc_name)
            if principal is None:
                continue  # a policy document not attached to any principal in prod
            iam.put_policy(principal, policy)
            touched.append(principal)
    return touched


def parse_configmaps(repo_dir: Path, overlay: str = "prod") -> list[dict]:
    """Parse every ConfigMap manifest in one overlay directory."""
    out = []
    d = Path(repo_dir) / "overlays" / overlay
    for path in sorted(d.glob("*.yaml")):
        doc = yaml.safe_load(path.read_text(encoding="utf-8"))
        if doc and doc.get("kind") == "ConfigMap":
            out.append(doc)
    return out
