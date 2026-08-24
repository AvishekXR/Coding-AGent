"""Causal brief builder (L1). Spec section 5.3. No LLM.

Converts raw telemetry into a compact causal brief *before any model sees it*. This is the
direct counter-measure to the documented context-exhaustion failure where agents read large
files into context until tokens run out, and it is why a multi-hour incident is affordable.

Four responsibilities from 5.3:
  * anomaly extraction against measured baselines;
  * log-pattern compression, target on the order of 1000:1;
  * first-mover ordering -- which entity deviated first, and in what propagation order;
  * topology-weighted candidate ranking (delegated to indexer/rank.py).

The brief is hard-capped at 30,000 tokens. That is a limit, not a target.

**Every detector here is generic.** None knows any table name, key name or service in advance.
They answer three structural questions that apply to any system:
  1. Did a measured series move relative to its own baseline?
  2. Did a series appear that has no baseline at all?
  3. Did an authorization decision start succeeding against a resource with no precedent?

Detector 3 is the one that matters most, and it is worth being explicit about why. Almost every
anomaly detector looks for something going *wrong* -- errors appearing, latency rising, a metric
falling. A guard rail that quietly stops firing produces no such signal: the absence of denials
looks exactly like healthy operation. Detecting it requires asking whether a *success* is
unprecedented, which is the only way an incident that is silent by construction can leave a
trace at all.
"""
from __future__ import annotations

import json
import re
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from pathlib import Path

import config as cfg
from indexer.severity import Anomaly, Severity
from util import approx_tokens, iso, parse_ts

#: Relative change in a metric's window mean vs its baseline mean before it counts.
DEVIATION_THRESHOLD = 0.25
#: Severity bands by absolute relative deviation.
SEVERITY_BANDS = ((0.90, Severity.critical), (0.50, Severity.high),
                  (0.25, Severity.medium), (0.0, Severity.low))

#: Log lines are collapsed to (template, count). A template keeps the message and the shape
#: of its fields, never the values -- values are what make log volume unbounded.
_NUM = re.compile(r"\d+")
_HEX = re.compile(r"\b[0-9a-f]{8,}\b", re.I)


@dataclass
class LogPattern:
    template: str
    count: int
    services: list[str]
    levels: list[str]
    first_seen: str
    last_seen: str
    baseline_count: int = 0

    @property
    def is_novel(self) -> bool:
        return self.baseline_count == 0

    def to_dict(self) -> dict:
        return {
            "template": self.template, "count": self.count,
            "services": self.services, "levels": self.levels,
            "first_seen": self.first_seen, "novel": self.is_novel,
            "baseline_count": self.baseline_count,
        }


@dataclass
class CausalBrief:
    """What the Proposer receives instead of telemetry. Spec 5.3."""

    incident_id: str
    window: tuple[str, str]
    first_symptom_ts: str
    alert: str
    anomalies: list[Anomaly] = field(default_factory=list)
    first_movers: list[dict] = field(default_factory=list)
    log_patterns: list[LogPattern] = field(default_factory=list)
    compression: dict = field(default_factory=dict)
    notes: list[str] = field(default_factory=list)

    def to_dict(self, max_patterns: int = 12) -> dict:
        return {
            "incident_id": self.incident_id,
            "window": list(self.window),
            "first_symptom_ts": self.first_symptom_ts,
            "alert": self.alert,
            "anomalies": [a.to_dict() for a in self.anomalies],
            "first_movers": self.first_movers,
            "log_patterns": [p.to_dict() for p in self.log_patterns[:max_patterns]],
            "compression": self.compression,
            "notes": self.notes,
        }

    def token_estimate(self) -> int:
        return approx_tokens(json.dumps(self.to_dict(), default=str))


# --- telemetry loading -------------------------------------------------------
def _read_jsonl(path: Path) -> list[dict]:
    if not path.exists():
        return []
    return [json.loads(l) for l in path.read_text(encoding="utf-8").splitlines() if l.strip()]


def _in_window(rows: list[dict], key: str, t0: datetime, t1: datetime) -> list[dict]:
    return [r for r in rows if t0 <= parse_ts(r[key]) <= t1]


def _template(msg: str, fields: dict) -> str:
    """Collapse one log line to a shape. Values are dropped; keys and types are kept."""
    base = _HEX.sub("<hex>", _NUM.sub("<n>", str(msg)))
    shape = ",".join(sorted(k for k in fields if k not in ("ts", "service", "level", "msg")))
    return "{} [{}]".format(base, shape)


# --- detectors ---------------------------------------------------------------
def _severity_for(rel: float) -> Severity:
    for bound, sev in SEVERITY_BANDS:
        if abs(rel) >= bound:
            return sev
    return Severity.info


#: Consecutive deviating samples required before a changepoint counts as an onset. Guards
#: against calling an anomaly on single-sample noise.
MIN_RUN = 3


def _series_by_key(rows: list[dict]) -> dict[tuple[str, str], list[dict]]:
    acc: dict[tuple[str, str], list[dict]] = defaultdict(list)
    for r in rows:
        acc[(r["entity"], r["metric"])].append(r)
    for v in acc.values():
        v.sort(key=lambda r: r["ts"])
    return acc


def detect_metric_deviations(window_rows: list[dict], baseline_rows: list[dict]) -> list[Anomaly]:
    """Question 1: did a measured series move relative to its own baseline?

    Measured **after the changepoint**, not across the whole window. This distinction is not
    cosmetic. A metric that is healthy for 95 minutes and then falls by 94% has a whole-window
    mean only 28% below baseline -- which would report the defining symptom of the incident as
    a medium-severity wobble and rank it *below* its own side effects. Since the Gate asks
    about the most severe unexplained anomaly first, diluting the real symptom sends the whole
    investigation at the wrong question. What matters is the magnitude of the step, and how
    much of the window it has held for.
    """
    win = _series_by_key(window_rows)
    base = _series_by_key(baseline_rows)
    out: list[Anomaly] = []

    for key in sorted(win):
        entity, metric = key
        if key not in base:
            continue  # handled by the novel-series detector
        series = win[key]
        b_vals = [float(r["value"]) for r in base[key]]
        b_mean = sum(b_vals) / len(b_vals)
        band = max(abs(b_mean) * DEVIATION_THRESHOLD, 1e-9)

        deviating = [abs(float(r["value"]) - b_mean) > band for r in series]
        onset_idx = _first_sustained_run(deviating, MIN_RUN)
        if onset_idx is None:
            continue

        after = [float(r["value"]) for r in series[onset_idx:]]
        a_mean = sum(after) / len(after)
        denom = abs(b_mean) if b_mean else abs(a_mean) or 1.0
        rel = (a_mean - b_mean) / denom
        if abs(rel) < DEVIATION_THRESHOLD:
            continue

        held = len(after) / len(series)
        out.append(Anomaly(
            id="A-dev-{}-{}".format(entity, metric).replace(".", "_"),
            entity=entity, kind="metric_deviation", first_seen=series[onset_idx]["ts"],
            magnitude="{:+.0%}".format(rel), severity=_severity_for(rel),
            evidence_ref="metric:{}:{}".format(entity, metric),
            detail=(
                "{} stepped {:+.0%} at {} and has held there for {:.0%} of the window "
                "({:.1f} -> {:.1f} against baseline)".format(
                    metric, rel, series[onset_idx]["ts"][11:16], held, b_mean, a_mean)
            ),
        ))
    return out


def _first_sustained_run(flags: list[bool], min_run: int) -> int | None:
    """Index where `min_run` consecutive True values begin, or None."""
    run = 0
    for i, f in enumerate(flags):
        if f:
            run += 1
            if run >= min_run:
                return i - run + 1
        else:
            run = 0
    return None


def detect_stopped_series(window_rows: list[dict], baseline_rows: list[dict]) -> list[Anomaly]:
    """A series that was reporting and stopped.

    A mean over the samples that *are* present cannot see this: writes to the old destination
    ran at exactly their normal rate right up to the moment they ceased. Only the sample count
    changes. This is the mirror image of `novel_metric_series` and, taken together, the pair
    describes a redirect rather than an outage.
    """
    win = _series_by_key(window_rows)
    base = _series_by_key(baseline_rows)
    out: list[Anomaly] = []

    for key in sorted(base):
        entity, metric = key
        expected = len(base[key])
        got = len(win.get(key, []))
        if expected < MIN_RUN or got == 0 or got >= expected * (1 - DEVIATION_THRESHOLD):
            continue
        last = win[key][-1]["ts"]
        out.append(Anomaly(
            id="A-stop-{}-{}".format(entity, metric).replace(".", "_"),
            entity=entity, kind="series_stopped_reporting", first_seen=last,
            magnitude="{}/{} samples".format(got, expected), severity=Severity.high,
            evidence_ref="metric:{}:{}".format(entity, metric),
            detail=(
                "{} reported normally until {} and then stopped, {} of an expected {} "
                "samples. The rate while present was unchanged, so this is a cessation "
                "rather than a degradation.".format(
                    metric, last[11:16], got, expected)
            ),
        ))
    return out


def detect_novel_series(window_rows: list[dict], baseline_rows: list[dict]) -> list[Anomaly]:
    """Question 2: did a series appear that has no baseline at all?

    A metric that simply did not exist yesterday is a structural change, not a fluctuation.
    """
    base_keys = {(r["entity"], r["metric"]) for r in baseline_rows}
    seen: dict[tuple[str, str], dict] = {}
    for r in window_rows:
        key = (r["entity"], r["metric"])
        if key in base_keys or float(r["value"]) == 0:
            continue
        if key not in seen or r["ts"] < seen[key]["ts"]:
            seen[key] = r

    out = []
    for (entity, metric), first in sorted(seen.items()):
        out.append(Anomaly(
            id="A-new-{}-{}".format(entity, metric).replace(".", "_"),
            entity=entity, kind="novel_metric_series", first_seen=first["ts"],
            magnitude="{:g}/min".format(float(first["value"])), severity=Severity.high,
            evidence_ref="metric:{}:{}".format(entity, metric),
            detail="{} has no baseline: this series did not exist before the window".format(
                metric),
        ))
    return out


def detect_authorization_gaps(window_rows: list[dict],
                              baseline_rows: list[dict]) -> list[Anomaly]:
    """Question 3: did an authorization decision start succeeding without precedent?

    The detector that can see a guard rail which stopped firing. See the module docstring for
    why this shape of question is necessary and why conventional detectors miss it.

    `detail` carries the resource and the policy clause that permitted the call, so the
    reverse index can be searched for whatever that clause names. That is the evidence chain
    from "this succeeded" to "someone widened a policy", and it is entirely generic.
    """
    baseline_pairs = {(r["principal"], r["resource"]) for r in baseline_rows}
    firsts: dict[tuple[str, str], dict] = {}
    for r in window_rows:
        if not r.get("allowed"):
            continue
        key = (r["principal"], r["resource"])
        if key in baseline_pairs:
            continue
        if key not in firsts or r["ts"] < firsts[key]["ts"]:
            firsts[key] = r

    out = []
    for (principal, resource), r in sorted(firsts.items()):
        out.append(Anomaly(
            id="A-authz-{}".format(_slug(resource)),
            entity=principal, kind="write_permitted_to_novel_resource",
            first_seen=r["ts"], magnitude="0 denials",
            severity=Severity.high,
            evidence_ref="authz:{}:{}".format(principal, resource),
            detail=(
                "{} was permitted to {} against {} with no baseline precedent and zero "
                "denials. The decision cites: {}. A write to a resource this principal had "
                "never touched succeeded rather than being refused -- so whatever previously "
                "constrained it no longer does.".format(
                    principal, r.get("action", "act"), resource, r.get("reason", "unknown"))
            ),
        ))
    return out


def _slug(s: str) -> str:
    return re.sub(r"[^A-Za-z0-9]+", "-", s).strip("-")[-40:]


# --- log compression ---------------------------------------------------------
def compress_logs(window_rows: list[dict], baseline_rows: list[dict]) -> tuple[list[LogPattern], dict]:
    """Collapse routine confirmations to (template, count); keep novel patterns at fidelity.

    Spec 5.3 cites the representative ratio: of 50,000 hourly lines, 49,950 match a known
    pattern and collapse; the 50 anomalous lines survive. Target on the order of 1000:1.
    """
    def group(rows):
        acc: dict[str, dict] = {}
        for r in rows:
            t = _template(r.get("msg", ""), r)
            e = acc.setdefault(t, {"count": 0, "services": set(), "levels": set(),
                                   "first": r["ts"], "last": r["ts"]})
            e["count"] += 1
            e["services"].add(r.get("service", "?"))
            e["levels"].add(r.get("level", "?"))
            e["first"] = min(e["first"], r["ts"])
            e["last"] = max(e["last"], r["ts"])
        return acc

    win = group(window_rows)
    base = group(baseline_rows)

    patterns = [
        LogPattern(
            template=t, count=e["count"], services=sorted(e["services"]),
            levels=sorted(e["levels"]), first_seen=e["first"], last_seen=e["last"],
            baseline_count=base.get(t, {}).get("count", 0),
        )
        for t, e in win.items()
    ]
    # Novel patterns first, then by volume: a new line type matters more than a loud one.
    patterns.sort(key=lambda p: (not p.is_novel, -p.count, p.template))

    lines_in = len(window_rows)
    ratio = (lines_in / len(patterns)) if patterns else 0.0
    return patterns, {
        "lines_in": lines_in,
        "patterns_out": len(patterns),
        "ratio": "{:.0f}:1".format(ratio) if ratio else "n/a",
        "novel_patterns": sum(1 for p in patterns if p.is_novel),
    }


# --- first-mover ordering ----------------------------------------------------
def first_movers(anomalies: list[Anomaly]) -> list[dict]:
    """Which entity deviated first, and in what propagation order. Spec 5.3."""
    ordered = sorted(anomalies, key=lambda a: (a.first_seen, a.id))
    out = []
    for i, a in enumerate(ordered):
        out.append({
            "order": i + 1, "entity": a.entity, "kind": a.kind,
            "first_seen": a.first_seen, "anomaly_id": a.id,
        })
    return out


# --- top level ---------------------------------------------------------------
def build(incident_meta: dict, state_dir: Path | None = None,
          baseline_day: str | None = None, config=None) -> CausalBrief:
    """Build the causal brief for an incident window. No LLM anywhere in this path."""
    config = config or cfg.DEFAULT
    state = Path(state_dir or cfg.STATE_DIR)
    tel = state / "telemetry"

    t0 = parse_ts(incident_meta["window_start_ts"])
    t1 = parse_ts(incident_meta["window_end_ts"])
    # The baseline is the same clock hours on the day before, so time-of-day effects cancel.
    if baseline_day is None:
        baseline_day = (t0 - timedelta(days=1)).strftime("%Y-%m-%d")
    b0 = parse_ts("{}T{}".format(baseline_day, t0.strftime("%H:%M:%S")))
    b1 = parse_ts("{}T{}".format(baseline_day, t1.strftime("%H:%M:%S")))

    metrics = _read_jsonl(tel / "metrics.jsonl")
    logs = _read_jsonl(tel / "logs.jsonl")
    authz = _read_jsonl(tel / "authz.jsonl")

    m_win, m_base = _in_window(metrics, "ts", t0, t1), _in_window(metrics, "ts", b0, b1)
    l_win, l_base = _in_window(logs, "ts", t0, t1), _in_window(logs, "ts", b0, b1)
    a_win, a_base = _in_window(authz, "ts", t0, t1), _in_window(authz, "ts", b0, b1)

    anomalies = (
        detect_metric_deviations(m_win, m_base)
        + detect_novel_series(m_win, m_base)
        + detect_stopped_series(m_win, m_base)
        + detect_authorization_gaps(a_win, a_base)
    )
    anomalies.sort(key=lambda a: a.sort_key)

    patterns, compression = compress_logs(l_win, l_base)

    brief = CausalBrief(
        incident_id=incident_meta["id"],
        window=(iso(t0), iso(t1)),
        first_symptom_ts=incident_meta["first_symptom_ts"],
        alert=incident_meta["alert"],
        anomalies=anomalies,
        first_movers=first_movers(anomalies),
        log_patterns=patterns,
        compression=compression,
        notes=[
            "baseline: {} {}-{} (same clock hours, previous day)".format(
                baseline_day, t0.strftime("%H:%M"), t1.strftime("%H:%M")),
            "no raw log content appears in this brief; log lines are collapsed to templates",
        ],
    )

    # Hard cap (5.3). Trim the least informative material first -- log patterns are ordered
    # novel-first, so trimming from the tail drops routine volume before it drops signal.
    while brief.token_estimate() > config.max_brief_tokens and brief.log_patterns:
        brief.log_patterns.pop()
        brief.notes.append("log patterns trimmed to respect the 30,000-token brief cap")
    return brief
