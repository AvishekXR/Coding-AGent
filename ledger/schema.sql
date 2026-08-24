-- Change ledger and derived indexes. Spec section 6.
--
-- SQLite for phases 0-4. Do not introduce a graph database or vector store until a named
-- acceptance test fails without one (spec 12).

PRAGMA journal_mode = WAL;
PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS changes (
  id          TEXT PRIMARY KEY,     -- stable; used as Claim.cause_ids
  ts          TIMESTAMP NOT NULL,
  source      TEXT NOT NULL,        -- git|iac|k8s|cloudtrail|flag|package|external
  author      TEXT,
  team        TEXT,
  repo        TEXT,
  path        TEXT,
  summary     TEXT,
  diff_ref    TEXT,
  evidenced   INTEGER DEFAULT 1,    -- external rows: 0 until corroborated
  raw         TEXT,                 -- JSON blob of the source record
  -- Added beyond spec 6 to satisfy the freshness requirement in 5.1.2 and Appendix E:
  -- "freshness stamps exist on ledger and index rows".
  collected_at TIMESTAMP
);
CREATE INDEX IF NOT EXISTS idx_changes_ts   ON changes(ts);
CREATE INDEX IF NOT EXISTS idx_changes_path ON changes(repo, path);
CREATE INDEX IF NOT EXISTS idx_changes_team ON changes(team, ts);

CREATE TABLE IF NOT EXISTS mentions (
  literal    TEXT NOT NULL,
  repo       TEXT NOT NULL,
  path       TEXT NOT NULL,
  line       INTEGER,
  snippet    TEXT,
  kind       TEXT,                  -- code|config|iac|docs
  indexed_at TIMESTAMP
);
CREATE INDEX IF NOT EXISTS idx_mentions_literal ON mentions(literal);
-- Dedupe guard: the sweep is re-runnable and must be idempotent.
CREATE UNIQUE INDEX IF NOT EXISTS idx_mentions_unique
  ON mentions(literal, repo, path, line);

CREATE TABLE IF NOT EXISTS ownership (
  pattern    TEXT PRIMARY KEY,      -- repo name or glob
  team       TEXT,
  oncall     TEXT,
  slack      TEXT,
  escalation TEXT
);

CREATE TABLE IF NOT EXISTS incidents (
  id               TEXT PRIMARY KEY,
  opened_at        TIMESTAMP,
  first_symptom_ts TIMESTAMP,
  window_start     TIMESTAMP,
  window_end       TIMESTAMP,
  alert            TEXT,
  status           TEXT              -- open|resolved|unresolved
);

CREATE TABLE IF NOT EXISTS runs (    -- one row per evaluation run
  id                TEXT PRIMARY KEY,
  incident_id       TEXT,
  started_at        TIMESTAMP,
  steps             INTEGER,
  tokens            INTEGER,
  cost_usd          REAL,
  wall_seconds      REAL,
  terminated_as     TEXT,            -- accepted|unresolved|budget|error
  cause_ids         TEXT,            -- JSON array as claimed
  verification_tier TEXT,
  confidence        REAL,
  score             REAL,
  depth_compliant   INTEGER,
  notes             TEXT
);

-- Not optional. The sequence of rejections is the primary debugging artifact for this
-- system: it shows exactly where the investigation was pushed deeper and why (spec 6).
CREATE TABLE IF NOT EXISTS gate_events (
  run_id        TEXT,
  step          INTEGER,
  accepted      INTEGER,
  reason        TEXT,
  next_question TEXT,
  claim         TEXT,
  rule          TEXT                 -- which rule fired: T1|T2|timing
);
CREATE INDEX IF NOT EXISTS idx_gate_events_run ON gate_events(run_id, step);

-- Every tool call, with incident id, timestamp and identity. Spec 5.9.1.
CREATE TABLE IF NOT EXISTS audit_log (
  id         INTEGER PRIMARY KEY AUTOINCREMENT,
  run_id     TEXT,
  incident_id TEXT,
  ts         TIMESTAMP,
  identity   TEXT,
  tool       TEXT,
  args       TEXT,
  outcome    TEXT,                   -- ok|error|denied
  tokens     INTEGER
);
CREATE INDEX IF NOT EXISTS idx_audit_run ON audit_log(run_id, ts);
