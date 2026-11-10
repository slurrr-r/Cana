"""
config.py
=========

Centralized configuration for Module 4 (Context-Aware Anomaly
Detection).
"""

from __future__ import annotations

import os
import sys
from pathlib import Path
from typing import Final

# --------------------------------------------------------------------------- #
# Filesystem locations
# --------------------------------------------------------------------------- #

BASE_DIR: Final[Path] = Path(__file__).resolve().parent.parent


def _runtime_logs_dir() -> Path:
    installed = bool(getattr(sys, "frozen", False)) and not (
        os.environ.get("CANA_DEV") == "1" or os.environ.get("CANA_TEST") == "1"
    )
    if os.name == "nt" and installed:
        programdata = os.environ.get("PROGRAMDATA")
        if programdata:
            return Path(programdata) / "CANA" / "logs"
    return BASE_DIR / "logs"


LOGS_DIR: Final[Path] = _runtime_logs_dir()

# Persistent state (learned baseline + triggered alert history) lives in
# its own directory, separate from logs/ (human-readable diagnostics) and
# sessions/ (per-run snapshots). This is the only data in the project that
# is deliberately meant to OUTLIVE a single run - see store.py.
DATA_DIR: Final[Path] = BASE_DIR / "data"


def ensure_runtime_directories() -> None:
    """Ensure directories this module writes to at runtime exist."""
    for directory in (LOGS_DIR, DATA_DIR):
        directory.mkdir(parents=True, exist_ok=True)


# --------------------------------------------------------------------------- #
# Logging configuration
# --------------------------------------------------------------------------- #

LOG_FILE_NAME: Final[str] = "anomaly_detection.log"
LOG_FORMAT: Final[str] = (
    "%(asctime)s | %(levelname)-8s | %(name)s | %(message)s"
)
LOG_DATE_FORMAT: Final[str] = "%Y-%m-%d %H:%M:%S"
LOG_MAX_BYTES: Final[int] = 5 * 1024 * 1024
LOG_BACKUP_COUNT: Final[int] = 3

# --------------------------------------------------------------------------- #
# Baseline configuration
# --------------------------------------------------------------------------- #

# Baseline statistics are bucketed by hour-of-day (0-23), since normal
# behavior (e.g. "streaming video most evenings") is often time-of-day
# dependent, not just a single global average.
BASELINE_HOUR_BUCKETS: Final[int] = 24

# Minimum number of observations a bucket needs before its baseline is
# considered "established" enough to judge new data against. Below
# this, a bucket is still in its cold-start phase (see project
# discussion: this is a real, documented limitation, not silently
# hidden).
MIN_OBSERVATIONS_FOR_BASELINE: Final[int] = 5

# A value is flagged as anomalous if it exceeds
# (mean + ANOMALY_STD_DEV_MULTIPLIER * std_dev) for its bucket - a
# standard z-score-style outlier check.
ANOMALY_STD_DEV_MULTIPLIER: Final[float] = 3.0

# --------------------------------------------------------------------------- #
# Rule configuration
# --------------------------------------------------------------------------- #

# Rules that don't depend on a learned baseline (e.g. "unknown app
# talking to the internet") can still use a fixed sanity threshold.
# This is intentionally a fallback for when baseline data doesn't
# exist yet (cold start) - see BaselineTracker.is_established().
#
# The value is deliberately a "clearly absurd single idle window"
# level, NOT a tight cap. Two properties follow:
#
#   1. Legitimate-but-large idle transfers (an evening of streaming,
#      a big download finishing while the user steps away - routinely
#      hundreds of MB to a few GB) must NOT be flagged during cold
#      start. A flagged session is, by design (see orchestrator.py's
#      anti-leakage policy), never learned as normal - so a fallback
#      that fires on ordinary large sessions would PERMANENTLY prevent
#      the baseline from ever learning that those volumes are normal
#      for this user, flagging them forever.
#   2. The fallback only has to catch the clearly absurd (a runaway
#      multi-GB idle exfiltration) while the model is still warming.
#      Once ~5 sessions complete, the learned baseline is the real
#      detector and judges "large for THIS user", not "large" globally.
FALLBACK_LARGE_TRANSFER_BYTES: Final[int] = 4 * 1024 * 1024 * 1024  # 4 GiB

# --------------------------------------------------------------------------- #
# Connection-rate configuration
# --------------------------------------------------------------------------- #

# Sliding window used to measure packets-per-second for a given
# (application, destination) pair.
RATE_TRACKER_WINDOW_SECONDS: Final[float] = 5.0

# Connection rate is a noisier, burstier signal than packet size or
# idle-transfer volume (a page load causes a brief spike, then goes
# quiet) - the global MIN_OBSERVATIONS_FOR_BASELINE (5) was too low to
# produce a trustworthy variance estimate for it, causing ordinary
# jitter to be flagged as anomalous. This higher, rate-specific
# minimum applies only to the connection-rate rule.
#
# There is deliberately NO fixed fallback threshold for this rule (no
# FALLBACK_MAX_PACKETS_PER_SECOND) - a single global "N pkt/s is
# suspicious for everyone" number has exactly the same flaw as pooling
# all apps into one baseline: a background service and an actively
# browsed tab don't share a meaningful "normal" rate. The rule simply
# skips (with an explicit reason) until real, per-application data
# exists - see rules.py's connection_rate_anomaly_rule.
MIN_RATE_SAMPLES_FOR_BASELINE: Final[int] = 30

# Cap distinct (application, destination) keys so a long capture cannot
# grow the in-memory rate tables without bound.
RATE_TRACKER_MAX_KEYS: Final[int] = 10_000

# --------------------------------------------------------------------------- #
# Persistence configuration
# --------------------------------------------------------------------------- #

# Single SQLite database holding both the learned baseline and the
# triggered-alert history. SQLite (rather than a JSON dump) because:
#   * writes are transactional, so a Ctrl+C landing mid-save can't leave
#     a half-written baseline behind;
#   * WAL mode lets the native UI read the data WHILE a capture is
#     running and writing to it;
#   * the baseline is naturally relational (metric x hour-of-day), so
#     UPSERT-by-primary-key expresses "replace this bucket's state"
#     directly.
BASELINE_DB_NAME: Final[str] = "baseline.db"
BASELINE_DB_PATH: Final[Path] = DATA_DIR / BASELINE_DB_NAME

# Bumped whenever the on-disk schema changes incompatibly. A database
# written by a different version is ignored (cold start) rather than
# misread - see store.BaselineStore._check_schema_version.
#
# Bumped 1 -> 2 for the P2 connection-rate metric-identity fix: the
# ``connection_rate:<application_name>`` baseline key became
# ``connection_rate:<application_name>:<peer>`` (see rules.py). A
# version-1 database's connection-rate rows are keyed under the old,
# less specific identity and are not meaningfully comparable to the
# new one - the existing cold-start-on-mismatch behavior below is what
# safely handles that rather than silently mixing old- and new-format
# rows under the new code.
BASELINE_SCHEMA_VERSION: Final[int] = 2

# How often the in-memory baseline is checkpointed to disk during a
# capture run.
#
# The two obvious alternatives are both worse: saving on every packet
# would put a synchronous disk write in the capture hot path (thousands
# per second during a download), and saving ONLY at shutdown would lose
# an entire session's learning to a hard kill or power loss - which
# matters here precisely because the whole point of persistence is that
# learning accumulates over many runs. A periodic checkpoint bounds
# worst-case loss to this interval while keeping the packet path free of
# disk I/O. A clean exit always performs one final save on top of this,
# so the interval only ever costs anything on an unclean kill.
BASELINE_CHECKPOINT_INTERVAL_SECONDS: Final[float] = 30.0

# Default number of rows returned by BaselineStore.recent_alerts().
RECENT_ALERTS_DEFAULT_LIMIT: Final[int] = 20
