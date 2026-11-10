# Context-Aware Network Behavior Analyzer

**Current detection scope:** three security alert rules are enabled: outbound
TCP port probes, inbound TCP port probes, and unusual TCP flags. Ten other
checks are diagnostic only and cannot add security alerts, risk scores or
correlated notifications. Packet-replay evidence and limits are recorded below.

## Install from source

On Windows, create a virtual environment and install the source package:

```powershell
python -m venv .venv
.venv\Scripts\python -m pip install -e ".[windows,ui,dev]"
.venv\Scripts\python -m pytest -q
.venv\Scripts\python main.py --help
```

Live capture needs Npcap and appropriate Windows permissions. The UI connects
to an installed CANA service; opening it alone does not start capture.
See [Windows service setup](PRODUCTIZATION.md) for installation and builds.

## Repository contents

Source, tests, build scripts and [saved validation reports](docs/validation/)
are included. Runtime databases, logs, session history, downloaded captures,
personal output files, virtual environments, installer binaries and third-party
build tools are excluded by `.gitignore`. Keep these exclusions when uploading.
Replay scripts in `tools/` require the separately downloaded samples described
below; the ordinary test suite does not require those downloads.

No project license is currently specified. External datasets and dependencies
retain their own terms. This is a research and portfolio project with bounded
test evidence, not a production-certified intrusion detection system.

## Module 1 — Network Traffic Collection & Packet Processing

The packet capture module collects and parses network traffic. CANA adds
process attribution, diagnostic baselines, three security alert rules,
SQLite history, a Windows service and a native UI.

---

## What This Module Does

- Detects available network interfaces and lets you select one.
- Lets you choose a packet filter (All / TCP / UDP / ICMP / DNS / HTTP / HTTPS).
- Captures live packets continuously using Scapy, on a background thread.
- Parses Ethernet, IP (v4/v6), TCP, UDP, and DNS headers into a structured dictionary.
- Validates packets, silently dropping corrupted/empty/unsupported ones without crashing.
- Classifies packets by protocol, direction (incoming/outgoing), and
  communication type (local network / internet / broadcast / multicast).
- Maintains live statistics (packet counts, protocol breakdown, average/min/max size, packets-per-second).
- Tracks and saves full session data (interface used, filter applied, duration, action log, and every captured packet) as a single JSON file.
- Logs all module activity to a rotating log file, separate from packet data.
- Prints clean, real-time packet summaries to the console.

### Module 2 — Application/Process Mapping (`app_mapper.py`)

Given the packet list Module 1 produces, Module 2 identifies which
running application generated each packet:

- Snapshots the OS-level connection table (`psutil.net_connections`).
- Matches each packet's local IP:port against that table (using the
  packet's `direction` field to know which side is "local").
- Resolves the owning PID to a process name and executable path.
- Enriches each packet with `application_name`, `process_id`, and
  `executable_path` (or `UNKNOWN`/`None` if no match was found).

```python
from packet_capture.capture import start_packet_capture
from packet_capture.app_mapper import map_packets_to_applications

packets = start_packet_capture(settings)
enriched_packets = map_packets_to_applications(packets)
# Each dict now also has: application_name, process_id, executable_path
```

**Known limitation (by nature of this approach, not a bug):**
`psutil.net_connections()` is a snapshot — short-lived connections
(a quick DNS lookup, a fast HTTP request) may already be closed by the
time this module checks, so some packets will legitimately map to
`UNKNOWN`. This is a documented, inherent tradeoff of connection-table
correlation, not something a later pass can eliminate entirely.
Elevated (Administrator) privileges also improve match accuracy, since
listing other processes' connections in full is otherwise restricted.

### Module 4 — Anomaly Detection & Baseline Persistence (`anomaly_detection/`)

Module 4 combines each packet with its owning application (Module 2) and
the user's activity state (Module 3) into a single `ContextRecord`, then
evaluates three enabled alert rules and ten diagnostic-only checks. Every check returns a
human-readable `reason` string, so an alert always says *why* it fired,
not merely *that* it did.

Two checks — `packet_size_anomaly` and `connection_rate_anomaly`
— judge traffic against a **learned baseline** rather than a fixed
threshold: "is this unusual for THIS machine at THIS hour of day?"

#### Baseline Persistence

`BaselineTracker` keeps one statistics bucket per hour-of-day (0–23) per
metric. Those buckets are persisted to SQLite at `data/baseline.db`, so
the baseline **accumulates across runs**.

`packet_size_anomaly` needs 5 observations and
`connection_rate_anomaly` needs 30 *per application, per hour bucket*
before it will judge anything — so within a single short run, both spend
their whole life reporting "baseline not yet established". Across runs,
they start producing baseline comparisons. Packet size is diagnostic only:
it does not create security alerts, correlation signals, or risk increments.
Its statistics learn all sizes so ordinary traffic changes do not freeze learning.

**Why persisting it is cheap.** `HourBucket` uses Welford's online
algorithm, so a bucket's entire state is three numbers — `count`,
`mean`, and `m2` — and those three are mathematically sufficient to
*resume* the observation stream: reloading them and continuing to call
`update()` yields exactly the same mean and standard deviation as a
process that never stopped. Persisting a baseline therefore costs
O(metrics × 24) rows rather than O(observations), and **no raw
observation history is ever stored**. `tests/test_store.py` asserts that
resumption is lossless against an uninterrupted run.

Triggered alerts are persisted to the same database with the full
`reason` string and complete context (application, IPs, protocol, user
status, idle time, hour of day). They are written on a rule's *rising
edge* only — once when a condition starts, not once per packet while it
persists — which is what keeps a synchronous write out of the capture
hot path.

| Table | Contents |
|---|---|
| `baseline_buckets` | One row per (metric, hour-of-day): `observation_count`, `mean`, `m2` |
| `triggered_alerts` | One row per alert: rule, severity, reason, full context, session ID |
| `schema_meta` | Schema version, so a future format change starts cold rather than misreading old data |

The in-memory baseline is checkpointed every 30 seconds by a background
thread, plus once more on shutdown. Saving per packet would put a disk
write in the capture path; saving only at exit would hand an entire
session's learning to whatever kills the process first. The database is
opened in WAL mode, so a reader (e.g. the native UI) can query
it while a capture is still writing.

**Persistence is best-effort and never fatal.** A corrupt, locked, or
unwritable database is logged once and the run continues with an
in-memory-only baseline. Losing learned history is a real cost, but a
strictly smaller one than killing a live capture over it.

Inspect the database directly at any time:

```bash
python -c "import sqlite3;c=sqlite3.connect('data/baseline.db');print(c.execute('SELECT metric_name,hour_of_day,observation_count,mean FROM baseline_buckets ORDER BY observation_count DESC LIMIT 10').fetchall())"
```

### Module 5 — Correlation, Risk Scoring & Alerting (`risk_scoring/`)

Module 5 turns Module 4's individual rule firings into a *risk picture*:

- **Time-decayed risk scores.** Every triggered alert adds weighted
  severity (LOW=1, MEDIUM=2, HIGH=4) to its application and destination.
  Scores decay exponentially with a 300-second half-life, so recent
  trouble dominates over old trouble. A live `RiskScorer` ranks
  applications/destinations via `leaderboard()` / `snapshot()`.
- **Correlation.** `AlertCorrelator` groups distinct rule signals for
  the same (application, destination) within a 60-second window into a
  single *correlated incident*, with a confidence score. Two or more
  distinct rules qualify; a lone HIGH also qualifies on its own.
- **Persistence.** Risk scores and correlated incidents are stored in
  the SAME `data/baseline.db` (new tables only, WAL mode), so they
  accumulate across runs. A `RiskCheckpointer` saves a periodic snapshot,
  mirroring the baseline checkpointer.
- **Alerting.** `AlertNotifier` fans a correlated incident out to
  channels. `DesktopNotifier` sends a best-effort desktop notification
  via the **optional** `plyer` package — enable with `--notify`. Without
  plyer everything still works; it just degrades to console + database.

Only the rising edge of a rule feeds the scorer/correlator (the same
de-dup that keeps console alerts to one per condition), so Module 5 adds
no per-packet cost to the capture path.

### Module 6 — Native Status/Control UI (`cana_ui/`)

The production UI is a small native Status/Control window plus system
tray. It talks only to the Windows service over `\\.\pipe\CANAControl`.
Closing the window does not stop monitoring. Settings open in a
separate small window. There is no web dashboard.

### What This Module Deliberately Does NOT Do

Per project scope, Module 1 does **not** implement:

- Machine learning or anomaly detection (Isolation Forest, etc.)
- Application/process identification (`psutil`)
- User activity / idle detection
- A dashboard or Streamlit UI
- A database (SQLite)
- Alert generation or risk scoring
- **Packet export to CSV/JSON** — this was explicitly removed from
  scope. The module's only data-handoff contract is the in-memory
  list returned by `start_packet_capture()`.

These are **Module 1's** boundaries, not the project's. Several of them
are now implemented by later modules in their own packages, with no
dependency added back into `packet_capture/`: application/process
identification in `packet_capture/app_mapper.py` (Module 2), user
activity/idle detection in `user_activity/` (Module 3), rule-based
anomaly detection plus the SQLite database in `anomaly_detection/`
(Module 4), risk scoring/correlation/alerting in `risk_scoring/`
(Module 5), and the native UI in `cana_ui/` (Module 6). Machine
learning remains deliberately out of scope: the project's rules are
explainable, and no ML phase was added without a justification.

---

## Project Structure

```
ContextAwareNetworkAnalyzer/
├── packet_capture/
│   ├── __init__.py
│   ├── capture.py       # Threaded capture engine + start_packet_capture() public API
│   ├── parser.py         # Raw Scapy packet -> structured dict
│   ├── validator.py      # Rejects corrupted/empty/unsupported packets
│   ├── classifier.py     # Protocol / direction / communication-type classification
│   ├── app_mapper.py      # Module 2: maps packets to owning application/process
│   ├── statistics.py     # Live running statistics (thread-safe)
│   ├── logger.py         # Centralized rotating-file + console logging
│   ├── session.py        # Capture session record: metadata + action log + full packet data (JSON)
│   ├── interface.py      # Network interface detection & selection
│   ├── config.py         # Centralized configuration constants
│   └── utils.py          # Console formatting helpers
├── user_activity/         # Module 3: keyboard/mouse idle detection
├── anomaly_detection/     # Module 4: context records, rules, baseline, persistence
│   ├── context.py         # ContextRecord: packet + application + user activity
│   ├── baseline.py        # Hour-of-day bucketed learned baseline (Welford)
│   ├── rules.py           # The four explainable rules
│   ├── orchestrator.py    # Runs all rules over one ContextRecord
│   ├── store.py           # SQLite persistence: baseline + triggered alerts
│   ├── checkpointer.py    # Periodic background baseline saves
│   ├── aggregator.py      # Cumulative idle-transfer totals per application
│   └── rate_tracker.py    # Connection-rate windows per application
├── risk_scoring/          # Module 5: correlation, risk scoring, alerting
│   ├── scorer.py          # Time-decayed per-app/destination risk scores
│   ├── correlator.py      # Collapses distinct signals into incidents
│   ├── store.py           # Risk scores + correlated alerts in the same DB
│   ├── checkpointer.py    # Periodic risk snapshot saves
│   ├── notifier.py        # Desktop notification channel (optional plyer)
│   ├── utils.py           # Console formatting for risk output
│   └── config.py          # Risk/correlation tunables
├── cana_engine/           # Shared start/stop/status engine + named-pipe payloads
├── cana_service/          # Windows service runtime, sc.exe install/uninstall
├── cana_ui/               # Native window + tray; does not own packet capture
├── packaging/             # PyInstaller spec, Inno Setup, install/uninstall scripts
├── logs/                  # Rotating log files (created at runtime)
├── sessions/              # Full session JSON files: metadata + actions + packets (created at runtime)
├── data/                  # Persistent SQLite database: learned baseline + alert history (created at runtime)
├── tests/                 # Unit + integration tests (pytest)
├── requirements.txt
├── requirements-dev.txt
├── pyproject.toml
├── README.md
└── main.py                # Application entry point
```

---

## Requirements

- **OS:** Windows 11 (primary target). Also runs on Linux for
  development/testing (see "Testing" section below).
- **Python:** 3.10 or newer (package requirement); local tests run on 3.14.
- **Packet driver:** [Npcap](https://npcap.com/) installed in WinPcap-compatible mode (Windows only).
- **Privileges:** Must be run as **Administrator** on Windows (raw
  packet capture requires elevated privileges).
- **Optional:** `plyer` for desktop notifications (`pip install -r requirements.txt plyer`),
  and `evdev` on Linux for keyboard/mouse idle detection.

Install dependencies:

```bash
pip install -r requirements.txt
```

For tests, also install:

```bash
pip install -r requirements-dev.txt
```

---

## Windows Service (product mode)

CANA is a background Windows security app. Packet capture belongs to
`CANAEngine`, not the UI. Closing the native window or tray does
**not** stop monitoring.

| Piece | Role |
|---|---|
| `cana_engine` | `start()` / `stop()` / `status()` / health / watchdog |
| `cana_service` | Windows service wrapper (`CANA` / CANA Network Monitor) |
| `cana_ui` | Native window + tray; talks to `\\.\pipe\CANAControl` |
| `python main.py` | Developer/debug launcher over the same engine |

```bash
# Developer CLI (prompts for interface/filter, then starts CANAEngine)
python main.py
python main.py --debug
python main.py --service
python main.py --ui
```

```powershell
# Build the Windows installer (Python and Inno Setup required)
powershell -File packaging/build_windows.ps1 -Python python -ISCC "C:\Program Files (x86)\Inno Setup 6\ISCC.exe"

# Install the packaged app; approve the Windows administrator prompt
.\packaging\output\CANA-Setup.exe

# Open the UI without owning capture
cana-ui
python main.py --ui
```

The installer (`packaging/CANA.iss` / `packaging/build_windows.ps1`)
registers the service with Automatic startup and failure recovery
(`restart` after 15s, three times, reset 86400s). Data lives under
`%ProgramData%\CANA` and is preserved on uninstall unless you confirm
deletion. Uninstall from Apps & Features, Start Menu, or
`packaging/uninstall.ps1`.

Open CANA from the Start menu after setup. The UI runs without administrator
rights; only service installation or starting a stopped service needs elevation.
Do not copy `CANA.exe` alone: the packaged `_internal` folder is required.
If setup fails, check `%ProgramData%\CANA\logs\install.log`.
UI logs are in `%LOCALAPPDATA%\CANA\logs`.
The packaged UI can repair a missing service through **Install service**;
the source-code UI instead directs you to the installer.

Run unit tests with the installed CANA service stopped, then run the live
Windows acceptance tests separately with the service running. Both the tests
and production engine use the same Windows capture lock and control pipe.

The service runs as LocalSystem so Npcap capture and
`%ProgramData%\CANA` writes work without an interactive logon. That
account is highly privileged; mitigate with a named-pipe control plane
whose DACL allows SYSTEM, Administrators, and the installing user SID.
Administrators are authorized by group membership, not by comparing
TokenUser to `S-1-5-32-544`. The production UI is native Tk + tray.

Privileged start/stop/config and UI status use `\\.\pipe\CANAControl`.
If Npcap is missing,
the service stays running and the UI shows "Capture unavailable".
The installer records the logged-on user SID to
`%ProgramData%\CANA\installer-user.sid`. On Windows, after
install, run `powershell -File packaging/windows_acceptance.ps1`.
The production UI is a native window (`cana-ui` / `python main.py --ui`).
Closing it does not stop the Windows service.

## Running the Application (developer CLI)

```bash
python main.py
```

You will be prompted to:
1. Select a network interface from the detected list.
2. Select a packet filter (All, TCP, UDP, ICMP, DNS, HTTP, or HTTPS).

Capture then begins immediately and runs until you press **Ctrl+C**,
at which point it shuts down safely, prints a final summary, and saves
session metadata under `sessions/`.

At startup it reports how much baseline it restored from previous runs:

```
Baseline: restored 3 metric(s), 47 established hour-bucket(s), 12,431 observation(s) from C:\...\data\baseline.db
Alert history: 18 alert(s) from previous sessions.
```

or, on a fresh install:

```
Baseline: no prior data - starting cold. Rules that need a baseline will report 'not enough data yet' until enough observations accumulate; run this a few times to build one up.
```

The `established hour-bucket(s)` figure is the one that matters: an
un-established bucket cannot fire a rule, so that number is how many
(metric, hour-of-day) pairs the detector can actually judge right now.

### Options

| Flag | Effect |
|---|---|
| `--reset-baseline` | Discard the baseline learned by previous runs before starting. Alert history is preserved. Useful for demonstrating cold-start vs. learned behavior back to back, or after a period of atypical traffic has polluted what the tool considers "normal". |
| `--no-persist` | Run entirely in memory: no baseline is loaded or saved, and no alerts/risk data are recorded. For experiments that shouldn't affect learned state. |
| `--db PATH` | Use an alternative database file instead of `data/baseline.db`. |
| `--notify` | Send best-effort desktop notifications for correlated incidents (requires the optional `plyer` package). Console + database alerts always happen regardless. |
| `--risk-half-life SECONDS` | Half-life of risk scores (default 300) — how quickly recent alerts dominate over old ones. |
| `--correlation-window SECONDS` | Window in which distinct signals for the same app/destination are combined into one incident (default 60). |
| `--debug` | Developer debug mode: verbose logging, same CANA engine. |
| `--service` | Run the CANA engine as a foreground service (no interactive prompts). |
| `--ui` | Open the native CANA window only; monitoring stays in the background service. |

```bash
python main.py --reset-baseline
python main.py --notify
```

---

## Public API

Module 1 exposes exactly one public contract for downstream modules:

```python
from packet_capture.capture import start_packet_capture
from packet_capture.config import CaptureSettings

settings = CaptureSettings(
    interface_name="eth0",        # OS/Scapy-level interface identifier
    display_name="Ethernet",      # human-friendly name
    packet_filter="ALL",          # ALL / TCP / UDP / ICMP / DNS / HTTP / HTTPS
)

packets = start_packet_capture(settings, local_ip="192.168.1.5")
# packets: List[Dict[str, Any]] — ready to be passed to Module 2.
```

Each dictionary in `packets` has a stable schema (keys always present,
`None` for fields that don't apply to a given packet), including:
`timestamp`, `source_mac`, `destination_mac`, `source_ip`,
`destination_ip`, `ip_version`, `protocol`, `application_protocol`,
`source_port`, `destination_port`, `ttl`, `tcp_flags`,
`sequence_number`, `ack_number`, `window_size`, `packet_size`,
`packet_length`, `direction`, `communication_type`, `dns_query_name`.

---

## Design Notes & Known Tradeoffs

- **Threading model:** Scapy's `sniff()` is blocking, so it runs on a
  dedicated background thread, feeding a bounded `queue.Queue` that the
  main flow drains and processes. A `threading.Event` provides
  cooperative shutdown. The capture loop polls
  `sniff(..., timeout=SNIFF_POLL_TIMEOUT_SECONDS)` so stop does not
  wait for a packet on a silent interface.
- **HTTP/HTTPS classification is heuristic:** Scapy has no reliable
  native HTTP parsing layer, and HTTPS payloads are encrypted by
  definition. Both are inferred from well-known port numbers (80/8080
  for HTTP, 443/8443 for HTTPS), documented explicitly in
  `config.py` and `parser.py`. DNS, by contrast, is parsed natively via
  Scapy's `DNS`/`DNSQR` layers — no heuristic involved.
  `Content-Length` values and true multicast are handled the same way.
- **Direction & communication-type classification** require knowing
  the local machine's IP on the capturing interface (for
  incoming/outgoing) and use standard private/broadcast/multicast IP
  range checks (for local/internet/broadcast/multicast).
- **Statistics use running aggregates**, not full recomputation per
  packet, keeping per-packet update cost O(1) regardless of session
  length.
- **Memory safety:** `MAX_RETAINED_PACKETS` in `config.py` caps how
  many processed packet dictionaries are retained in memory during a
  session, since a very long-running capture could otherwise grow
  unbounded before being written out.
- **Session file is the single source of truth for a run:** each
  capture run produces one JSON file under `sessions/` containing the
  session metadata, a chronological action log ("Session started",
  "Capture stopped - N packets", "Application mapping performed - X
  mapped, Y unknown", "Session ended"), and the full list of captured
  (and, once `main.py` runs Module 2, application-mapped) packet
  dictionaries. The file is safe to re-save multiple times during a
  run (e.g. once right after capture, again after app-mapping
  enriches the packets) since the filename is derived from a stable
  session ID.

---

## Testing

Run the full test suite:

```bash
pip install -r requirements-dev.txt
python -m pytest -v
```

All parsing, validation, classification, statistics, session, and
capture-engine logic is covered using **synthetic Scapy packets**
built in-memory and a **mocked `sniff()`** — no real network interface
or Npcap driver is required to run the test suite. Persistence tests use
pytest's `tmp_path`, so they never touch the real `data/` directory.

**Important caveat:** the test suite validates all logic *except* true
live capture against a real NIC. Before relying on this in production,
run `python main.py` manually on your target Windows machine (as
Administrator, with Npcap installed) to confirm live capture behaves
as expected on real hardware/drivers — this is not something a mocked
test suite can fully substitute for.

To verify baseline persistence end to end on real traffic, run
`python main.py --reset-baseline`, stop it with Ctrl+C after a minute,
then run `python main.py` again and confirm it reports restored
observations. Repeating this a few times is the demo-visible proof of
the feature: `packet_size_anomaly` stops saying "baseline not yet
established" and starts giving real `baseline mean=…` verdicts.

---

## Error Handling Summary

| Scenario | Behavior |
|---|---|
| Npcap missing / interface enumeration fails | `InterfaceDetectionError`, clean message, exits with code 1 |
| Invalid interface/filter selection | `InterfaceSelectionError`, clean message, exits with code 1 |
| Permission denied opening interface | Logged, capture stops safely, session saved |
| Malformed/corrupted packet | Dropped silently (logged at WARNING), capture continues |
| Packet queue full (slow consumer) | Packet dropped, counted, logged; capture continues |
| Ctrl+C during capture | Caught, capture stops safely, session saved before exit |
| Baseline database corrupt / unreadable | Logged once, run continues with an in-memory-only baseline |
| Baseline database unwritable (permissions, missing drive, disk full) | Logged once, persistence disabled for the run, capture unaffected |
| Baseline database written by an incompatible schema version | Logged, ignored, run starts with an empty baseline rather than misreading it |
# Behavioral detection additions

Audit reliability fixes: Windows service mode reports user activity as UNKNOWN
because its session cannot observe desktop input; consequently the idle-transfer
rule waits for usable activity data (interactive CLI tracking still works).
Scapy background errors propagate into engine health. Risk scoring and snapshots
share a lock, and destination risk now means the direction-aware remote peer.
Existing historical scores are retained, not rewritten.

Correlation retains at most 1,024 groups and 256 signals per group, expires
inactive groups during observation, and drops oldest state when full. UI status
is Window closed only when application, remote peer, rule and time match a
stored correlation. It never infers remediation from a time window.

Named-pipe server connect/read/write operations have cancellable three-second
deadlines. Clients acknowledge consumed responses so the server can disconnect
without an unbounded flush. Isolated native Windows tests cover cancellation,
blocked writes, and recovery after a silent client; they do not replace full
installed-service/Npcap acceptance testing.

The live engine now retains destination ports and TCP flags in alert evidence.
It evaluates these additional checks without needing a learned baseline. The
current three-rule security gate above overrides the historical severity table;
all other checks below are diagnostic only:

| Rule | Evidence | Severity |
| --- | --- | --- |
| `tcp_port_probe` | Outbound SYN attempts to at least 20 distinct ports on one host within 60 seconds | High |
| `tcp_host_probe` | Outbound SYN attempts to at least 20 distinct hosts on one port within 60 seconds | High |
| `internet_smb_attempt` | Outbound SYN attempt to a globally routable IP on TCP 445 | Medium |
| `unusual_tcp_flags` | Inbound or outbound TCP with SYN+FIN, SYN+RST, no flags, or exactly FIN+PSH+URG | Medium |
| `long_dns_query_burst` | 20 distinct long outbound DNS query names to one resolver within 60 seconds | Medium |
| `public_legacy_service` | Outbound SYN attempt to a globally routable IP on TCP 21 or 23 | Medium |
| `inbound_tcp_port_probe` | One remote source attempts 20 distinct local ports in 60 seconds | High |
| `dns_failure_burst` | At least 30 distinct matched DNS names return NXDOMAIN, at least 80% of retained answered names, within 60 seconds | Medium |
| `upload_heavy_transfer` | At least 50 MiB captured outbound bytes to one public peer, at least five times inbound bytes, over a window up to five minutes with at least 60 seconds observed | Medium |

Protocol checks explain the specific anomaly in both the UI title and explanation.
Long DNS names mean at least 100 characters overall or a label of at least 50;
responses, unknown query/response status, duplicate names, and malformed label
lengths do not contribute distinct queries. Names are normalized for case and a
trailing dot. The count is per source/resolver, so multiple applications can
contribute. Long names can come from legitimate telemetry; this is a possible
encoded-DNS signal, not proof of tunneling. Encrypted DNS is not inspected.

Unusual TCP flags may indicate crafted probes, authorized testing, or capture
artifacts. Ports 21 and 23 suggest FTP/Telnet but do not establish the protocol,
unencrypted credentials, or successful login. Protocol alerts are limited to
one per rule/source/destination per 60 seconds. DNS and cooldown tracking each
retain at most 1,024 groups; DNS groups retain at most 20 names. Eviction can
lose history or cooldowns. These rules use live processing time and reset on
restart, like the probe rules. Medium signals use the existing correlation
policy; a standalone signal may not produce a desktop notification.

Probe rules count targets once, exclude SYN-ACK replies, and emit at most once
per source/scope per 60 seconds. They group by source IP, not process name:
short-lived sockets can evade process attribution. Consequently multiple apps
on the same source can contribute to one alert. Authorized scanners, discovery
tools, and some distributed applications can trigger these heuristics.
The thresholds are initial policy choices, not measured detection accuracy.

Tracking is bounded to 2,048 recently used groups and 20 targets per group.
Eviction under heavy traffic can lose detection history. Windows capture must
actually observe SYN packets; slow scans and UDP scans
are outside these rules. Timing uses live monotonic processing time, so these
rules are not a timestamp-aware PCAP replay detector. State resets on restart.
SMB port evidence does not establish protocol identity, successful access, or
malicious intent. A lone Medium signal remains subject to existing correlation
policy and may not produce a desktop notification.

Existing volume/rate rules remain heuristic signals. Validate normal browsing,
updates, backups, and authorized scan samples on the target Windows machine
before relying on alert quality. No automatic blocking is performed. These
source changes do not update an already installed executable; rebuild the
installer to deploy them.

## Real-world basis and validation limits

These are engineering heuristics informed by published research, not replicas
of vendor detections or claims of identifying a specific malware family.
Three AI reviewers examined detection logic, integration, and primary sources;
no human senior engineers were consulted.

- **Inbound probing:** service enumeration is documented in
  [MITRE T1046](https://attack.mitre.org/techniques/T1046/), including APT32
  network scanning. This rule detects a rapid TCP probing shape, not APT32
  attribution. Authorized vulnerability scanners are a benign example.
- **DNS failures:** [CERT Polska's DGA research](https://cert.pl/en/posts/2015/10/lang_pljak-nieistniejace-nazwy-domenowe-moga-pomoc-w-wykryciu-botnetow-dgalang_pllang_enhow-non-existent-domain-names-can-unveil-dga-botnets-lang_en/)
  discusses Conficker.A and warns that benign software also produces NXDOMAIN.
  [MITRE DET0419](https://attack.mitre.org/detectionstrategies/DET0419/) combines
  failure evidence with other signals. CANA reports lookup failures, not a DGA
  infection. DNS filtering or broken application configuration may trigger it.
- **Upload-heavy traffic:** [MITRE DET0348](https://attack.mitre.org/detectionstrategies/DET0348/)
  uses outbound volume and byte ratios with file/process context. CANA lacks
  sensitive-file access evidence, so a cloud backup and a malicious bulk upload
  can look alike. The alert explicitly calls for investigation.

DNS failures require an observed outbound query and matching incoming response
on port 53, including endpoints, client port, transport, transaction ID, name,
question type and class. Duplicate names count once. The ratio covers the latest
256 distinct answered names per client/resolver within 60 seconds, including
other response codes in the denominator. At most 4,096 pending queries and
1,024 result groups are retained. Query matching is not DNS authentication.
Encrypted DNS, missing replies, cache hits and dropped capture packets limit visibility.

Upload accounting groups by local address, public peer and application name,
uses five-second buckets over five minutes, and a conservative 65-second bucket
age before alerting. Bucket expiry can undercount up to five seconds. It counts
captured bytes including headers/retransmissions, not unique file bytes. Unknown
or changing attribution can split or combine transfers. At most 1,024 groups are
retained. Both new statistical patterns have per-group cooldowns; eviction and
restart lose history. These are live processing-time rules, not PCAP event-time
replay analytics.

Alert history now preserves direction, ports, TCP flags and DNS question/response
metadata through an additive SQLite migration. Existing history and baselines
are retained; older rows lack the newly added evidence. UI grouping distinguishes
remote peers and aggregate host-level rules do not attribute the entire pattern
to the final packet's application.

Automated tests use constructed packets and controlled clocks, including benign
downloads, successful DNS answers, retries and expiry. No real malware was run.
Real Windows/Npcap acceptance, benign-traffic false-positive measurement,
labelled-traffic recall measurement, and installer deployment remain necessary
before describing CANA as production-validated security software. More rules
alone cannot establish that reliability. Beaconing is deferred until connection
identity, retransmission handling and timing can be validated properly.

### Candidate evaluation on captured traffic (2026-11-11)

`tools/validate_real_traffic.py` evaluates the previous cadence and rejection
prototypes against three original IoT-23 labeled Zeek connection logs. Run it
with Python from this checkout; inputs are in `tmp/real_traffic/`, and the
reproducible results, source URLs and SHA-256 hashes are in
`output/real_traffic_validation.json`. Its inline self-checks cover malformed
rows, positive triggers and duplicate connection identities. No packets are sent.

| Capture | Flow records | Result |
| --- | ---: | --- |
| CTU-Honeypot-Capture-4-1 | 452 benign | 19 cadence alerts on benign traffic |
| CTU-Honeypot-Capture-5-1 | 1,374 benign | No candidate alerts |
| CTU-IoT-Malware-Capture-20-1 | 3,193 benign, 16 C&C-Torii | No candidate alerts |

These 5,035 records are real captured traffic, not generated fixtures. They are
flow-log evaluation, not replay through CANA's packet parser. Fixed cadence
thresholds were retained; the evaluation uses rolling 12-flow peer/service
groups, a 60-second rejection window and 600-second alert cooldown. Those
evaluation choices are experimental, not calibrated production settings.
Triggering-flow labels do not establish whole-window accuracy. No precision,
recall or Windows false-alert rate is claimed. The requested fourth capture,
CTU-Honeypot-Capture-7-1, returned HTTP 404 at the attempted log URL and is excluded.

**No candidate is approved or enabled.** Cadence demonstrably flags normal
behavior. Rejection detection has no confirmed positive scenario in these samples
and needs matched TCP outcomes absent from CANA's context. Resolver-policy
detection requires an explicit approved-resolver list and DNS evidence absent
from these logs. Existing live rules are not certified by this experiment.

Dataset credit: Sebastian Garcia, Agustin Parmisano and Maria Jose Erquiaga,
[IoT-23 (2020)](https://doi.org/10.5281/zenodo.4743746).
The [collection index](https://mcfp.felk.cvut.cz/publicDatasets/IoT-23-Dataset/)
states CC-BY. A scenario README also contains an authorization notice; because
those notices differ, these local research samples are not included in the
application package and should not be redistributed without clarifying the terms.

### Similar projects and reuse decisions

| Project | Relevant capability | Fit and reuse decision |
| --- | --- | --- |
| [RITA](https://github.com/activecm/rita) | Beaconing, long connections and DNS tunneling using Zeek logs | Relevant research reference; requires richer flow telemetry and a separate Docker/Zeek deployment. No rules or code imported. Its [GPLv3 license](https://github.com/activecm/rita/blob/main/LICENSE) cannot be treated as MIT-permissive code for CANA. |
| [Zeek](https://docs.zeek.org/en/master/reference/logs/conn.html) | Connection identity, history and outcome states | Useful semantics for future flow tracking. Current packet context is insufficient to reproduce those outcomes. Its [BSD-style license](https://github.com/zeek/zeek/blob/master/COPYING) permits conditional reuse with notices and no implied endorsement; individual files can carry additional notices. No code imported. |

CANA does not currently declare a project license. An outside rule still needs the right
telemetry, positive and benign validation, acceptable alert volume and a check of
its exact license before incorporation. A familiar rule name or another tool's
success does not transfer that tool's validation to CANA. This comparison did not
run either external engine or establish blanket legal compatibility.

### Existing-rule packet replay and alert gate (2026-11-11)

The offline harness `tools/replay_existing_rules.py` reads actual PCAP/PCAPNG
packets through the production parser, validator, direction classifier,
orchestrator and rising-edge alert handler. It advances isolated virtual clocks
with capture timestamps, so rapid file reading cannot manufacture bursts.
Each host gets a fresh baseline. Historical process and user-activity data are
left UNKNOWN; no current socket table is used to attribute old packets.
Replay never transmits packets or writes to live alert databases.

The [CICIDS2017 source description](https://www.unb.ca/cic/datasets/ids-2017.html)
identifies Monday as benign and maps Windows endpoints. The first 128 MiB of
a [public mirror](https://huggingface.co/datasets/bvsam/cic-ids-2017/blob/main/pcap/Monday-WorkingHours.pcap)
was downloaded. Its first 32 MiB was used for discovery and the later disjoint
segment for holdout. Incomplete trailing PCAPNG blocks were excluded explicitly.
This is recorded lab traffic generated from user profiles, not a capture from
this user's PC. The mirror's full-file authenticity was not independently
verified against an original publisher checksum; downloaded-byte hashes are saved.

| Evidence | Observation |
| --- | --- |
| Windows discovery excerpt, 54,632 total packets over 635 seconds | Before the gate: one host-probe alert and one rate alert on labelled benign traffic; 145 missing-attribution alerts |
| Windows holdout excerpt, 115,600 total packets over 454 seconds | Enabled three rules produced no alerts; held-back host/rate checks still triggered |
| Windows host coverage | 121,467 host-packet evaluations across both excerpts; .9, .5 and .14 observed, no packets for .8 or .15 |
| Benign Philips Hue, 21,664 total packets | Before the gate: 1,318 rate alerts; after the gate: no security alerts |
| Torii capture, 50,156 total packets | No alerts from the enabled rules; these rules do not detect Torii C&C |
| Wireshark standard Nmap scan | Outbound and inbound port-probe alerts fired from their respective endpoint perspectives |
| Wireshark OS scan | Both port-probe directions and unusual TCP flags fired |
| Single-port ACK scan | Outside the enabled SYN/flag patterns; no detection claimed |

The Nmap samples are documented in the [Wireshark sample catalog](https://wiki.wireshark.org/SampleCaptures)
and its [capture archive](https://wiki.wireshark.org/uploads/__moin_import__/attachments/SampleCaptures/NMap-Captures.zip).
These are authorized scan examples, so an alert means observed probing, not
proof of malicious intent. No scan or malware was executed for this validation.

| Check | Current decision |
| --- | --- |
| `tcp_port_probe`, `inbound_tcp_port_probe`, `unusual_tcp_flags` | Enabled: observed positives and no alerts on the bounded benign samples |
| `tcp_host_probe`, `connection_rate_anomaly` | Diagnostic only: failed benign checks; thresholds were not tuned on the test data |
| `unknown_application_internet`, `packet_size_anomaly` | Diagnostic only: missing ownership and packet size alone are insufficient security evidence |
| `idle_large_transfer` | Diagnostic only: activity ground truth unavailable |
| `internet_smb_attempt`, `public_legacy_service` | Diagnostic only: no validated service-policy positive/negative coverage |
| `long_dns_query_burst`, `dns_failure_burst`, `upload_heavy_transfer` | Diagnostic only: no suitable positive and benign coverage for these behaviors |

The shared `SECURITY_ALERT_RULES` gate excludes held-back checks from alert
storage, printed security alerts, risk scoring, correlation, notifications and
security trigger totals. Their underlying calculations remain testable for
future evaluation. Existing historical alerts and saved baselines are preserved.
The UI says Monitoring active and names the limited detection scope.

Run `python tools/replay_existing_rules.py` with the downloaded local samples to
regenerate `output/existing_rules_packet_replay.json`. The harness asserts the
benign and positive acceptance checks and records hashes, per-host coverage,
raw triggers, emitted alerts, validator rejections and rule decisions. The
pre-change result is `output/existing_rules_packet_replay_before.json`.
`tests/test_replay_validation.py` independently checks timestamp spacing,
both detection directions, and exclusion of every held-back rule from security
sinks. Downloaded captures are local research inputs, not packaged app assets.

Zero observed alerts in these short benign Windows excerpts is not a measured
fleet-wide false-positive rate. Contemporary Windows 11 workloads, backups,
VPNs, authorized scanners, idle/activity correlation, real process attribution,
IPv6 capture coverage, live Npcap behavior and installer deployment remain
unverified. This update changes source behavior; it does not rebuild or replace
an already installed CANA service.

Dataset citation: Iman Sharafaldin, Arash Habibi Lashkari and Ali A. Ghorbani,
"Toward Generating a New Intrusion Detection Dataset and Intrusion Traffic
Characterization", ICISSP 2018. IoT-23 attribution is provided above.

