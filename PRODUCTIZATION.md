# CANA Windows Productization

CANA is a background Windows security application. Packet capture,
anomaly detection, risk scoring, and persistence belong to
`CANAEngine`. The UI does not own capture. Closing the UI does not
stop monitoring.

## Architecture

| Component | Responsibility |
|---|---|
| `cana_engine.CANAEngine` | `start()` / `stop()` / `status()` / health / watchdog |
| `cana_engine.control` | Named-pipe status/snapshot payloads for the native UI |
| `cana_engine.pipe` | Privileged named pipe `\\.\pipe\CANAControl` |
| `cana_service` | Windows service runtime and `sc.exe` install/uninstall |
| `cana_ui` | Status/Control window + tray; named-pipe status and Start/Stop |
| `main.py` | Developer/debug launcher over the same engine |

The engine uses the three enabled alert rules described in README.md.
Other checks are diagnostic only. It reuses `build_packet_handler` from
`cana_engine/handler.py`.

## Engine API

```python
from cana_engine import CANAEngine, load_config

engine = CANAEngine(load_config())
engine.start()
status = engine.status()
engine.stop()
```

- At most one capture engine (`_capture_guard`).
- Idle shutdown polls `sniff(..., timeout=1s)`; stop does not wait
  for a packet.
- Watchdog restarts a dead worker (5s poll, 8s delay, max 3 restarts
  in 120s) and stops with `Event.wait` + join on engine shutdown.
- Missing Npcap does not kill the service; UI shows Capture unavailable.

## Windows service

- Service name: `CANA`
- Display name: CANA Network Monitor
- Start type: Automatic
- Recovery: restart after 15s, three times, reset 86400s
- Data: `%ProgramData%\CANA` (`config.json`, `cana.db`, `installer-user.sid`, `logs\`, `sessions\`)
- Config: `%ProgramData%\CANA\config.json` (authoritative for the installed service)
- `CANA_CONFIG` is ignored by the installed/frozen Windows service. Use `CANA_DEV=1` or `CANA_TEST=1` for developer overrides.
- Account: LocalSystem (needed for Npcap and `%ProgramData%\CANA`).
  This is a privileged account; mitigate by authorizing the named pipe
  with SYSTEM, Administrators, and the installing-user SID.
- Status and privileged start/stop/config use
  `\\.\pipe\CANAControl`. The native UI talks only to the named pipe. The pipe
  server impersonates the connected caller, reads TokenUser, and
  allows SYSTEM (`S-1-5-18`), the installing-user SID, or a caller
  who is a member of Administrators (`S-1-5-32-544`). TokenUser is
  never compared to the Administrators group SID.
- Named-pipe reads reject oversized messages (`ERROR_MORE_DATA`).
  UI IPC runs off the Tk thread with a 3s timeout.
- Config booleans reject unknown strings (`banana` is not False).
  Correlation groups by application + remote peer (inbound uses source).
- Production service is pipe-only. Capture/Npcap failure parks the
  engine; the service stays alive.
- Pipe protocol is strict: start/stop/status take no extra fields;
  `apply_config` requires `{"config": {...}}`.
- Pipe start/stop persist a validated candidate first, then apply.
  A persist failure leaves runtime unchanged. An apply failure after
  persist rolls the on-disk config back.
- Installer SID must be `S-1-5-21-*-*` (interactive user). SYSTEM and
  service SIDs abort install. A corrupt SID file is ignored at runtime.
- Installed binPath is `CANA.exe` with no extra args. `python main.py
  --service` is developer foreground only and does not enter
  `StartServiceCtrlDispatcher`.

`CANA.exe` with empty argv (frozen) enters the pywin32 SCM dispatcher.
If the process was not started by Service Manager (error 1063), it
opens the UI. `python main.py --service` always runs foreground.

```powershell
cana-service install
cana-service uninstall
python main.py --service
```

`packaging/install.ps1` / `packaging/uninstall.ps1` / `packaging/CANA.iss`
register the service, Start Menu shortcut (`CANA.exe --ui`), and
preserve user data on uninstall unless confirmed.

## UI vs CLI

| Command | Behavior |
|---|---|
| `python main.py` | Interactive CLI; prompts then starts `CANAEngine` |
| `python main.py --debug` | Same engine, verbose logging |
| `python main.py --service` / `CANA.exe --service` | Foreground debug runtime (not SCM) |
| `CANA.exe` (no args, frozen) | SCM dispatch; UI if not started by Service Manager |
| `python main.py --ui` / `cana-ui` | Native UI only; does not start capture |
| Tray Start/Stop | Named-pipe client (`\\.\pipe\CANAControl`) |

Tray Exit UI / closing the window leaves the Windows service running.

## Build

```powershell
powershell -File packaging/build_windows.ps1
```

Then compile `packaging/CANA.iss` with Inno Setup to produce
`CANA-Setup.exe`. The installer records the logged-on user SID
(explorer owner; fail closed if that SID cannot be obtained) to
`%ProgramData%\CANA\installer-user.sid` and ACLs ProgramData to
SYSTEM + Administrators (Full) and the installing user (read/execute).

## Windows acceptance

The ordinary test suite skips live SCM/Npcap acceptance tests. On an
installed Windows machine:

```powershell
powershell -File packaging/windows_acceptance.ps1
```

Or:

```powershell
$env:CANA_ACCEPTANCE = "1"
python -m pytest tests/test_windows_acceptance.py -q
```

That checks `sc.exe query/qc`, named-pipe start/stop, and
`installer-user.sid`.
