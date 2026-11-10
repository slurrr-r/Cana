"""Windows service identity and recovery defaults."""

from __future__ import annotations

SERVICE_NAME = "CANA"
SERVICE_DISPLAY_NAME = "CANA Network Monitor"
SERVICE_DESCRIPTION = (
    "Context-Aware Network Behavior Analyzer. Captures and analyzes "
    "local network traffic in the background."
)
SERVICE_RECOVERY_DELAY_MS = 15_000
SERVICE_RESTART_RESET_SECONDS = 86_400
