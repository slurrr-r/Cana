"""
packet_capture
==============

Module 1 of the Context-Aware Network Behavior Analyzer.

This package provides a standalone, production-quality network traffic
collection and packet processing subsystem. It is fully independent of
any downstream modules (application mapping, anomaly detection, UI,
etc.) and exposes a single public entry point:

    from packet_capture.capture import start_packet_capture
    packets = start_packet_capture()

The returned list of packet dictionaries is the contract this module
provides to whatever consumes it next.
"""

__version__ = "1.0.0"
