"""
anomaly_detection
==================

Module 4 of the Context-Aware Network Behavior Analyzer.

Combines outputs from Module 1 (packet capture/classification),
Module 2 (application mapping), and Module 3 (user activity) into a
unified "context record," maintains a rolling per-hour baseline of
what "normal" looks like for this machine, and evaluates a small set
of explainable rules against that baseline to flag suspicious
behavior.

Design philosophy (see project discussion history): fixed thresholds
like "idle + >100MB = suspicious" produce false positives on
completely normal behavior (e.g. streaming video while away from the
keyboard). Checking against a *learned baseline* instead of a fixed
number is what actually addresses this - "is this unusual for THIS
machine" rather than "is this unusual in the abstract."

This package is standalone: it depends only on plain dictionaries/
dataclasses passed in by the caller, not on importing
``packet_capture`` or ``user_activity`` directly, so it can be tested
independently and wired into any future orchestrator.
"""

__version__ = "1.0.0"
