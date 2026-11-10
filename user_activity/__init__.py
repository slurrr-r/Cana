"""
user_activity
=============

Module 3 of the Context-Aware Network Behavior Analyzer.

Detects system-wide keyboard and mouse activity and classifies the
user's current status as ACTIVE or IDLE based on time elapsed since
the last input event.

This package is fully standalone: it has no dependency on
``packet_capture`` (Module 1/2) and exposes a single public entry
point:

    from user_activity.tracker import ActivityTracker

    tracker = ActivityTracker()
    tracker.start()
    status = tracker.get_status()  # ActivityStatus(status="ACTIVE", ...)
    tracker.stop()

Design note: the underlying ``pynput`` library requires a live
GUI/input backend (X11 on Linux, a display session on Windows/macOS)
and cannot even be imported in headless environments. To keep the
rest of this package importable and testable everywhere, ``pynput``
is imported lazily - only inside :class:`user_activity.listener.ActivityListener.start`,
never at module load time.
"""

__version__ = "1.0.0"
