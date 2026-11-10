"""Capture feeds: the only module permitted to import scapy (packora PRD section 6)."""

from __future__ import annotations

from packora.capture.base import Frame

__all__ = ["Frame"]
