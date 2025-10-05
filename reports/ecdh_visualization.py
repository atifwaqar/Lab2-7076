"""Wrapper for generating the ECDH visualisation asset."""

from __future__ import annotations

from pathlib import Path
from typing import Optional

from ecdh.ecdh_tinyec import save_ecdh_visualization


def make_ecdh_visualization(save_path: str | Path) -> Optional[Path]:
    """Create the ECDH visualisation PNG, skipping gracefully if unavailable."""

    try:
        return save_ecdh_visualization(save_path)
    except RuntimeError as exc:
        if str(exc) == "tinyec not installed":
            print("skipped")
            return None
        raise
