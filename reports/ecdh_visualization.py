"""Wrapper for generating the ECDH visualisation asset."""

from __future__ import annotations

from contextlib import contextmanager
from pathlib import Path
from typing import Iterator, Optional

from ecdh.ecdh_tinyec import save_ecdh_visualization
from utils.plotting import HAS_MPL

_NOTE_TEXT = "Illustrative scaling only; not a benchmark."


@contextmanager
def _patched_figure_hooks() -> Iterator[None]:
    """Temporarily append illustrative labels to the generated figure."""

    if not HAS_MPL:
        yield
        return

    from matplotlib.figure import Figure  # imported lazily for optional dependency

    original_suptitle = Figure.suptitle
    original_tight_layout = Figure.tight_layout

    def patched_suptitle(self, t, *args, **kwargs):  # type: ignore[override]
        if isinstance(t, str) and "(illustrative" not in t.lower():
            t = f"{t} (illustrative)"
        return original_suptitle(self, t, *args, **kwargs)

    def patched_tight_layout(self, *args, **kwargs):  # type: ignore[override]
        result = original_tight_layout(self, *args, **kwargs)
        if not any(text.get_text() == _NOTE_TEXT for text in getattr(self, "texts", [])):
            self.text(0.5, 0.01, _NOTE_TEXT, ha="center", fontsize=9)
        return result

    Figure.suptitle = patched_suptitle  # type: ignore[assignment]
    Figure.tight_layout = patched_tight_layout  # type: ignore[assignment]
    try:
        yield
    finally:
        Figure.suptitle = original_suptitle  # type: ignore[assignment]
        Figure.tight_layout = original_tight_layout  # type: ignore[assignment]


def make_ecdh_visualization(save_path: str | Path) -> Optional[Path]:
    """Generate the ECDH visualization PNG, skipping gracefully if unavailable."""

    try:
        if HAS_MPL:
            with _patched_figure_hooks():
                return save_ecdh_visualization(save_path)
        return save_ecdh_visualization(save_path)
    except RuntimeError as exc:
        if str(exc) == "tinyec not installed":
            return None
        raise
