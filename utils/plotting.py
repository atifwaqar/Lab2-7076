from __future__ import annotations

from pathlib import Path
from typing import Optional, Tuple

HAS_MPL = False
plt = None  # type: ignore[assignment]

try:  # pragma: no cover - optional dependency
    import matplotlib

    matplotlib.use("Agg")
    import matplotlib.pyplot as plt

    HAS_MPL = True
except Exception:  # pragma: no cover - optional dependency missing
    plt = None  # type: ignore[assignment]


def ensure_out_dir(pathlike) -> Path:
    """Ensure the given directory exists and return it as a Path."""
    path = Path(pathlike)
    path.mkdir(parents=True, exist_ok=True)
    return path


if HAS_MPL:  # pragma: no cover - tiny wrapper around matplotlib
    from matplotlib.axes import Axes
    from matplotlib.figure import Figure

    def new_figure(figsize: Tuple[float, float] = (16, 12)) -> Tuple[Figure, Axes]:
        """Create a new figure and axis with a large default size."""
        fig, ax = plt.subplots(figsize=figsize)
        return fig, ax

    def save(fig: Figure, path) -> Path:
        """Save the figure to *path* (parent directories created automatically)."""
        target = Path(path)
        target.parent.mkdir(parents=True, exist_ok=True)
        fig.savefig(str(target), bbox_inches="tight")
        plt.close(fig)
        return target

    def wide_grid(rows: int, cols: int):
        """Create a grid of subplots suitable for dashboard-style layouts."""
        fig, axes = plt.subplots(rows, cols, figsize=(cols * 5.5, rows * 3.5), squeeze=False)
        return fig, axes

    def nice_axes(
        ax: Axes,
        title: str,
        xlabel: Optional[str] = None,
        ylabel: Optional[str] = None,
    ) -> Axes:
        """Apply consistent styling to a matplotlib Axes object."""
        ax.set_title(title)
        if xlabel:
            ax.set_xlabel(xlabel)
        if ylabel:
            ax.set_ylabel(ylabel)
        ax.grid(True, alpha=0.3)
        return ax

else:  # pragma: no cover - exercised when matplotlib is unavailable

    def new_figure(figsize: Tuple[float, float] = (16, 12)):
        """Fallback that returns (None, None) when matplotlib is absent."""
        return None, None

    def save(fig, path) -> Path:
        """Fallback save that simply ensures the destination directory exists."""
        target = Path(path)
        target.parent.mkdir(parents=True, exist_ok=True)
        return target

    def wide_grid(rows: int, cols: int):
        """Fallback that returns (None, None) when matplotlib is absent."""
        return None, None

    def nice_axes(ax, title: str, xlabel: Optional[str] = None, ylabel: Optional[str] = None):
        """Fallback that performs no styling when matplotlib is absent."""
        return ax

__all__ = [
    "HAS_MPL",
    "ensure_out_dir",
    "new_figure",
    "save",
    "wide_grid",
    "nice_axes",
]
