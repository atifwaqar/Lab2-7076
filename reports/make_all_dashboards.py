from __future__ import annotations

from importlib import import_module
from pathlib import Path
from typing import Callable, List, Optional, Sequence, Tuple

from utils.plotting import HAS_MPL, ensure_out_dir

_DASHBOARD_SPECS: Sequence[Tuple[str, str, str]] = (
    ("attacks.bleichenbacher_oracle", "make_attack_complexity_dashboard", "attack_complexity_analysis.png"),
    ("ecdh.ecdh_tinyec", "make_ecdh_visualization", "ecdh_visualization.png"),
    ("aes_modes.entropy_demo", "make_key_entropy_dashboard", "key_entropy_analysis.png"),
    ("reports.performance_dashboard", "make_performance_dashboard", "performance_comparison.png"),
)


def _load_callable(module_name: str, attr: str) -> Optional[Callable[[Path], Optional[Path]]]:
    try:
        module = import_module(module_name)
    except ImportError:
        return None
    return getattr(module, attr, None)


def _invoke_dashboard(func: Optional[Callable[[Path], Optional[Path]]], target: Path) -> Optional[Path]:
    if func is None:
        print("skipped")
        return None
    try:
        result = func(target)
    except (ModuleNotFoundError, ImportError):
        print("skipped")
        return None
    if result is None:
        return target
    return Path(result)


def make_all_dashboards() -> List[Path]:
    """Generate all available dashboards and return the paths that were written."""
    if not HAS_MPL:
        print("matplotlib is not available; skipping dashboard export.")
        return []

    out_dir = ensure_out_dir("out")
    saved: List[Path] = []
    for module_name, attr, filename in _DASHBOARD_SPECS:
        func = _load_callable(module_name, attr)
        target = out_dir / filename
        path = _invoke_dashboard(func, target)
        if path is not None:
            saved.append(path)
    return saved


def main() -> None:
    paths = make_all_dashboards()
    for path in paths:
        print(path.resolve())


if __name__ == "__main__":
    main()
