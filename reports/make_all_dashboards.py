from __future__ import annotations

from importlib import import_module
from pathlib import Path
from typing import Callable, Optional, Sequence, Tuple, TypedDict

from utils.plotting import HAS_MPL, ensure_out_dir

_DASHBOARD_SPECS: Sequence[Tuple[str, str, str, str]] = (
    (
        "Cryptographic Security Analysis",
        "reports.attack_complexity_dashboard",
        "make_attack_complexity_dashboard",
        "attack_complexity_analysis.png",
    ),
    (
        "Elliptic Curve Cryptography Visualization",
        "reports.ecdh_visualization",
        "make_ecdh_visualization",
        "ecdh_visualization.png",
    ),
    (
        "Key Entropy and Quality Analysis",
        "reports.key_entropy_dashboard",
        "make_key_entropy_dashboard",
        "key_entropy_analysis.png",
    ),
    (
        "Cryptographic Performance and Security Trade-offs",
        "reports.performance_dashboard",
        "make_performance_dashboard",
        "performance_comparison.png",
    ),
)


class DashboardOutcome(TypedDict):
    """Dictionary describing the outcome of a dashboard export."""

    title: str
    path: Optional[Path]
    skipped: bool
    reason: Optional[str]


def _load_callable(module_name: str, attr: str) -> Tuple[Optional[Callable[[Path], Optional[Path]]], str]:
    try:
        module = import_module(module_name)
    except ImportError as exc:
        return None, f"import failed: {exc}"

    func = getattr(module, attr, None)
    if func is None:
        return None, f"callable '{attr}' not found in {module_name}"
    return func, ""


def _invoke_dashboard(
    func: Callable[[Path], Optional[Path]],
    target: Path,
) -> Tuple[Optional[Path], Optional[str]]:
    try:
        result = func(target)
    except (ModuleNotFoundError, ImportError) as exc:
        name = getattr(exc, "name", None) or str(exc)
        reason = f"missing dependency: {name}"
        return None, reason
    except RuntimeError as exc:
        message = str(exc)
        if message == "tinyec not installed":
            return None, "missing dependency: tinyec"
        return None, f"error: {message}"
    except Exception as exc:  # pragma: no cover - runtime safeguard
        return None, f"error: {exc}"
    if result is None:
        if target.exists():
            return target, None
        return None, "no output generated"
    return Path(result), None


def make_all_dashboards() -> list[DashboardOutcome]:
    """Generate all dashboards, printing a summary and returning detailed results."""

    out_dir = ensure_out_dir("Visualizations")
    results: list[DashboardOutcome] = []

    if not HAS_MPL:
        reason = "matplotlib not installed"
        print("matplotlib is not available; skipping dashboard export.")
        for title, _module_name, _attr, _filename in _DASHBOARD_SPECS:
            print(f"Skipped: {title} ({reason})")
            results.append(
                {
                    "title": title,
                    "path": None,
                    "skipped": True,
                    "reason": reason,
                }
            )
        return results

    for title, module_name, attr, filename in _DASHBOARD_SPECS:
        func, reason = _load_callable(module_name, attr)
        target = out_dir / filename
        if func is None:
            print(f"Skipped: {title} ({reason})")
            results.append(
                {
                    "title": title,
                    "path": None,
                    "skipped": True,
                    "reason": reason,
                }
            )
            continue

        path, invoke_reason = _invoke_dashboard(func, target)
        if path is None:
            skip_reason = invoke_reason or reason or "unknown error"
            print(f"Skipped: {title} ({skip_reason})")
            results.append(
                {
                    "title": title,
                    "path": None,
                    "skipped": True,
                    "reason": skip_reason,
                }
            )
            continue

        resolved = Path(path)
        absolute = resolved.resolve()
        print(f"Saved: {title} -> {absolute}")
        results.append(
            {
                "title": title,
                "path": absolute,
                "skipped": False,
                "reason": None,
            }
        )
    return results


def main() -> list[DashboardOutcome]:
    """Entry point used by ``python -m reports.make_all_dashboards``."""

    return make_all_dashboards()


if __name__ == "__main__":
    main()
