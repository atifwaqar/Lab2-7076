from __future__ import annotations

from dataclasses import dataclass
from importlib import import_module
from pathlib import Path
from typing import Callable, List, Optional, Sequence, Tuple

from utils.plotting import HAS_MPL, ensure_out_dir

_DASHBOARD_SPECS: Sequence[Tuple[str, str, str]] = (
    ("attacks.bleichenbacher_oracle", "make_attack_complexity_dashboard", "attack_complexity_analysis.png"),
    ("reports.ecdh_visualization", "make_ecdh_visualization", "ecdh_visualization.png"),
    ("reports.attack_complexity_dashboard", "make_attack_complexity_dashboard", "attack_complexity_analysis.png"),
    ("ecdh.ecdh_tinyec", "make_ecdh_visualization", "ecdh_visualization.png"),
    ("reports.key_entropy_dashboard", "make_key_entropy_dashboard", "key_entropy_analysis.png"),
    ("reports.performance_dashboard", "make_performance_dashboard", "performance_comparison.png"),
)


@dataclass
class DashboardResult:
    """Outcome of a single dashboard export attempt."""

    module: str
    attr: str
    target: Path
    status: str
    reason: str = ""
    output: Optional[Path] = None

    def resolved_target(self) -> Path:
        return self.target.resolve()

    def resolved_output(self) -> Optional[Path]:
        return None if self.output is None else self.output.resolve()


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
    *,
    module_name: str,
    attr: str,
) -> Tuple[Optional[Path], str]:
    try:
        result = func(target)
    except (ModuleNotFoundError, ImportError) as exc:
        name = getattr(exc, "name", None) or str(exc)
        reason = f"missing dependency: {name}"
        print(f"skipped {module_name}.{attr} ({reason})")
        return None, reason
    except Exception as exc:  # pragma: no cover - runtime safeguard
        reason = f"error: {exc}"
        print(f"skipped {module_name}.{attr} ({reason})")
        return None, reason
    if result is None:
        if target.exists():
            return target, ""
        reason = "no output generated"
        print(f"skipped {module_name}.{attr} ({reason})")
        return None, reason
    return Path(result), ""


def make_all_dashboards() -> List[DashboardResult]:
    """Generate all available dashboards and describe the outcome of each attempt."""

    out_dir = ensure_out_dir("Visualizations")
    results: List[DashboardResult] = []

    if not HAS_MPL:
        reason = "matplotlib not installed"
        print("matplotlib is not available; skipping dashboard export.")
        for module_name, attr, filename in _DASHBOARD_SPECS:
            target = out_dir / filename
            print(f"skipped {module_name}.{attr} ({reason})")
            results.append(
                DashboardResult(
                    module=module_name,
                    attr=attr,
                    target=target,
                    status="skipped",
                    reason=reason,
                )
            )
        return results

    for module_name, attr, filename in _DASHBOARD_SPECS:
        func, reason = _load_callable(module_name, attr)
        target = out_dir / filename
        if func is None:
            print(f"skipped {module_name}.{attr} ({reason})")
            results.append(
                DashboardResult(
                    module=module_name,
                    attr=attr,
                    target=target,
                    status="skipped",
                    reason=reason,
                )
            )
            continue

        path, invoke_reason = _invoke_dashboard(func, target, module_name=module_name, attr=attr)
        if path is None:
            results.append(
                DashboardResult(
                    module=module_name,
                    attr=attr,
                    target=target,
                    status="skipped",
                    reason=invoke_reason or reason,
                )
            )
            continue

        resolved = Path(path)
        results.append(
            DashboardResult(
                module=module_name,
                attr=attr,
                target=target,
                status="saved",
                output=resolved,
            )
        )
    return results


def main() -> None:
    results = make_all_dashboards()
    for result in results:
        if result.status == "saved" and result.output is not None:
            print(result.output.resolve())


if __name__ == "__main__":
    main()
