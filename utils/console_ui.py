"""Console presentation helpers with graceful fallbacks."""
from __future__ import annotations

import os
import shutil
import sys
from typing import Optional

try:  # optional dependency
    import colorama
    from colorama import Fore, Style
except Exception:  # pragma: no cover - optional dep
    colorama = None
    Fore = None  # type: ignore[assignment]
    Style = None  # type: ignore[assignment]

try:  # optional dependency
    import pyfiglet
except Exception:  # pragma: no cover - optional dep
    pyfiglet = None

__all__ = [
    "init",
    "banner",
    "step_header",
    "running_panel",
    "section",
    "kv",
    "bullet",
    "success",
    "warning",
    "error",
    "elapsed",
    "rule",
    "line",
]

_width = 100
_plain_mode = False
_use_color = False
_color_prefix = {
    "success": "",
    "warning": "",
    "error": "",
}

_symbol_success = "✓"
_symbol_warning = "!"
_symbol_error = "✗"
_symbol_bullet = "•"


def init(plain: bool = False) -> None:
    """Initialise console helpers with optional colour output."""

    global _width, _plain_mode, _use_color, _color_prefix
    global _symbol_success, _symbol_warning, _symbol_error, _symbol_bullet

    # Determine terminal width.
    _width = shutil.get_terminal_size(fallback=(100, 24)).columns or 100

    env_plain = bool(os.environ.get("NO_COLOR"))
    stream = getattr(sys.stdout, "isatty", lambda: False)
    is_tty = False
    try:
        is_tty = bool(stream())
    except Exception:  # pragma: no cover - conservative fallback
        is_tty = False

    _plain_mode = plain or env_plain or not is_tty

    if _plain_mode:
        _use_color = False
    else:
        _use_color = colorama is not None
        if _use_color and colorama is not None:
            try:
                colorama.init(autoreset=True)
            except Exception:  # pragma: no cover - best-effort init
                _use_color = False

    if _plain_mode:
        _symbol_success = "[OK]"
        _symbol_warning = "[!]"
        _symbol_error = "[X]"
        _symbol_bullet = "-"
    else:
        _symbol_success = "✓"
        _symbol_warning = "!"
        _symbol_error = "✗"
        _symbol_bullet = "•"

    if _use_color and Fore is not None and Style is not None:
        _color_prefix = {
            "success": Fore.GREEN + Style.BRIGHT,
            "warning": Fore.YELLOW + Style.BRIGHT,
            "error": Fore.RED + Style.BRIGHT,
        }
    else:
        _color_prefix = {"success": "", "warning": "", "error": ""}


def _apply(style: str, message: str) -> str:
    if not _use_color:
        return message
    suffix = Style.RESET_ALL if Style is not None else ""
    return f"{style}{message}{suffix}"


def rule(char: str = "=", width: Optional[int] = None) -> None:
    """Print a horizontal rule spanning the console width."""

    count = width if width is not None else _width
    print(char * max(1, count))


def banner(title: str) -> None:
    """Display a banner heading for the CLI."""

    if _plain_mode or pyfiglet is None:
        text = f"=== {title} ==="
        print(text.center(_width))
        return

    try:
        fig = pyfiglet.figlet_format(title, width=_width)
    except Exception:
        text = f"=== {title} ==="
        print(text.center(_width))
        return
    print(fig)


def step_header(i: int, n: int, title: str) -> None:
    """Print a numbered step header before running a demo."""

    msg = f"[{i}/{n}] Preparing to run: {title}"
    if _use_color:
        msg = _apply(Fore.CYAN + Style.BRIGHT if Fore and Style else "", msg)
    print(msg)


def running_panel(title: str, script: str | None = None) -> None:
    """Display a panel indicating that a script/demo is running."""

    rule("=")
    heading = f"RUNNING: {title}"
    if _use_color and Fore is not None:
        heading = _apply(Fore.MAGENTA + Style.BRIGHT if Style else "", heading)
    print(heading)
    info = f"Script: {script or 'n/a'}"
    print(info)
    rule("=")


def section(title: str) -> None:
    """Display a section divider with the given title."""

    rule("=")
    heading = f" {title.upper()}"
    print(heading)
    rule("=")


def kv(key: str, value: str) -> None:
    """Print a key-value line."""

    print(f"{key}: {value}")


def bullet(msg: str) -> None:
    """Print a bullet-point line."""

    print(f"{_symbol_bullet} {msg}")


def success(msg: str) -> None:
    """Highlight a success message."""

    prefix = _color_prefix["success"]
    symbol = _symbol_success
    print(_apply(prefix, f"{symbol} {msg}"))


def warning(msg: str) -> None:
    """Highlight a warning message."""

    prefix = _color_prefix["warning"]
    symbol = _symbol_warning
    print(_apply(prefix, f"{symbol} {msg}"))


def error(msg: str) -> None:
    """Highlight an error message."""

    prefix = _color_prefix["error"]
    symbol = _symbol_error
    print(_apply(prefix, f"{symbol} {msg}"))


def elapsed(prefix: str, seconds: float) -> None:
    """Print a formatted elapsed time entry."""

    print(f"{prefix} {seconds:.2f}s")


def line() -> None:
    """Print a thin separator line."""

    rule("-")
