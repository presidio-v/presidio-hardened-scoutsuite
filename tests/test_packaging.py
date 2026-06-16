from __future__ import annotations

from pathlib import Path

try:
    import tomllib
except ModuleNotFoundError:  # Python 3.9 / 3.10
    import tomli as tomllib  # type: ignore[no-redef]

from presidio_scoutsuite import __version__

_ROOT = Path(__file__).resolve().parent.parent


def test_pyproject_version_matches_dunder():
    """pyproject.toml's static version must equal presidio_scoutsuite.__version__.

    They are separate sources (the build reads pyproject; the runtime reads
    version.py); a drift between them shipped a mismatched PyPI version before.
    """

    data = tomllib.loads((_ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    assert data["project"]["version"] == __version__


def test_every_console_script_is_importable():
    """Each declared entry point must resolve to a real module:callable."""

    import importlib

    data = tomllib.loads((_ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    scripts = data["project"]["scripts"]
    assert scripts  # non-empty
    for name, target in scripts.items():
        module_name, _, attr = target.partition(":")
        module = importlib.import_module(module_name)
        assert callable(getattr(module, attr)), f"{name} -> {target} not callable"
