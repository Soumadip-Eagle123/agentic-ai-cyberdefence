"""Locating the upstream layers' artifacts.

Layer 2's output has already moved once (repository root -> ``src/layer_2/artifacts/demo``).
Layer 6 reads it, so rather than hard-code one path we search the known layouts and
fail with a message that names every place we looked.

Set ``ACCDS_DATA_DIR`` to override the search entirely.
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import List, Optional

REPO_ROOT = Path(__file__).resolve().parent.parent

#: Known Layer 2 output locations, newest layout first.
CANDIDATE_DIRS = (
    Path("src/layer_2/artifacts/demo"),
    Path("artifacts/demo"),
    Path("src/layer_2"),
    Path("."),
)

ENV_OVERRIDE = "ACCDS_DATA_DIR"


class DataSourceNotFound(FileNotFoundError):
    """Raised when Layer 2's artifacts cannot be located."""


def search_paths() -> List[Path]:
    override = os.environ.get(ENV_OVERRIDE)
    if override:
        return [Path(override).expanduser().resolve()]
    return [(REPO_ROOT / candidate).resolve() for candidate in CANDIDATE_DIRS]


def find_data_dir(required: str = "findings.json") -> Path:
    """Return the first directory containing Layer 2's output."""
    searched = search_paths()
    for directory in searched:
        if (directory / required).is_file():
            return directory
    locations = "\n  ".join(str(item) for item in searched)
    raise DataSourceNotFound(
        f"Could not find Layer 2's '{required}'. Looked in:\n  {locations}\n"
        f"Run Layer 2's demo first, or set {ENV_OVERRIDE} to the directory holding it."
    )


def findings_file(explicit: Optional[str | Path] = None) -> Path:
    if explicit:
        return Path(explicit)
    return find_data_dir("findings.json") / "findings.json"


def scenario_file(scenario: str, explicit: Optional[str | Path] = None) -> Path:
    if explicit:
        return Path(explicit)
    name = f"scenario_{scenario}.json"
    return find_data_dir(name) / name


def available() -> bool:
    """True when Layer 2's artifacts can be located. Used to report, never to skip silently."""
    try:
        find_data_dir()
    except DataSourceNotFound:
        return False
    return True
