"""Tolerant reading of the small JSON state files in the config folder.

A state file can be cut short by a full disk or a crash, or edited by hand. None of that may take
the app (or the background sync timer) down, so a missing, unreadable, corrupt, oddly shaped or
absurdly nested file reads as "nothing saved" instead of raising."""

from __future__ import annotations

import json
from pathlib import Path


def read_object(path) -> dict:
    """The JSON object stored at `path`, or {} when there is no usable one."""
    try:
        data = json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, ValueError, RecursionError):      # ValueError covers bad JSON and bad UTF-8
        return {}
    return data if isinstance(data, dict) else {}
