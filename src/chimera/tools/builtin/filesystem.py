from __future__ import annotations

import glob as glob_module
from pathlib import Path

from chimera.core.exceptions import ValidationError


def filesystem_read(path: str, offset: int = 0, limit: int | None = None) -> str:
    file_path = Path(path).resolve()
    if not file_path.exists():
        raise ValidationError(f"File not found: {path}")
    if not file_path.is_file():
        raise ValidationError(f"Not a file: {path}")

    content = file_path.read_text(encoding="utf-8", errors="replace")
    lines = content.splitlines(keepends=True)

    if offset > 0:
        lines = lines[offset:]

    if limit is not None:
        lines = lines[:limit]

    return "".join(lines)


def filesystem_write(path: str, content: str) -> str:
    file_path = Path(path).resolve()
    file_path.parent.mkdir(parents=True, exist_ok=True)
    file_path.write_text(content, encoding="utf-8")
    return f"Written {len(content)} bytes to {path}"


def filesystem_search(pattern: str, path: str | None = None) -> str:
    search_path = Path(path).resolve() if path else Path.cwd()
    if not search_path.is_dir():
        raise ValidationError(f"Directory not found: {path or '.'}")

    matches = list(glob_module.glob(pattern, root_dir=search_path, recursive=True))
    if not matches:
        return f"No files matching '{pattern}' in {search_path}"

    return "\n".join(sorted(matches)[:100])
