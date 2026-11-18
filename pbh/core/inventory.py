"""File inventory with size, depth, and symlink limits. Never follows symlinks."""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path

MAX_FILE_BYTES = 2 * 1024 * 1024
MAX_FILES = 5000
MAX_DEPTH = 12


@dataclass(frozen=True)
class InventoryItem:
    path: Path
    relative: str
    size: int
    kind: str


@dataclass(frozen=True)
class Inventory:
    items: tuple[InventoryItem, ...]
    skipped: tuple[tuple[str, str], ...]


KIND_BY_SUFFIX = {
    ".json": "json",
    ".jsonc": "jsonc",
    ".json5": "json5",
    ".yaml": "yaml",
    ".yml": "yaml",
    ".toml": "toml",
    ".xml": "xml",
}


def classify(path: Path) -> str:
    name = path.name
    if name in {"package.json", "package-lock.json"}:
        return "json"
    if path.suffix == ".json" and "openapi" in name.lower():
        return "json"
    return KIND_BY_SUFFIX.get(path.suffix, "other")


def build_inventory(root: Path) -> Inventory:
    """Walk root without following symlinks; enforce file, depth and count limits."""
    root = root.resolve()
    items: list[InventoryItem] = []
    skipped: list[tuple[str, str]] = []
    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        current = Path(dirpath)
        depth = len(current.relative_to(root).parts)
        if depth > MAX_DEPTH:
            skipped.append((str(current.relative_to(root)), "depth_limit"))
            dirnames[:] = []
            continue
        dirnames[:] = [d for d in dirnames if d != ".git"]
        for name in filenames:
            path = current / name
            rel = str(path.relative_to(root))
            if path.is_symlink():
                skipped.append((rel, "symlink_not_followed"))
                continue
            try:
                resolved = path.resolve(strict=True)
            except OSError:
                skipped.append((rel, "unresolvable"))
                continue
            if root not in resolved.parents and resolved != root:
                skipped.append((rel, "outside_root"))
                continue
            size = resolved.stat().st_size
            if size > MAX_FILE_BYTES:
                skipped.append((rel, "size_limit"))
                continue
            if len(items) >= MAX_FILES:
                skipped.append((rel, "file_count_limit"))
                continue
            items.append(InventoryItem(path=resolved, relative=rel, size=size, kind=classify(resolved)))
    return Inventory(items=tuple(sorted(items, key=lambda i: i.relative)), skipped=tuple(skipped))
