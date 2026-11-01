"""Compare two extracts, and list what changed outside the consumed set (req-anchore-drift-ci).

Standard library only, no I/O: the caller passes parsed documents.
"""

from typing import Any

MAX_REPORTED = 200


def _walk(a: Any, b: Any, where: str, out: list[str]) -> None:
    if len(out) >= MAX_REPORTED:
        return
    if isinstance(a, dict) and isinstance(b, dict):
        for key in sorted(set(a) | set(b)):
            if key not in b:
                out.append(f"{where}/{key}: removed")
            elif key not in a:
                out.append(f"{where}/{key}: added")
            else:
                _walk(a[key], b[key], f"{where}/{key}", out)
    elif isinstance(a, list) and isinstance(b, list) and len(a) == len(b):
        for index, (x, y) in enumerate(zip(a, b, strict=True)):
            _walk(x, y, f"{where}[{index}]", out)
    elif a != b:
        out.append(f"{where}: changed")


def diff_extracts(committed: dict[str, Any], fresh: dict[str, Any]) -> list[str]:
    """Differences in what the plugin consumes. The ``source`` block is compared separately."""
    out: list[str] = []
    old = {(op["method"], op["path"]): op for op in committed["operations"]}
    new = {(op["method"], op["path"]): op for op in fresh["operations"]}
    for key in sorted(set(old) | set(new)):
        label = f"{key[0].upper()} {key[1]}"
        if key not in new:
            out.append(f"{label}: dropped from the extract")
        elif key not in old:
            out.append(f"{label}: new in the extract")
        else:
            _walk(old[key], new[key], label, out)
    return out


def operation_keys(doc: dict[str, Any]) -> set[tuple[str, str]]:
    """Every (method, path) the document declares."""
    keys: set[tuple[str, str]] = set()
    paths = doc.get("paths") if isinstance(doc.get("paths"), dict) else {}
    for path, item in paths.items():
        if isinstance(item, dict):
            keys.update((m, path) for m in item if m in ("get", "put", "post", "delete", "patch", "head", "options"))
    return keys


def other_changes(baseline: dict[str, Any], fresh: dict[str, Any], consumed: set[tuple[str, str]]) -> list[str]:
    """Operations added or removed outside the consumed set, plus a version change."""
    out: list[str] = []
    old_v = (baseline.get("info") or {}).get("version")
    new_v = (fresh.get("info") or {}).get("version")
    if old_v != new_v:
        out.append(f"version: {old_v} -> {new_v}")
    before, after = operation_keys(baseline), operation_keys(fresh)
    out.extend(f"{m.upper()} {p}: added upstream" for m, p in sorted(after - before - consumed))
    out.extend(f"{m.upper()} {p}: removed upstream" for m, p in sorted(before - after - consumed))
    return out[:MAX_REPORTED]
