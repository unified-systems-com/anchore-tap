"""Split one run's rows into several GRIFT batches (req-anchore-limits-7).

Pure: no grid, no request, no Django. A batch is applied whole or not at all, so one very large
batch makes a whole run depend on a single write. Splitting bounds each write. A batch's refs are
local to it, so an edge that would point across batches is rewritten to name its ends by natural
key, which resolves against what an earlier batch already wrote. Node batches therefore come
first and edge batches after.
"""

from collections.abc import Callable, Mapping
from typing import Any

Row = dict[str, Any]
#: A node's ``{"entity_type": ..., "key": {...}}``, or None when its natural key cannot be stated.
KeyOf = Callable[[Row], Mapping[str, Any] | None]


def _chunks(rows: list[Row], size: int) -> list[list[Row]]:
    return [rows[start : start + size] for start in range(0, len(rows), size)]


def split(nodes: list[Row], edges: list[Row], max_rows: int, key_of: KeyOf) -> tuple[list[tuple[list[Row], list[Row]]], str | None]:
    """(the batches as ``(nodes, edges)`` pairs in the order to apply them, why it was not split or None).

    One batch when everything fits in ``max_rows``. Otherwise the nodes in batches of ``max_rows``,
    then the edges in batches of ``max_rows`` with every ref replaced by its node's natural key. If
    any ref an edge uses names a node whose key cannot be stated, nothing is split and the reason is
    returned: a run that cannot be split safely is written as it always was.
    """
    if max_rows <= 0 or len(nodes) + len(edges) <= max_rows:
        return [(nodes, edges)], None
    keys: dict[str, Mapping[str, Any]] = {}
    for node in nodes:
        ref = node.get("entity", {}).get("ref")
        key = key_of(node)
        if isinstance(ref, str) and key is not None:
            keys[ref] = key
    rewritten: list[Row] = []
    for edge in edges:
        body = dict(edge["edge"])
        for end in ("from", "to"):
            ref = body.get(f"{end}_ref")
            if ref is None:
                continue
            if ref not in keys:
                return [(nodes, edges)], f"an edge names a node ({str(ref)[:80]}) whose natural key cannot be stated"
            del body[f"{end}_ref"]
            body[f"{end}_key"] = dict(keys[ref])
        rewritten.append({**edge, "edge": body})
    return [(chunk, []) for chunk in _chunks(nodes, max_rows)] + [([], chunk) for chunk in _chunks(rewritten, max_rows)], None
