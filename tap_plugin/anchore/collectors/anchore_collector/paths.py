"""Resolve a manifest field path against a reduced response schema.

A path is dotted. ``name[]`` means the items of the array ``name``, and a path may begin with ``[]``
for a response that is itself an array: ``items[].image_digest``, ``[].dataset_name``. Schemas in
the extract may combine members with ``allOf`` (the vulnerability record does), so a node's
properties are the union of its members'. Standard library only, no I/O.
"""

from typing import Any


def _properties(node: dict[str, Any]) -> dict[str, Any]:
    props: dict[str, Any] = dict(node.get("properties") or {})
    for member in node.get("allOf") or []:
        if isinstance(member, dict):
            props.update(_properties(member))
    return props


def _items(node: dict[str, Any]) -> dict[str, Any] | None:
    items = node.get("items")
    if isinstance(items, dict):
        return items
    for member in node.get("allOf") or []:
        if isinstance(member, dict) and isinstance(member.get("items"), dict):
            return member["items"]
    return None


def resolve_field(schema: dict[str, Any], path: str) -> dict[str, Any] | None:
    """The schema node at ``path``, or None when the path is not there."""
    node: dict[str, Any] | None = schema
    for segment in path.split("."):
        if node is None:
            return None
        name, descend = (segment[:-2], True) if segment.endswith("[]") else (segment, False)
        if name:
            nxt = _properties(node).get(name)
            node = nxt if isinstance(nxt, dict) else None
            if node is None:
                return None
        if descend:
            node = _items(node)
            if node is None:
                return None
    return node


def type_of(node: dict[str, Any]) -> tuple[str, ...]:
    """The node's JSON types as a sorted tuple (a nullable type lists both)."""
    declared = node.get("type")
    if isinstance(declared, list):
        return tuple(sorted(str(t) for t in declared))
    if isinstance(declared, str):
        return (declared,)
    return ()


def enum_of(node: dict[str, Any]) -> frozenset[Any] | None:
    values = node.get("enum")
    return frozenset(values) if isinstance(values, list) else None
