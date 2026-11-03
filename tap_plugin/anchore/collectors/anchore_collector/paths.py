"""Resolve a manifest field path against a reduced response schema.

A path is dotted. ``name[]`` means the items of the array ``name``, and a path may begin with ``[]``
for a response that is itself an array: ``items[].image_digest``, ``[].dataset_name``. Schemas in
the extract may combine members with ``allOf`` (the vulnerability record does), so a node's
properties are the union of its members'. Standard library only, no I/O.
"""

from typing import Any


def _properties(node: dict[str, Any]) -> dict[str, Any]:
    """The node's properties; allOf members are an intersection, so a property that more than one
    member (or the node itself) constrains keeps every definition, as an ``allOf`` of them."""
    found: dict[str, list[Any]] = {name: [schema] for name, schema in (node.get("properties") or {}).items()}
    for member in node.get("allOf") or []:
        if isinstance(member, dict):
            for name, schema in _properties(member).items():
                found.setdefault(name, []).append(schema)
    return {name: defs[0] if len(defs) == 1 else {"allOf": defs} for name, defs in found.items()}


def _items(node: dict[str, Any]) -> dict[str, Any] | None:
    items = node.get("items")
    if isinstance(items, dict):
        return items
    for member in node.get("allOf") or []:
        if isinstance(member, dict) and isinstance(member.get("items"), dict):
            return member["items"]
    return None


def resolve_chain(schema: dict[str, Any], path: str) -> list[dict[str, Any]] | None:
    """Every schema node the path passes through, the root first and the field last, or None.

    A change to a container on the way (an array that may now be null) breaks a reader of the
    field as surely as a change to the field itself, so the self-test compares the whole chain.
    """
    node: dict[str, Any] | None = schema
    chain: list[dict[str, Any]] = [schema]
    for segment in path.split("."):
        if node is None:
            return None
        name, descend = (segment[:-2], True) if segment.endswith("[]") else (segment, False)
        if name:
            nxt = _properties(node).get(name)
            node = nxt if isinstance(nxt, dict) else None
            if node is None:
                return None
            chain.append(node)
        if descend:
            node = _items(node)
            if node is None:
                return None
            chain.append(node)
    return chain


def resolve_field(schema: dict[str, Any], path: str) -> dict[str, Any] | None:
    """The schema node at ``path``, or None when the path is not there."""
    chain = resolve_chain(schema, path)
    return chain[-1] if chain else None


def type_of(node: dict[str, Any]) -> tuple[str, ...]:
    """The node's JSON types as a sorted tuple (a nullable type lists both), plus a signature for
    each ``allOf`` member, so a change in any member changes the result."""
    declared = node.get("type")
    own: tuple[str, ...] = ()
    if isinstance(declared, list):
        own = tuple(sorted(str(t) for t in declared))
    elif isinstance(declared, str):
        own = (declared,)
    members = tuple(
        f"allOf:{'/'.join(type_of(m)) or 'untyped'}" for m in (node.get("allOf") or []) if isinstance(m, dict)
    )
    return own + members


def enum_of(node: dict[str, Any]) -> frozenset[Any] | None:
    values = node.get("enum")
    return frozenset(values) if isinstance(values, list) else None
