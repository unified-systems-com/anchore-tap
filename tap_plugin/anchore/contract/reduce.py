"""Reduce an OpenAPI document to the part of it this plugin consumes (req-anchore-contract-extract).

One reducer builds the committed extract, the scheduled drift comparison and the per-run
self-test, so a difference is never an artifact of two code paths (req-anchore-selftest-5).

The input is a document supplied by a host this plugin does not control (the vendor's published
file, an instance's own spec), so this module is bounded and does no I/O of its own: it takes
bytes or an already parsed dict, resolves only local ``#/...`` references, rejects any other
``$ref``, refuses a document over a fixed size or nesting depth or one that expands past a node
budget, replaces a reference cycle with a marker instead of following it, and never opens a file
or a socket. It imports only the standard library so it runs without the grid.
"""

import copy
import json
from typing import Any

MAX_DOCUMENT_BYTES = 16 * 1024 * 1024
MAX_DEPTH = 64
MAX_NODES = 2_000_000

# Keys that change what a client may send or receive. Documentation-only keys (description,
# title, example, externalDocs and x-* vendor notes) are dropped so a reworded sentence in the
# vendor's file is not drift.
_SCHEMA_KEYS = (
    "type",
    "format",
    "enum",
    "nullable",
    "required",
    "pattern",
    "minimum",
    "maximum",
    "minLength",
    "maxLength",
    "minItems",
    "maxItems",
    "additionalProperties",
    "default",
    "const",
    "exclusiveMinimum",
    "exclusiveMaximum",
    "multipleOf",
    "uniqueItems",
)
_SCHEMA_LIST_KEYS = ("allOf", "anyOf", "oneOf")
_METHODS = ("get", "put", "post", "delete", "patch", "head", "options")


class ReducerError(ValueError):
    """The document is not one this reducer will read."""


def load_document(raw: bytes) -> dict[str, Any]:
    """Parse JSON bytes under the size and nesting limits."""
    if len(raw) > MAX_DOCUMENT_BYTES:
        raise ReducerError(f"document is {len(raw)} bytes, over the {MAX_DOCUMENT_BYTES} limit")
    try:
        doc = json.loads(raw)
    except RecursionError as exc:
        raise ReducerError("document nesting is too deep to parse") from exc
    except ValueError as exc:
        raise ReducerError(f"document is not valid JSON: {exc}") from exc
    if not isinstance(doc, dict):
        raise ReducerError("document root is not an object")
    _check_depth(doc)
    return doc


def _check_depth(root: Any) -> None:
    stack: list[tuple[Any, int]] = [(root, 0)]
    while stack:
        node, depth = stack.pop()
        if depth > MAX_DEPTH:
            raise ReducerError(f"document nesting exceeds {MAX_DEPTH}")
        if isinstance(node, dict):
            stack.extend((v, depth + 1) for v in node.values())
        elif isinstance(node, list):
            stack.extend((v, depth + 1) for v in node)


class _Resolver:
    def __init__(self, doc: dict[str, Any]) -> None:
        self.doc = doc
        self.nodes = 0
        self._memo: dict[str, tuple[Any, bool, int]] = {}

    def _tick(self, count: int = 1) -> None:
        self.nodes += count
        if self.nodes > MAX_NODES:
            raise ReducerError(f"document expands past {MAX_NODES} nodes")

    def _size(self, value: Any) -> int:
        """Count the JSON values in ``value``, stopping once the budget is clearly spent."""
        count = 0
        stack = [value]
        while stack:
            node = stack.pop()
            count += 1
            if count > MAX_NODES:
                raise ReducerError(f"document expands past {MAX_NODES} nodes")
            if isinstance(node, dict):
                stack.extend(node.values())
            elif isinstance(node, list):
                stack.extend(node)
        return count

    def lookup(self, ref: Any) -> Any:
        if not isinstance(ref, str) or not ref.startswith("#/"):
            raise ReducerError(f"only local '#/...' references are resolved, got {ref!r}")
        node: Any = self.doc
        for part in ref[2:].split("/"):
            part = part.replace("~1", "/").replace("~0", "~")
            if not isinstance(node, dict) or part not in node:
                raise ReducerError(f"reference {ref!r} does not resolve")
            node = node[part]
        return node

    def schema(self, node: Any, stack: tuple[str, ...], depth: int = 0) -> tuple[Any, bool]:
        """Resolve a schema node; the flag says whether a cycle marker is inside the result."""
        self._tick()
        if depth > MAX_DEPTH:
            raise ReducerError(f"schema nesting exceeds {MAX_DEPTH}")
        if not isinstance(node, dict):
            return None, False
        if "$ref" in node:
            ref = node["$ref"]
            if ref in stack:
                return {"$recursive": ref}, True
            if ref in self._memo:
                # A cached subtree still appears in the output once more, so it is charged
                # what it cost the first time; otherwise many operations naming one large
                # schema would expand far past the budget.
                resolved, cyclic, size = self._memo[ref]
                self._tick(size)
                return resolved, cyclic
            before = self.nodes
            resolved, cyclic = self.schema(self.lookup(ref), stack + (ref,), depth + 1)
            if not cyclic:
                self._memo[ref] = (resolved, cyclic, self.nodes - before)
            return resolved, cyclic
        out: dict[str, Any] = {}
        cyclic = False
        for key in _SCHEMA_KEYS:
            if key in node:
                value = node[key]
                if key == "additionalProperties" and isinstance(value, dict):
                    value, inner = self.schema(value, stack, depth + 1)
                    cyclic = cyclic or inner
                else:
                    # A kept value (an enum, a default) appears in the output as it stands, so
                    # it is charged by what it holds, not as one node.
                    self._tick(self._size(value) - 1)
                out[key] = value
        if isinstance(node.get("properties"), dict):
            props: dict[str, Any] = {}
            for name in sorted(node["properties"]):
                props[name], inner = self.schema(node["properties"][name], stack, depth + 1)
                cyclic = cyclic or inner
            out["properties"] = props
        if "items" in node:
            out["items"], inner = self.schema(node["items"], stack, depth + 1)
            cyclic = cyclic or inner
        for key in _SCHEMA_LIST_KEYS:
            if isinstance(node.get(key), list):
                members = []
                for member in node[key]:
                    resolved, inner = self.schema(member, stack, depth + 1)
                    members.append(resolved)
                    cyclic = cyclic or inner
                out[key] = members
        return out, cyclic

    def parameter(self, node: Any) -> dict[str, Any] | None:
        self._tick()
        if isinstance(node, dict) and "$ref" in node:
            node = self.lookup(node["$ref"])
        if not isinstance(node, dict):
            return None
        schema, _ = self.schema(node.get("schema", {}), ())
        return {
            "name": node.get("name"),
            "in": node.get("in"),
            "required": bool(node.get("required", False)),
            "schema": schema,
        }

    def responses(self, node: Any) -> list[dict[str, Any]]:
        out: list[dict[str, Any]] = []
        if not isinstance(node, dict):
            return out
        for status in sorted(node):
            if not str(status).startswith("2"):
                continue
            response = node[status]
            if isinstance(response, dict) and "$ref" in response:
                response = self.lookup(response["$ref"])
            content = response.get("content") if isinstance(response, dict) else None
            if not isinstance(content, dict) or not content:
                out.append({"status": str(status), "content_type": None, "schema": None})
                continue
            for content_type in sorted(content):
                body = content[content_type]
                schema = None
                if isinstance(body, dict) and "schema" in body:
                    schema, _ = self.schema(body["schema"], ())
                out.append({"status": str(status), "content_type": content_type, "schema": schema})
        return out


def _step(schema: Any, name: str) -> Any:
    """The schema of property ``name`` of an object schema, looked for in its own properties and
    then in the members of its ``allOf`` / ``anyOf`` / ``oneOf``; None when it has none."""
    if not isinstance(schema, dict):
        return None
    props = schema.get("properties")
    if isinstance(props, dict) and name in props:
        return props[name]
    for key in _SCHEMA_LIST_KEYS:
        for member in schema.get(key) or []:
            found = _step(member, name)
            if found is not None:
                return found
    return None


def _owner(schema: Any, name: str) -> Any:
    """The object schema that itself declares property ``name`` (the one whose ``required`` governs it)."""
    if not isinstance(schema, dict):
        return None
    if isinstance(schema.get("properties"), dict) and name in schema["properties"]:
        return schema
    for key in _SCHEMA_LIST_KEYS:
        for member in schema.get(key) or []:
            found = _owner(member, name)
            if found is not None:
                return found
    return None


def _walk_to(schema: Any, path: str) -> tuple[Any, str]:
    """(the object schema holding the last segment, that segment's name) for a path such as
    ``items[].image_content.metadata.arch``; ``[]`` after a name, or alone, steps into array items."""
    segments = path.split(".")
    node = schema
    for index, segment in enumerate(segments):
        name, into_items = (segment[:-2], True) if segment.endswith("[]") else (segment, False)
        last = index == len(segments) - 1
        if last and not into_items:
            return node, name
        if name:
            node = _step(node, name)
        if into_items:
            node = node.get("items") if isinstance(node, dict) else None
        if not isinstance(node, dict):
            raise ReducerError(f"observed path {path!r} does not resolve at {segment!r}")
    raise ReducerError(f"observed path {path!r} names no field")


def apply_observed(schema: Any, observed: dict[str, Any], where: str) -> Any:
    """A copy of a response schema with the differences a real instance was seen to have (req-anchore-contract-extract-5).

    ``nullable``: field paths the instance returns as null although the vendor's file declares a
    type; each gains ``nullable: true``. ``either``: ``[path, other name]`` pairs, where the
    instance returns the field under the other name; the declared field stops being required on
    its own, the other name is declared with the same schema, and one of the two is required.
    A path that does not resolve is an error, so an override cannot outlive the field it names.
    """
    out = copy.deepcopy(schema)
    for path in observed.get("nullable", []):
        parent, name = _walk_to(out, path)
        target = _step(parent, name)
        if not isinstance(target, dict):
            raise ReducerError(f"{where}: observed nullable path {path!r} does not resolve")
        target["nullable"] = True
    for path, other in observed.get("either", []):
        parent, name = _walk_to(out, path)
        owner = _owner(parent, name)
        if owner is None:
            raise ReducerError(f"{where}: observed either path {path!r} does not resolve")
        owner["properties"].setdefault(other, copy.deepcopy(owner["properties"][name]))
        if name in owner.get("required", []):
            owner["required"] = [r for r in owner["required"] if r != name]
            owner.setdefault("anyOf", []).extend([{"required": [name]}, {"required": [other]}])
    return out


def reduce_document(doc: dict[str, Any], consumed: dict[str, Any]) -> dict[str, Any]:
    """Build the extract for the operations ``consumed`` names.

    An operation the document no longer has is kept with ``present: false`` so its absence is a
    difference, not a silent omission.
    """
    paths = doc.get("paths")
    if not isinstance(paths, dict):
        raise ReducerError("document has no 'paths' object")
    resolver = _Resolver(doc)
    info = doc.get("info") if isinstance(doc.get("info"), dict) else {}
    operations: list[dict[str, Any]] = []
    for entry in consumed["operations"]:
        method, path = entry["method"], entry["path"]
        item = paths.get(path)
        op = item.get(method) if isinstance(item, dict) and method in _METHODS else None
        record: dict[str, Any] = {"description": entry["description"], "method": method, "path": path}
        if not isinstance(op, dict):
            record["present"] = False
            operations.append(record)
            continue
        raw_params = list(item.get("parameters", [])) + list(op.get("parameters", []))
        params = [p for p in (resolver.parameter(raw) for raw in raw_params) if p is not None]
        params.sort(key=lambda p: (str(p["in"]), str(p["name"])))
        record["present"] = True
        record["operation_id"] = op.get("operationId")
        record["parameters"] = params
        record["responses"] = resolver.responses(op.get("responses"))
        if entry.get("never_request"):
            record["never_request"] = entry["never_request"]
        if entry.get("observed"):
            # What a real instance was seen to return that the vendor's file does not describe. The
            # extract carries the list, so a reader of it sees which lines are the vendor's and which are not.
            record["observed"] = entry["observed"]
            for response in record["responses"]:
                if str(response["status"]).startswith("2"):
                    response["schema"] = apply_observed(response["schema"], entry["observed"], f"{method} {path}")
        operations.append(record)
    return {
        "description": (
            "The part of Anchore's OpenAPI file this plugin consumes, generated by "
            "tap_plugin/anchore/contract/reduce.py from the committed source copy. "
            "Never edited by hand: regenerate it with tap_plugin.anchore.contract.build."
        ),
        "source": {"openapi": doc.get("openapi"), "title": info.get("title"), "version": info.get("version")},
        "operations": operations,
    }
