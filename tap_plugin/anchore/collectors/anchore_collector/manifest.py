"""Load the collector manifest and hold it against the committed extract (req-anchore-scope-walk-3).

The manifest is data: ``manifest.json`` says what the collector reads, ``manifest.schema.json``
says what a manifest may say. A manifest that breaks its schema, names a path the extract does not
carry, or lists a field the extract's response schema does not have raises ``ManifestError`` at
load, so a typo cannot become a source that silently reads nothing.
"""

import json
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path
from typing import Any

import jsonschema

from tap_plugin.anchore.collectors.anchore_collector.paths import resolve_field

_HERE = Path(__file__).resolve().parent
_EXTRACT = _HERE.parents[1] / "contract" / "extract.json"


class ManifestError(ValueError):
    """The manifest is invalid, or disagrees with the committed extract."""


@dataclass(frozen=True)
class Source:
    id: str
    path: str
    scope: str
    required: bool
    required_fields: tuple[str, ...]
    optional_fields: tuple[str, ...]


def _response_schema(extract: dict[str, Any], path: str) -> dict[str, Any] | None:
    for op in extract["operations"]:
        if op["method"] == "get" and op["path"] == path:
            for response in op.get("responses", []):
                if str(response.get("status", "")).startswith("2"):
                    schema = response.get("schema")
                    return schema if isinstance(schema, dict) else None
    return None


def load_manifest(manifest: dict[str, Any] | None = None, extract: dict[str, Any] | None = None) -> tuple[Source, ...]:
    """Validate a manifest (the shipped one by default) and return its sources.

    Both arguments exist so a test can hand in a broken document; production calls take neither.
    """
    document = manifest if manifest is not None else json.loads((_HERE / "manifest.json").read_text(encoding="utf-8"))
    schema = json.loads((_HERE / "manifest.schema.json").read_text(encoding="utf-8"))
    try:
        jsonschema.validate(document, schema)
    except jsonschema.ValidationError as exc:
        raise ManifestError(f"manifest does not match its schema: {exc.message}") from None
    committed = extract if extract is not None else json.loads(_EXTRACT.read_text(encoding="utf-8"))
    sources: list[Source] = []
    seen: set[str] = set()
    for entry in document["sources"]:
        if entry["id"] in seen:
            raise ManifestError(f"source id {entry['id']!r} appears twice")
        seen.add(entry["id"])
        response = _response_schema(committed, entry["path"])
        if response is None:
            raise ManifestError(f"source {entry['id']!r}: GET {entry['path']} has no 2xx response in the committed extract")
        for field in (*entry["required_fields"], *entry["optional_fields"]):
            if resolve_field(response, field) is None:
                raise ManifestError(f"source {entry['id']!r}: field {field!r} is not in the extract's response for GET {entry['path']}")
        sources.append(
            Source(
                id=entry["id"],
                path=entry["path"],
                scope=entry["scope"],
                required=entry["required"],
                required_fields=tuple(entry["required_fields"]),
                optional_fields=tuple(entry["optional_fields"]),
            )
        )
    return tuple(sources)


@lru_cache(maxsize=1)
def shipped_manifest() -> tuple[Source, ...]:
    return load_manifest()
