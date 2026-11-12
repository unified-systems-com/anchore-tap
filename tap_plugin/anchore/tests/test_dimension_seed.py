"""Every dimension key this plugin declares has a Dimension node (unified-systems-com/tap#711).

Dimension nodes are declared, never minted on the fly: a key with no node is refused once the
dimension map keys by node id. The expected keys are read from the models and the edge
definitions, so a key added to either without a node fails here.
"""

import json
import re
from pathlib import Path

import tap_plugin.anchore.models as anchore

ROOT = Path(__file__).resolve().parent.parent
SEED = ROOT / "grift" / "dimension.grift.json"
#: The id other plugins and the core migration know this key's node by; it must never change.
AREA_ID = "01a1d10b-e806-75e5-96bd-ccb5fc917d18"


def _dimension_nodes() -> list[dict]:
    doc = json.loads(SEED.read_text(encoding="utf-8"))
    return [n for batch in doc["batches"] for n in batch["nodes"] if n["entity"]["entity_type"] == "dimension"]


def _declared() -> dict[str, set[str]]:
    """Every dimension key the plugin's own models and edges stamp, with the values used."""
    found: dict[str, set[str]] = {}
    sources = [getattr(anchore, name).DEFAULT_DIMENSIONS for name in anchore.__all__]
    sources += [json.loads(path.read_text(encoding="utf-8")).get("default_dimensions", {}) for path in sorted((ROOT / "edges").glob("*.edge.json"))]
    for dimensions in sources:
        for key, value in dimensions.items():
            found.setdefault(key, set()).add(value)
    return found


def test_every_declared_key_has_a_dimension_node() -> None:
    assert {n["node"]["name"] for n in _dimension_nodes()} == set(_declared()) == {"anchore.area"}


def test_the_node_has_its_fixed_id_and_names_every_value_in_use() -> None:
    (node,) = _dimension_nodes()
    assert node["entity"]["entity_id"] == AREA_ID
    assert node["entity"]["name"] == node["node"]["name"]
    assert node["entity"]["dimensions"] == {"tap.meta": "dimension"}
    # Whole words, so "runtime" does not stand in for "run".
    described = set(re.findall(r"[a-z_]+", node["node"]["description"]))
    assert _declared()["anchore.area"] <= described, described


def test_the_seed_is_registered_in_the_manifest() -> None:
    import tomllib

    manifest = tomllib.loads((ROOT / "tap-plugin.toml").read_text(encoding="utf-8"))
    assert manifest["grift"] == {"dimension": "grift/dimension.grift.json"}
