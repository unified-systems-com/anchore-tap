"""Every dimension key this plugin declares has a Dimension node (unified-systems-com/tap#711).

Dimension nodes are declared, never minted on the fly: a key with no node is refused once the
dimension map keys by node id. The expected keys are read from the models and the edge
definitions, so a key added to either without a node fails here.
"""

import json
import re
from pathlib import Path

import pytest

import tap_plugin.anchore.models as anchore
from tap_plugin.anchore.collectors.anchore_collector.decompose import INSTANCE_DIMENSION

ROOT = Path(__file__).resolve().parent.parent
SEED = ROOT / "grift" / "dimension.grift.json"
#: The id other plugins and the core migration know this key's node by; it must never change.
AREA_ID = "01a1d10b-e806-75e5-96bd-ccb5fc917d18"
INSTANCE_ID = "01a1d123-7220-76d4-951d-42397e4837aa"


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
    """The keys the types declare, and the one the collector stamps per node."""
    assert set(_declared()) == {"anchore.area"}
    assert {n["node"]["name"] for n in _dimension_nodes()} == set(_declared()) | {INSTANCE_DIMENSION}


def test_the_node_has_its_fixed_id_and_names_every_value_in_use() -> None:
    nodes = {n["node"]["name"]: n for n in _dimension_nodes()}
    for each in nodes.values():
        assert each["entity"]["name"] == each["node"]["name"]
        assert each["entity"]["dimensions"] == {"tap.meta": "dimension"}
        assert each["entity"]["entity_id"] and each["node"]["description"].strip()
    assert len({n["entity"]["entity_id"] for n in nodes.values()}) == len(nodes)
    node = nodes["anchore.area"]
    assert node["entity"]["entity_id"] == AREA_ID
    assert nodes[INSTANCE_DIMENSION]["entity"]["entity_id"] == INSTANCE_ID
    # Whole words, so "runtime" does not stand in for "run".
    described = set(re.findall(r"[a-z_]+", node["node"]["description"]))
    assert _declared()["anchore.area"] <= described, described


def test_the_seed_is_registered_in_the_manifest() -> None:
    import tomllib

    manifest = tomllib.loads((ROOT / "tap-plugin.toml").read_text(encoding="utf-8"))
    assert manifest["grift"] == {"dimension": "grift/dimension.grift.json"}


class TestInstanceDimension:
    """req-anchore-dimensions-2: every Anchore-owned node says which instance and account it came from."""

    def test_an_own_node_carries_its_scanner_key_as_the_instance(self):
        from tap_plugin.anchore.collectors.anchore_collector import decompose
        from tap_plugin.anchore.models.finding import AnchoreFinding

        node = decompose.envelope("r", AnchoreFinding, "n", {"scanner_key": '["https://anchore.example/v2","acct"]'})
        assert node["entity"]["dimensions"] == {"anchore.area": "finding", "anchore.instance": '["https://anchore.example/v2","acct"]'}

    @pytest.mark.parametrize("fields", [{}, {"scanner_key": ""}, {"scanner_key": None}, {"scanner_key": 7}])
    def test_an_own_node_with_no_scanner_key_is_refused_not_written_unscoped(self, fields):
        from tap_plugin.anchore.collectors.anchore_collector import decompose
        from tap_plugin.anchore.models.finding import AnchoreFinding

        with pytest.raises(ValueError, match="scanner_key"):
            decompose.envelope("r", AnchoreFinding, "n", fields)

    def test_every_own_type_is_keyed_under_a_scanner_key(self):
        """What makes the refusal safe: no own type exists that could lack one."""
        for name in anchore.__all__:
            model = getattr(anchore, name)
            assert model.ENTITY_TYPE.startswith("anchore__") and "scanner_key" in model.NATURAL_KEY, name

    def test_a_shared_type_built_by_the_same_function_is_not_stamped_even_with_a_scanner_key(self):
        """Ownership decides, not the presence of a field."""
        from tap_plugin.computing_core.models.host import Host

        from tap_plugin.anchore.collectors.anchore_collector import decompose

        node = decompose.envelope("r", Host, "n", {"scanner_key": "x"})
        assert INSTANCE_DIMENSION not in node["entity"]["dimensions"]

    def test_a_node_of_a_shared_type_never_carries_it(self):
        from tap_plugin.anchore.collectors.anchore_collector import decompose

        digest = "sha256:" + "a" * 64
        assert INSTANCE_DIMENSION not in decompose.host_node("r", digest)["entity"]["dimensions"]
        assert INSTANCE_DIMENSION not in decompose.typed_node("r", "computing_core__kubernetes_pod", "p", {"uid": "u"}, {"tap.computing": "runtime"})["entity"]["dimensions"]
