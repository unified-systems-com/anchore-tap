"""Key field names are read from the owning type, never written out (req-anchore-shared-13)."""

import re
from pathlib import Path

import pytest

import tap_plugin.anchore
from tap_plugin.anchore import keys


def model(*key, entity_type="x__thing"):
    return type("Fake", (), {"NATURAL_KEY": tuple(key), "ENTITY_TYPE": entity_type})


class TestSchemeField:
    def test_todays_host_key(self):
        assert keys.scheme_field(model("realm", "stable_id")) == "realm"

    def test_the_renamed_host_key(self):
        assert keys.scheme_field(model("host_id_scheme", "stable_id")) == "host_id_scheme"

    def test_it_is_chosen_by_role_not_position(self):
        assert keys.scheme_field(model("stable_id", "cluster_id_scheme")) == "cluster_id_scheme"

    @pytest.mark.parametrize("key", [("realm",), ("a", "b", "stable_id"), ("stable_id",), ()])
    def test_a_key_of_another_shape_is_refused_not_guessed(self, key):
        with pytest.raises(keys.KeyShapeError, match="x__thing"):
            keys.scheme_field(model(*key))

    def test_a_type_with_no_key_is_refused(self):
        with pytest.raises(keys.KeyShapeError):
            keys.scheme_field(type("Keyless", (), {"NATURAL_KEY": None, "ENTITY_TYPE": "x__keyless"}))


class TestSoleField:
    @pytest.mark.parametrize("name", ["task_arn", "arn"])
    def test_the_one_field_before_and_after_the_rename(self, name):
        assert keys.sole_field(model(name)) == name

    def test_a_compound_key_is_refused(self):
        with pytest.raises(keys.KeyShapeError):
            keys.sole_field(model("account", "arn"))


class TestInstalledTypes:
    """Against the types installed here, whatever their fields are called today."""

    @pytest.mark.django_db
    def test_host_and_cluster_and_ecs_keys_resolve(self):
        from tap_grid.registry import get_model_class
        from tap_plugin.anchore.collectors.anchore_collector import decompose, store

        host = get_model_class("computing_core__host")
        digest = "sha256:" + "a" * 64
        assert set(decompose.host_key(digest)) == set(host.NATURAL_KEY)
        assert store.scheme_field("computing_core__kubernetes_cluster") in get_model_class("computing_core__kubernetes_cluster").NATURAL_KEY
        for kind, entity_type in store.ECS_TYPES.items():
            assert (store.ecs_key(kind),) == get_model_class(entity_type).NATURAL_KEY


def test_no_source_file_writes_out_a_foreign_key_field_name():
    """The ratchet: a host's or cluster's scheme field, and an ECS type's own ARN field, appear nowhere as literals."""
    root = Path(tap_plugin.anchore.__file__).parent
    literal = re.compile(r"""["']realm["']|\brealm=|["'](container|task|service|cluster)_arn["']\s*[:\]]\s*arn\b|_arn__in""")
    found = [
        f"{path.relative_to(root)}:{number}"
        for path in sorted(root.rglob("*.py"))
        if "tests" not in path.parts and "migrations" not in path.parts
        for number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1)
        if literal.search(line)
    ]
    assert found == []
