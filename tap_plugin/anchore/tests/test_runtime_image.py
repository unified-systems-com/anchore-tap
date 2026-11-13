"""The runtime image node, its edge, and the scope fields on the scan run (req-anchore-inventory-*, req-anchore-scope-14)."""

import json
from pathlib import Path

import pytest
import tap_plugin.computing_core.models as computing  # noqa: F401 — trigger model registration

import tap_plugin.anchore.models as anchore  # noqa: F401 — trigger model registration
from tap_grid.constraints import InvalidEdgeError
from tap_grid.models import Entity
from tap_grid.registry import get_model_class
from tap_grid.services import create_edge, create_node
from tap_plugin.anchore.tests.conftest import dimension_view

PLUGIN = Path(__file__).resolve().parents[1]
RUNTIME = "anchore__anchore_runtime_image"
RUN = "anchore__anchore_scan_run"
SCANNER_KEY = '["https://anchore.example/v2","acct"]'
DIGEST = "sha256:" + "a" * 64
OBSERVED = {"scanner_key": SCANNER_KEY, "inventory_type": "kubernetes", "context": "prod/default", "image_digest": DIGEST}


def _create(type_slug: str, payload: dict):
    result = create_node(type_slug, payload)
    assert result.success, f"create_node failed: {result.errors}"
    return get_model_class(type_slug).objects.get(entity=Entity.objects.get(pk=result.entity_id))


@pytest.mark.django_db
class TestRuntimeImage:
    def test_create_display_and_dimension(self):
        node = _create(RUNTIME, {**OBSERVED, "image_tag": "ghcr.io/o/web:1", "last_seen": "2026-11-09T11:00:00Z"})
        node.entity.refresh_from_db()
        assert node.entity.name == "ghcr.io/o/web:1 in prod/default"
        assert dimension_view(node.entity).get("anchore.area") == "runtime"
        assert node.last_seen is not None
        assert node.created_at is None and node.last_updated is None

    def test_name_falls_back_to_the_digest(self):
        assert _create(RUNTIME, OBSERVED).get_name() == f"{DIGEST} in prod/default"

    def test_keyed_by_scanner_type_context_and_digest_not_tag(self):
        model = get_model_class(RUNTIME)
        assert model.NATURAL_KEY == ("scanner_key", "inventory_type", "context", "image_digest")
        node = _create(RUNTIME, {**OBSERVED, "image_tag": "one"})
        assert model.find_existing(**OBSERVED).pk == node.pk
        assert model.find_existing(**{**OBSERVED, "context": "prod/other"}) is None

    @pytest.mark.parametrize("missing", ["scanner_key", "inventory_type", "context", "image_digest"])
    def test_key_fields_are_required(self, missing):
        payload = {k: v for k, v in OBSERVED.items() if k != missing}
        assert not create_node(RUNTIME, payload).success

    @pytest.mark.parametrize("bad", ["nginx:latest", "sha256:abc", "SHA256:" + "A" * 64, ""])
    def test_only_a_sha256_digest_is_a_key(self, bad):
        assert not create_node(RUNTIME, {**OBSERVED, "image_digest": bad}).success

    def test_it_has_an_icon(self):
        icon = get_model_class(RUNTIME).ENTITY_ICON
        assert (PLUGIN / "static" / "anchore" / "icons" / f"{icon}.svg").read_text().startswith("<svg")

    def test_observes_the_image_host_and_nothing_else(self):
        node = _create(RUNTIME, OBSERVED)
        image = _create("computing_core__host", {"realm": "oci-digest", "stable_id": DIGEST, "kind": "container"})
        assert create_edge(node.entity, image.entity, "OBSERVES_IMAGE__anchore") is not None
        with pytest.raises(InvalidEdgeError):
            create_edge(image.entity, node.entity, "OBSERVES_IMAGE__anchore")

    def test_the_edge_definition(self):
        definition = json.loads((PLUGIN / "edges" / "OBSERVES_IMAGE__anchore.edge.json").read_text())
        assert definition["sources"] == [RUNTIME]
        assert definition["targets"] == ["computing_core__host"]
        assert definition["identity"] == {"discriminators": []}
        assert definition["default_dimensions"] == {"anchore.area": "runtime"}


@pytest.mark.django_db
class TestRunScopeFields:
    def test_a_run_holds_its_settings_and_counts(self):
        settings = {"scope": {"running_only": True, "context_prefixes": ["prod/"]}, "inventory_max_age_hours": 24, "create": {"kubernetes": True, "ecs": False}, "limits": {"max_response_mib": 64, "max_run_minutes": None, "max_batch_rows": 5000}}
        run = _create(
            RUN,
            {
                "scanner_key": SCANNER_KEY,
                "run_id": "r1",
                "settings": settings,
                "images_listed": 40,
                "images_selected": 3,
                "images_out_of_scope": 37,
                "images_not_in_anchore": 1,
                "inventory_stale": 12,
            },
        )
        assert run.settings == settings
        assert (run.images_listed, run.images_selected, run.images_out_of_scope) == (40, 3, 37)
        assert (run.images_not_in_anchore, run.inventory_stale) == (1, 12)

    def test_they_are_null_until_a_run_gets_that_far(self):
        run = _create(RUN, {"scanner_key": SCANNER_KEY, "run_id": "r2"})
        assert run.settings is None
        assert run.images_listed is None and run.inventory_stale is None

    def test_a_negative_count_is_refused(self):
        assert not create_node(RUN, {"scanner_key": SCANNER_KEY, "run_id": "r3", "images_listed": -1}).success
