"""The image's generic facts and its tags go into computing_core's types (req-anchore-image-5, -6)."""

import pytest
import tap_plugin.anchore.models as anchore  # noqa: F401 — trigger model registration
import tap_plugin.compliance_core.models as compliance  # noqa: F401 — trigger model registration
import tap_plugin.computing_core.models as computing  # noqa: F401 — trigger model registration
from tap_plugin.computing_core.models.host import Host

from tap_grid.models import Edge
from tap_grid.registry import get_model_class
from tap_grid.services import create_node
from tap_plugin.anchore.collectors.anchore_collector import decompose
from tap_plugin.anchore.tests.test_collector_run import DIGEST, OTHER, Instance, no_sockets, run_against, secrets  # noqa: F401 — fixtures
from tap_plugin.anchore.tests.test_collector_scope import configure

TAG_TYPE = "computing_core__image_tag"
IMAGE = {
    "image_digest": DIGEST,
    "analysis_status": "analyzed",
    "image_detail": [
        {"registry": "registry.example", "repo": "app", "tag": "1.4", "full_tag": "registry.example/app:1.4", "tag_detected_at": "2026-11-10T12:00:00Z"},
        {"registry": "registry.example", "repo": "app", "tag": "latest", "full_tag": "registry.example/app:latest"},
        {"registry": "docker.io", "repo": "mirror/app", "tag": "1.4", "full_tag": "docker.io/mirror/app:1.4"},
    ],
    "image_content": {"metadata": {"arch": "amd64", "distro": "debian", "distro_version": "12", "image_size": 123456789012, "layer_count": 7}},
}


def host(digest: str = DIGEST) -> Host:
    return Host.objects.get(realm="oci-digest", stable_id=digest)


def tags() -> dict[str, object]:
    return {t.get_name(): t for t in get_model_class(TAG_TYPE).objects.all()}


def tag_edges() -> dict[str, dict]:
    return {e.from_entity.name: e.properties for e in Edge.objects.filter(edge_type="TAGS_IMAGE__computing_core").select_related("from_entity")}


@pytest.mark.django_db
class TestFacts:
    def test_a_host_this_run_creates_carries_the_images_architecture_size_and_layers(self, secrets, monkeypatch):
        run_against(monkeypatch, Instance(images=[IMAGE]))
        assert (host().architecture, host().image_size_bytes, host().image_layer_count) == ("amd64", 123456789012, 7)
        # Anchore's record has no build time for the image, so none is written.
        assert host().image_built_at is None

    def test_a_host_the_grid_holds_gets_only_the_facts_it_lacks(self, secrets, monkeypatch):
        assert create_node("computing_core__host", {"realm": "oci-digest", "stable_id": DIGEST, "kind": "container", "name": "theirs", "architecture": "arm64"}).success
        run_against(monkeypatch, Instance(images=[IMAGE]))
        assert (host().name, host().architecture, host().os, host().image_size_bytes, host().image_layer_count) == ("theirs", "arm64", "debian 12", 123456789012, 7)

    def test_a_size_of_zero_another_collector_wrote_is_a_value_and_is_kept(self, secrets, monkeypatch):
        assert create_node("computing_core__host", {"realm": "oci-digest", "stable_id": DIGEST, "kind": "container", "image_layer_count": 0}).success
        run_against(monkeypatch, Instance(images=[IMAGE]))
        assert host().image_layer_count == 0

    @pytest.mark.parametrize("metadata", [{"arch": "x" * 40}, {"arch": 7}, {"image_size": -1}, {"image_size": "big"}, {"image_size": True}, {"layer_count": 2147483648}, {"arch": None, "image_size": None, "layer_count": None}])
    def test_a_fact_the_host_cannot_hold_is_left_out(self, metadata):
        facts = decompose.image_facts({"image_content": {"metadata": metadata}})
        assert not set(facts) & set(decompose.IMAGE_FACT_FIELDS)

    def test_a_second_run_changes_nothing(self, secrets, monkeypatch):
        server = Instance(images=[IMAGE])
        run_against(monkeypatch, server)
        before = (host().architecture, host().image_size_bytes, host().image_layer_count, host().name)
        run_against(monkeypatch, server)
        assert (host().architecture, host().image_size_bytes, host().image_layer_count, host().name) == before and Host.objects.filter(stable_id=DIGEST).count() == 1


@pytest.mark.django_db
class TestTags:
    def test_each_tag_is_a_node_pointing_at_the_image_and_says_when_it_was_seen(self, secrets, monkeypatch):
        run_against(monkeypatch, Instance(images=[IMAGE]))
        got = tags()
        assert set(got) == {"registry.example/app:1.4", "registry.example/app:latest", "docker.io/mirror/app:1.4"}
        one = got["registry.example/app:1.4"]
        assert (one.registry, one.repository, one.tag) == ("registry.example", "app", "1.4")
        edges = tag_edges()
        assert edges["registry.example/app:1.4"] == {"detected_at": "2026-11-10T12:00:00+00:00"}
        assert edges["registry.example/app:latest"] in ({}, None)
        assert {e.to_entity_id for e in Edge.objects.filter(edge_type="TAGS_IMAGE__computing_core")} == {host().entity_id}

    def test_a_tag_two_images_carry_is_one_node_with_an_edge_to_each(self, secrets, monkeypatch):
        other = {**IMAGE, "image_digest": OTHER, "image_detail": [IMAGE["image_detail"][1]]}
        run_against(monkeypatch, Instance(images=[IMAGE, other]))
        latest = tags()["registry.example/app:latest"]
        assert Edge.objects.filter(edge_type="TAGS_IMAGE__computing_core", from_entity_id=latest.entity_id).count() == 2
        assert get_model_class(TAG_TYPE).objects.count() == 3

    def test_a_second_run_writes_no_second_tag_or_edge(self, secrets, monkeypatch):
        server = Instance(images=[IMAGE])
        run_against(monkeypatch, server)
        run_against(monkeypatch, server)
        assert get_model_class(TAG_TYPE).objects.count() == 3 and Edge.objects.filter(edge_type="TAGS_IMAGE__computing_core").count() == 3

    def test_a_tag_outside_the_repository_prefixes_is_not_written(self, tmp_path, monkeypatch):
        configure(tmp_path, monkeypatch, {"running_only": False, "repository_prefixes": ["registry.example/"]})
        run_against(monkeypatch, Instance(images=[IMAGE]))
        assert set(tags()) == {"registry.example/app:1.4", "registry.example/app:latest"}

    @pytest.mark.parametrize("detail", [{"registry": "r", "repo": "p"}, {"registry": "", "repo": "p", "tag": "t"}, {"registry": "r", "repo": "p", "tag": "t" * 129}, {"registry": "r" * 256, "repo": "p", "tag": "t"}, "text", {"registry": None, "repo": "p", "tag": "t"}])
    def test_a_detail_that_names_no_whole_tag_is_left_out(self, detail):
        assert decompose.image_tag_rows({"image_detail": [detail]}) == []

    def test_a_detection_time_that_does_not_read_as_a_time_is_left_off_the_edge(self):
        (row,) = decompose.image_tag_rows({"image_detail": [{"registry": "r", "repo": "p", "tag": "t", "tag_detected_at": "sometime"}]})
        assert row["detected_at"] is None and row["reference"] == "r/p:t"
