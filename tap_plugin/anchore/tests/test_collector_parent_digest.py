"""A running digest that is an index is matched to the image Anchore analyzed under it (req-anchore-scope-15).

A runtime reports the digest a workload was started from; for a multi-platform image that is the
index. Anchore analyzes one platform's image under its own ``image_digest`` and keeps the index
digest as ``parent_digest``. Spec-derived payloads (OpenAPI 2.20.0), not recorded.
"""

import pytest
import tap_plugin.anchore.models as anchore  # noqa: F401 — trigger model registration
import tap_plugin.compliance_core.models as compliance  # noqa: F401 — trigger model registration
import tap_plugin.computing_core.models as computing  # noqa: F401 — trigger model registration
from tap_plugin.computing_core.models.host import Host

from tap_grid.models import Edge
from tap_plugin.anchore import scope
from tap_plugin.anchore.models.runtime_image import AnchoreRuntimeImage
from tap_plugin.anchore.tests.test_collector_run import DIGEST, OTHER, Instance, findings, no_sockets, run_against, vuln  # noqa: F401 — no_sockets is autouse
from tap_plugin.anchore.tests.test_collector_scope import configure, item, latest_run, not_read, read_images

INDEX = "sha256:" + "1" * 64
UNKNOWN = "sha256:" + "2" * 64


def image(digest: str, parent: str | None = None, **over) -> dict:
    record = {"image_digest": digest, "analysis_status": "analyzed", **over}
    if parent is not None:
        record["parent_digest"] = parent
    return record


def settings(running_only: bool = True, **over) -> scope.Settings:
    return scope.Settings(running_only=running_only, **over)


def platform_edges() -> set[tuple[str, str]]:
    return {(Host.objects.get(entity_id=e.from_entity_id).stable_id, Host.objects.get(entity_id=e.to_entity_id).stable_id) for e in Edge.objects.filter(edge_type="INDEXES_PLATFORM_IMAGE__anchore")}


class TestSelection:
    def test_a_running_digest_matches_by_parent_digest(self):
        got = scope.images_to_read({DIGEST: image(DIGEST, INDEX)}, {INDEX}, settings())
        assert got.digests == [DIGEST] and got.not_in_anchore == [] and got.analyzed_for == {INDEX: [DIGEST]}

    def test_a_direct_match_is_itself_and_does_not_also_read_its_children(self):
        listed = {INDEX: image(INDEX), DIGEST: image(DIGEST, INDEX)}
        got = scope.images_to_read(listed, {INDEX}, settings())
        assert got.digests == [INDEX] and got.analyzed_for == {INDEX: [INDEX]}

    def test_an_index_over_several_platform_images_reads_them_all(self):
        """One index, two analyzed architectures: neither is picked over the other."""
        listed = {DIGEST: image(DIGEST, INDEX), OTHER: image(OTHER, INDEX)}
        got = scope.images_to_read(listed, {INDEX}, settings())
        assert got.digests == [DIGEST, OTHER] and got.analyzed_for == {INDEX: [DIGEST, OTHER]}

    def test_a_digest_that_is_neither_an_image_nor_a_parent_is_not_in_anchore(self):
        got = scope.images_to_read({DIGEST: image(DIGEST, INDEX)}, {UNKNOWN}, settings())
        assert got.digests == [] and got.not_in_anchore == [UNKNOWN] and got.analyzed_for == {UNKNOWN: []}

    def test_an_image_that_is_its_own_parent_is_not_its_own_child(self):
        assert scope.images_by_parent({DIGEST: image(DIGEST, DIGEST)}) == {}

    @pytest.mark.parametrize("parent", [None, "", "latest", 7, "sha256:XYZ"])
    def test_a_parent_that_is_not_a_digest_matches_nothing(self, parent):
        assert scope.images_by_parent({DIGEST: {"image_digest": DIGEST, "parent_digest": parent}}) == {}

    def test_the_repository_filter_applies_to_the_stand_in(self):
        outside = image(DIGEST, INDEX, image_detail=[{"registry": "docker.io", "repo": "library/nginx"}])
        got = scope.images_to_read({DIGEST: outside}, {INDEX}, settings(repository_prefixes=("registry.example/",)))
        assert got.digests == [] and got.analyzed_for == {INDEX: []}
        # Anchore does hold it; it is out of scope, which is not the same as not in Anchore.
        assert got.not_in_anchore == []

    def test_all_images_mode_still_records_what_stands_in(self):
        got = scope.images_to_read({DIGEST: image(DIGEST, INDEX), OTHER: image(OTHER)}, {INDEX}, settings(False))
        assert got.digests == [DIGEST, OTHER] and got.analyzed_for == {INDEX: [DIGEST]}


@pytest.mark.django_db
class TestRun:
    def test_an_inventory_record_whose_digest_is_a_parent_digest_is_selected_and_read(self, tmp_path, monkeypatch):
        configure(tmp_path, monkeypatch, {"running_only": True})
        server = Instance(images=[image(DIGEST, INDEX)])
        server.inventory = [item("prod/default", INDEX)]
        run_against(monkeypatch, server)
        run = latest_run()
        # Read under the analyzed image's digest, and not reported as missing from Anchore.
        assert read_images(run) == {DIGEST}
        assert not any("not-in-anchore" in reason for reason in not_read(run).values()) and run.images_not_in_anchore == 0
        assert {target for _, target in findings()} == {DIGEST}
        # The runtime image keeps the running (index) digest and says which analyzed digest stood in.
        (observed,) = AnchoreRuntimeImage.objects.all()
        assert (observed.image_digest, observed.analyzed_digests) == (INDEX, [DIGEST])
        assert platform_edges() == {(INDEX, DIGEST)}

    def test_several_platform_images_under_one_index_are_all_read_and_all_recorded(self, tmp_path, monkeypatch):
        configure(tmp_path, monkeypatch, {"running_only": True})
        server = Instance(images=[image(DIGEST, INDEX), image(OTHER, INDEX)])
        server.vulns[OTHER] = [vuln("CVE-2024-0009")]
        server.inventory = [item("prod/default", INDEX)]
        run_against(monkeypatch, server)
        assert read_images(latest_run()) == {DIGEST, OTHER}
        (observed,) = AnchoreRuntimeImage.objects.all()
        assert observed.analyzed_digests == sorted([DIGEST, OTHER])
        assert platform_edges() == {(INDEX, DIGEST), (INDEX, OTHER)}

    def test_a_direct_match_records_itself_and_draws_no_platform_edge(self, tmp_path, monkeypatch):
        configure(tmp_path, monkeypatch, {"running_only": True})
        server = Instance()
        server.inventory = [item("prod/default", DIGEST)]
        run_against(monkeypatch, server)
        (observed,) = AnchoreRuntimeImage.objects.all()
        assert observed.analyzed_digests == [DIGEST] and platform_edges() == set()

    def test_a_running_digest_anchore_does_not_hold_is_still_reported_and_recorded_empty(self, tmp_path, monkeypatch):
        configure(tmp_path, monkeypatch, {"running_only": True})
        server = Instance(images=[image(DIGEST, INDEX)])
        server.inventory = [item("prod/default", UNKNOWN)]
        run_against(monkeypatch, server)
        run = latest_run()
        assert run.images_not_in_anchore == 1 and f"image:{UNKNOWN}" in not_read(run)
        (observed,) = AnchoreRuntimeImage.objects.all()
        assert observed.analyzed_digests == []
