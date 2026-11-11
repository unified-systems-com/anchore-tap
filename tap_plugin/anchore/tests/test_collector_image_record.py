"""Anchore's record of an image, the host's name, and records kept as returned (req-anchore-image, req-anchore-record)."""

import pytest
import tap_plugin.anchore.models as anchore  # noqa: F401 — trigger model registration
import tap_plugin.compliance_core.models as compliance  # noqa: F401 — trigger model registration
import tap_plugin.computing_core.models as computing  # noqa: F401 — trigger model registration
from tap_plugin.computing_core.models.host import Host

from tap_grid.models import Edge
from tap_grid.services import create_node
from tap_plugin.anchore.collectors.anchore_collector import decompose
from tap_plugin.anchore.models.image import AnchoreImage
from tap_plugin.anchore.models.runtime_image import AnchoreRuntimeImage
from tap_plugin.anchore.tests.test_collector_run import DIGEST, KEY, OTHER, Instance, findings, no_sockets, run_against, secrets, vuln  # noqa: F401 — fixtures
from tap_plugin.anchore.tests.test_collector_scope import configure, item

IMAGE = {
    "image_digest": DIGEST,
    "analysis_status": "analyzed",
    "image_status": "active",
    "parent_digest": DIGEST,
    "created_at": "2026-11-01T08:00:00Z",
    "last_updated": "2026-11-02T09:30:00Z",
    "annotations": {"team": "platform"},
    "image_detail": [
        {"registry": "registry.example", "repo": "app", "tag": "latest", "full_tag": "registry.example/app:latest"},
        {"registry": "registry.example", "repo": "app", "tag": "1.4", "full_tag": "registry.example/app:1.4"},
    ],
    "image_content": {"metadata": {"arch": "amd64", "distro": "debian", "distro_version": "12", "image_size": 1234, "layer_count": 7}},
}


def host(digest: str = DIGEST) -> Host:
    return Host.objects.get(realm="oci-digest", stable_id=digest)


@pytest.mark.django_db
class TestTheRecord:
    def test_anchores_record_of_the_image_is_written_whole(self, secrets, monkeypatch):
        run_against(monkeypatch, Instance(images=[IMAGE]))
        (record,) = AnchoreImage.objects.all()
        assert (record.scanner_key, record.image_digest, record.analysis_status, record.image_status, record.parent_digest) == (KEY, DIGEST, "analyzed", "active", DIGEST)
        assert record.reference == "registry.example/app:1.4" and record.get_name() == "registry.example/app:1.4"
        assert record.created_at.isoformat().startswith("2026-11-01T08:00:00") and record.last_updated is not None
        # Every key Anchore returned, as it returned it.
        assert record.record == IMAGE
        (edge,) = Edge.objects.filter(edge_type="RECORDS_IMAGE__anchore")
        assert (edge.from_entity_id, edge.to_entity_id) == (record.entity_id, host().entity_id)

    def test_an_image_not_yet_analyzed_still_has_its_record(self, secrets, monkeypatch):
        run_against(monkeypatch, Instance(images=[{"image_digest": DIGEST, "analysis_status": "analyzing"}]))
        (record,) = AnchoreImage.objects.all()
        assert (record.analysis_status, record.reference, record.record) == ("analyzing", None, {"image_digest": DIGEST, "analysis_status": "analyzing"})
        assert not findings()

    def test_a_second_run_is_the_same_record(self, secrets, monkeypatch):
        server = Instance(images=[IMAGE])
        run_against(monkeypatch, server)
        run_against(monkeypatch, server)
        assert AnchoreImage.objects.count() == 1 and Edge.objects.filter(edge_type="RECORDS_IMAGE__anchore").count() == 1


@pytest.mark.django_db
class TestTheHostsName:
    def test_a_host_this_run_creates_carries_the_reference_and_the_operating_system(self, secrets, monkeypatch):
        run_against(monkeypatch, Instance(images=[IMAGE]))
        assert (host().name, host().os, host().kind) == ("registry.example/app:1.4", "debian 12", "container")

    def test_a_host_the_grid_holds_gets_only_what_it_lacks(self, secrets, monkeypatch):
        assert create_node("computing_core__host", {"realm": "oci-digest", "stable_id": DIGEST, "kind": "container", "name": "ghcr.io/theirs/app:9"}).success
        run_against(monkeypatch, Instance(images=[IMAGE]))
        assert (host().name, host().os) == ("ghcr.io/theirs/app:9", "debian 12")

    def test_a_host_with_both_already_is_left_alone(self, secrets, monkeypatch):
        assert create_node("computing_core__host", {"realm": "oci-digest", "stable_id": DIGEST, "kind": "container", "name": "theirs", "os": "alpine 3.20"}).success
        collector = run_against(monkeypatch, Instance(images=[IMAGE]))
        assert (host().name, host().os) == ("theirs", "alpine 3.20")
        assert Host.objects.filter(stable_id=DIGEST).count() == 1 and collector is not None

    def test_a_bare_host_from_an_earlier_run_is_named_on_the_next(self, secrets, monkeypatch):
        assert create_node("computing_core__host", {"realm": "oci-digest", "stable_id": DIGEST, "kind": "container"}).success
        run_against(monkeypatch, Instance(images=[IMAGE]))
        assert (host().name, host().os) == ("registry.example/app:1.4", "debian 12")

    def test_an_image_with_no_tag_and_no_distribution_names_nothing(self, secrets, monkeypatch):
        run_against(monkeypatch, Instance())
        assert (host().name, host().os) == ("", "")


    def test_two_scanners_that_each_know_one_field_give_the_host_both(self, tmp_path, monkeypatch):
        """Whichever is read first: the tag comes from one instance and the distribution from the other."""
        import types

        from tap_plugin.anchore.collectors.anchore_collector import collector as collector_module
        from tap_plugin.anchore.tests.fakes import response
        from tap_plugin.anchore.tests.test_anchore_credential import data, write

        write(tmp_path, "one", data("basic", base_url="https://one.example:8228/v2"))
        write(tmp_path, "two", data("basic", base_url="https://two.example:8228/v2"))
        monkeypatch.setattr(collector_module, "secrets_root", types.SimpleNamespace(resolve=lambda: tmp_path))
        tagged = {"image_digest": DIGEST, "analysis_status": "analyzed", "image_detail": IMAGE["image_detail"]}
        with_distro = {"image_digest": DIGEST, "analysis_status": "analyzed", "image_content": IMAGE["image_content"]}
        server = Instance()
        server.transport.routes["/images"] = lambda r: response(200, {"items": [tagged if "one.example" in str(r.url) else with_distro]})
        run_against(monkeypatch, server)
        assert (host().name, host().os) == ("registry.example/app:1.4", "debian 12")
        assert Host.objects.filter(stable_id=DIGEST).count() == 1 and AnchoreImage.objects.count() == 2

    def test_an_operating_system_too_long_for_the_host_is_not_sent_and_the_run_lands(self, secrets, monkeypatch):
        long = {**IMAGE, "image_content": {"metadata": {"distro": "d" * 300, "distro_version": "1"}}}
        run_against(monkeypatch, Instance(images=[long]))
        assert (host().name, host().os) == ("registry.example/app:1.4", "")
        assert AnchoreImage.objects.get().record["image_content"]["metadata"]["distro"] == "d" * 300


class TestNaming:
    def test_the_reference_does_not_move_with_the_order_of_the_tags(self):
        flipped = {**IMAGE, "image_detail": list(reversed(IMAGE["image_detail"]))}
        assert decompose.image_naming(IMAGE) == decompose.image_naming(flipped) == ("registry.example/app:1.4", "debian 12")

    @pytest.mark.parametrize("image", [None, {}, {"image_detail": "x", "image_content": 7}, {"image_detail": [{"full_tag": None}, "x"], "image_content": {"metadata": {"distro": None, "distro_version": None}}}])
    def test_a_record_that_gives_neither_is_none_and_none(self, image):
        assert decompose.image_naming(image) == (None, None)

    def test_a_distribution_without_a_version_is_the_distribution(self):
        assert decompose.image_naming({"image_content": {"metadata": {"distro": "alpine", "distro_version": None}}}) == (None, "alpine")


@pytest.mark.django_db
class TestRecordsAsReturned:
    def test_a_finding_keeps_its_entry_as_returned(self, secrets, monkeypatch):
        entry = vuln("CVE-2024-0001", some_new_key={"nested": [1, 2]}, will_not_fix=False)
        run_against(monkeypatch, Instance(vulns=[entry]))
        (finding,) = findings().values()
        assert finding.record == entry and finding.record["some_new_key"] == {"nested": [1, 2]}

    def test_a_runtime_image_keeps_its_inventory_item_as_returned(self, tmp_path, monkeypatch):
        configure(tmp_path, monkeypatch, {"running_only": True})
        server = Instance()
        server.inventory = [item("prod/default", DIGEST, account_name="acct", namespace="default")]
        run_against(monkeypatch, server)
        (observed,) = AnchoreRuntimeImage.objects.all()
        assert observed.record == server.inventory[0]

    def test_a_resolved_finding_keeps_the_record_it_had(self, secrets, monkeypatch):
        entry = vuln("CVE-2024-0001")
        server = Instance(vulns=[entry])
        run_against(monkeypatch, server)
        server.vulns[DIGEST] = []
        run_against(monkeypatch, server)
        (finding,) = findings().values()
        assert finding.state == "resolved" and finding.record == entry
