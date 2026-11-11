"""The VEX annotations Anchore holds on an image (req-anchore-vex).

Spec-derived payloads (OpenAPI 2.20.0), not recorded from an instance.
"""

import pytest
import tap_plugin.anchore.models as anchore  # noqa: F401 — trigger model registration
import tap_plugin.compliance_core.models as compliance  # noqa: F401 — trigger model registration
import tap_plugin.computing_core.models as computing  # noqa: F401 — trigger model registration

from tap_grid.models import Edge
from tap_grid.services import create_node
from tap_plugin.anchore.models.finding import AnchoreFinding
from tap_plugin.anchore.models.scan_run import AnchoreScanRun
from tap_plugin.anchore.models.vex_annotation import AnchoreVexAnnotation
from tap_plugin.anchore.tests.test_collector_run import DIGEST, KEY, Instance, no_sockets, run_against, secrets, vuln  # noqa: F401 — fixtures

UUID, OTHER_UUID = "0b9e6b1e-7a55-4c0b-9d0a-000000000001", "0b9e6b1e-7a55-4c0b-9d0a-000000000002"


def entry(uuid: str = UUID, vulnerability: str = "CVE-2024-0001", status: str = "not_affected", package: dict | None = None, **over) -> dict:
    annotation = {
        "uuid": uuid,
        "vulnerability_id": vulnerability,
        "status": status,
        "justification": "vulnerable_code_not_present",
        "status_notes": "The affected function is compiled out.",
        "impact_statement": None,
        "action_statement": None,
        "additional_details": "Checked against build flags, 2026-11-01.",
        "source": {"type": "user", "name": "Acme Corp"},
        "version": 2,
        "created_at": "2026-11-01T10:00:00Z",
        "updated_at": "2026-11-02T10:00:00Z",
        "author": "anchore",
        "a_key_the_model_has_no_field_for": {"kept": True},
    }
    annotation.update(over)
    return {"annotation": annotation, "package_identifier": package}


def server(*entries, vulns=None) -> Instance:
    instance = Instance(vulns=vulns if vulns is not None else [vuln(annotation_uuid=UUID, annotation_status="not_affected"), vuln("CVE-2024-0002")])
    instance.vex[DIGEST] = list(entries) if entries else [entry()]
    return instance


def run() -> AnchoreScanRun:
    return AnchoreScanRun.objects.order_by("-finished_at").first()


def not_read() -> dict[str, str]:
    return {e["scope"]: e["reason"] for e in run().scopes_not_read}


def edges(slug: str) -> list[Edge]:
    return list(Edge.objects.filter(edge_type=slug))


@pytest.mark.django_db
class TestAnnotations:
    def test_an_annotation_is_stored_as_anchore_returned_it(self, secrets, monkeypatch):
        run_against(monkeypatch, server(entry(package={"name": "libx", "version": "1.0", "type": "rpm"})))
        (got,) = AnchoreVexAnnotation.objects.all()
        assert (got.scanner_key, got.scope_kind, got.scope_id, got.annotation_id) == (KEY, "image", DIGEST, UUID)
        assert (got.state, got.vulnerability_id, got.status, got.justification) == ("current", "CVE-2024-0001", "not_affected", "vulnerable_code_not_present")
        assert (got.package_name, got.package_version, got.package_type) == ("libx", "1.0", "rpm")
        assert got.status_notes == "The affected function is compiled out." and got.impact_statement is None
        assert (got.source_type, got.source_name, got.annotation_version) == ("user", "Acme Corp", 2)
        assert got.annotation_updated_at.isoformat().startswith("2026-11-02T10:00:00")
        assert got.record["annotation"]["a_key_the_model_has_no_field_for"] == {"kept": True}
        assert got.last_seen_run_id == run().run_id
        assert f"vex:{DIGEST}" in run().scopes_read
        assert got.entity.dimensions["anchore.area"] == "annotation"

    def test_a_null_package_scope_stays_null(self, secrets, monkeypatch):
        run_against(monkeypatch, server(entry(package=None)))
        (got,) = AnchoreVexAnnotation.objects.all()
        assert (got.package_name, got.package_version, got.package_type) == (None, None, None)
        assert edges("ABOUT_PACKAGE__anchore") == []

    def test_it_points_at_its_image_and_at_the_finding_that_carries_its_uuid(self, secrets, monkeypatch):
        run_against(monkeypatch, server())
        (got,) = AnchoreVexAnnotation.objects.all()
        (to_image,) = edges("ANNOTATES_IMAGE__anchore")
        assert to_image.from_entity_id == got.entity_id and to_image.to_entity.name
        (to_finding,) = edges("ANNOTATES_FINDING__anchore")
        finding = AnchoreFinding.objects.get(entity_id=to_finding.to_entity_id)
        assert (finding.vulnerability_id, finding.annotation_uuid) == ("CVE-2024-0001", UUID)

    def test_a_finding_is_never_joined_by_vulnerability_alone(self, secrets, monkeypatch):
        """The same CVE with no uuid on the finding is not this statement's finding."""
        run_against(monkeypatch, server(vulns=[vuln()]))
        assert AnchoreVexAnnotation.objects.count() == 1
        assert edges("ANNOTATES_FINDING__anchore") == []

    def test_the_shared_vulnerability_is_linked_only_where_it_exists_exactly(self, secrets, monkeypatch):
        run_against(monkeypatch, server())
        assert [e for e in edges("ABOUT_VULNERABILITY__anchore") if e.from_entity.entity_type == AnchoreVexAnnotation.ENTITY_TYPE] == []
        assert create_node("compliance_core__compliance_vulnerability", {"vuln_id": "CVE-2024-0001"}).success
        run_against(monkeypatch, server())
        (link,) = [e for e in edges("ABOUT_VULNERABILITY__anchore") if e.from_entity.entity_type == AnchoreVexAnnotation.ENTITY_TYPE]
        assert link.to_entity.entity_type == "compliance_core__compliance_vulnerability"

    def test_one_uuid_returned_twice_is_one_annotation(self, secrets, monkeypatch):
        run_against(monkeypatch, server(entry(), entry()))
        assert AnchoreVexAnnotation.objects.count() == 1


@pytest.mark.django_db
class TestWithdrawal:
    def test_an_annotation_no_longer_returned_is_marked_withdrawn_and_kept(self, secrets, monkeypatch):
        run_against(monkeypatch, server(entry(), entry(OTHER_UUID, "CVE-2024-0002", "fixed")))
        run_against(monkeypatch, server(entry()))
        got = {a.annotation_id: a for a in AnchoreVexAnnotation.objects.all()}
        assert (got[UUID].state, got[OTHER_UUID].state) == ("current", "withdrawn")
        assert (got[OTHER_UUID].status, got[OTHER_UUID].vulnerability_id) == ("fixed", "CVE-2024-0002")
        assert got[OTHER_UUID].get_name() == "withdrawn fixed · CVE-2024-0002"

    def test_a_withdrawn_annotation_returned_again_is_current_again(self, secrets, monkeypatch):
        run_against(monkeypatch, server(entry()))
        run_against(monkeypatch, server(entry(OTHER_UUID)))
        run_against(monkeypatch, server(entry(), entry(OTHER_UUID)))
        assert {a.state for a in AnchoreVexAnnotation.objects.all()} == {"current"}

    def test_a_failed_read_withdraws_nothing_and_is_not_read(self, secrets, monkeypatch):
        run_against(monkeypatch, server(entry()))
        instance = server()
        instance.vex[DIGEST] = 500
        run_against(monkeypatch, instance)
        assert AnchoreVexAnnotation.objects.get().state == "current"
        assert f"vex:{DIGEST}" in not_read() and f"vex:{DIGEST}" not in run().scopes_read

    def test_an_entry_that_cannot_be_stored_withdraws_nothing(self, secrets, monkeypatch):
        run_against(monkeypatch, server(entry()))
        broken = entry(OTHER_UUID)
        del broken["annotation"]["uuid"]
        run_against(monkeypatch, server(broken))
        assert AnchoreVexAnnotation.objects.get().state == "current"
        assert "1 annotation(s)" in not_read()[f"vex:{DIGEST}:withdrawal"]

    def test_an_image_with_no_annotations_is_read_and_empty(self, secrets, monkeypatch):
        instance = server()
        instance.vex[DIGEST] = []
        run_against(monkeypatch, instance)
        assert AnchoreVexAnnotation.objects.count() == 0
        assert f"vex:{DIGEST}" in run().scopes_read


@pytest.mark.django_db
class TestPackageScope:
    """ABOUT_PACKAGE: only an exact, single match among the image's parsed packages."""

    def cdx(self, *components):
        from tap_plugin.anchore.tests.test_collector_sbom_inventory import CDX

        return {**CDX, "components": [{"type": "library", "name": n, "version": v, "purl": p} for n, v, p in components]}

    def test_the_one_package_with_that_name_and_version_is_linked(self, secrets, monkeypatch):
        from tap_plugin.computing_core.models.package import Package

        instance = server(entry(package={"name": "libx", "version": "1.0", "type": "dpkg"}))
        instance.sboms[(DIGEST, "cyclonedx-json")] = self.cdx(("libx", "1.0", "pkg:deb/debian/libx@1.0"), ("liby", "2.1", "pkg:deb/debian/liby@2.1"))
        run_against(monkeypatch, instance)
        (link,) = edges("ABOUT_PACKAGE__anchore")
        assert link.to_entity_id == Package.objects.get(name="libx").entity_id

    def test_two_packages_with_that_name_and_version_get_no_edge(self, secrets, monkeypatch):
        """The same name and version in two ecosystems: Anchore's package type is not translated, so neither is chosen."""
        instance = server(entry(package={"name": "libx", "version": "1.0", "type": "dpkg"}))
        instance.sboms[(DIGEST, "cyclonedx-json")] = self.cdx(("libx", "1.0", "pkg:deb/debian/libx@1.0"), ("libx", "1.0", "pkg:pypi/libx@1.0"))
        run_against(monkeypatch, instance)
        assert AnchoreVexAnnotation.objects.count() == 1 and edges("ABOUT_PACKAGE__anchore") == []

    def test_a_package_the_inventory_does_not_hold_gets_no_edge(self, secrets, monkeypatch):
        run_against(monkeypatch, server(entry(package={"name": "absent", "version": "9", "type": "dpkg"})))
        assert edges("ABOUT_PACKAGE__anchore") == []
