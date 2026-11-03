"""The links a run draws and the SBOM documents it records (req-anchore-findings, req-anchore-sbom).

Same canned instance and real GRIFT importer as test_collector_run. The shared nodes (the image
host, the vulnerability) are created through the service layer as another collector would have.
"""

import hashlib
import json

import pytest

from tap_grid.models import Edge
from tap_grid.services import create_node
from tap_plugin.anchore.models.finding import AnchoreFinding
from tap_plugin.anchore.models.scan_run import AnchoreScanRun
from tap_plugin.anchore.tests.fakes import response
from tap_plugin.anchore.tests.test_collector_run import DIGEST, OTHER, Instance, run_against, secrets, vuln  # noqa: F401
from tap_plugin.compliance_core.models.compliance_vulnerability import ComplianceVulnerability
from tap_plugin.computing_core.models.host import Host
from tap_plugin.computing_core.models.sbom_document import SbomDocument


def edges(slug):
    return list(Edge.objects.filter(edge_type=slug).select_related("from_entity", "to_entity"))


def make(entity_type, payload):
    result = create_node(entity_type, payload)
    assert result.success, result.errors


@pytest.mark.django_db
class TestImageHost:
    def test_findings_point_at_the_image_host_which_is_written_with_only_its_digest(self, secrets, monkeypatch):
        run_against(monkeypatch, Instance())
        host = Host.objects.get()
        assert (host.realm, host.stable_id, host.kind, host.name) == ("oci-digest", DIGEST, "container", "")
        found = edges("FOUND_ON_IMAGE__anchore")
        assert len(found) == 2 and {e.to_entity_id for e in found} == {host.entity_id}
        assert {e.from_entity.entity_type for e in found} == {"anchore__anchore_finding"}

    def test_an_existing_host_is_linked_and_never_rewritten(self, secrets, monkeypatch):
        make(Host.ENTITY_TYPE, {"realm": "oci-digest", "stable_id": DIGEST, "kind": "container", "name": "ghcr.io/example/app:1"})
        run_against(monkeypatch, Instance())
        host = Host.objects.get()
        assert host.name == "ghcr.io/example/app:1" and len(edges("FOUND_ON_IMAGE__anchore")) == 2

    def test_a_digest_that_is_not_a_plain_sha256_digest_names_no_host_and_is_counted(self, secrets, monkeypatch):
        odd = "sha256:" + "AB" * 32
        instance = Instance(images=[{"image_digest": odd, "analysis_status": "analyzed"}])
        instance.transport.routes[f"/images/{odd}/vuln/all"] = lambda r: response(200, {"vulnerabilities": [vuln()]})
        for fmt in ("native-json", "spdx-json", "cyclonedx-json"):
            instance.transport.routes[f"/images/{odd}/sboms/{fmt}"] = lambda r: response(200, {"x": 1})
        collector = run_against(monkeypatch, instance)
        assert AnchoreFinding.objects.count() == 1 and Host.objects.count() == 0
        assert not edges("FOUND_ON_IMAGE__anchore") and not edges("DESCRIBES_HOST__computing_core")
        assert any(w["message_code"] == "IMAGES_NOT_LINKED" for w in collector.results["warn"])

    def test_a_second_run_adds_no_host_and_no_duplicate_edge(self, secrets, monkeypatch):
        instance = Instance()
        run_against(monkeypatch, instance)
        run_against(monkeypatch, instance)
        assert Host.objects.count() == 1 and len(edges("FOUND_ON_IMAGE__anchore")) == 2 and SbomDocument.objects.count() == 3


@pytest.mark.django_db
class TestSharedVulnerability:
    def test_only_a_vulnerability_that_exists_with_exactly_the_identifier_is_linked_and_none_is_written(self, secrets, monkeypatch):
        make(ComplianceVulnerability.ENTITY_TYPE, {"vuln_id": "CVE-2024-0001"})
        make(ComplianceVulnerability.ENTITY_TYPE, {"vuln_id": "cve-2024-0002"})
        run_against(monkeypatch, Instance())
        linked = edges("ABOUT_VULNERABILITY__anchore")
        assert len(linked) == 1 and linked[0].from_entity.name.startswith("CVE-2024-0001")
        assert ComplianceVulnerability.objects.count() == 2
        assert ComplianceVulnerability.objects.get(vuln_id="CVE-2024-0001").entity_id == linked[0].to_entity_id

    def test_no_vulnerability_on_the_grid_means_no_edge_and_no_node(self, secrets, monkeypatch):
        run_against(monkeypatch, Instance())
        assert not edges("ABOUT_VULNERABILITY__anchore") and ComplianceVulnerability.objects.count() == 0


@pytest.mark.django_db
class TestSbomDocuments:
    def test_each_format_is_recorded_by_the_digest_of_its_exact_bytes_and_never_marked_verified(self, secrets, monkeypatch):
        instance = Instance()
        run_against(monkeypatch, instance)
        docs = {d.format: d for d in SbomDocument.objects.all()}
        assert set(docs) == {"anchore-native", "spdx", "cyclonedx"}
        exact = json.dumps({"format": "native-json", "digest": DIGEST}).encode()
        assert docs["anchore-native"].content_digest == hashlib.sha256(exact).hexdigest()
        assert all(d.verified is None and d.signer == "" and d.subject_digest == DIGEST and d.verification_note.startswith("unsigned; read from") for d in docs.values())
        host = Host.objects.get()
        describes = edges("DESCRIBES_HOST__computing_core")
        assert len(describes) == 3 and {e.to_entity_id for e in describes} == {host.entity_id}
        run = AnchoreScanRun.objects.get()
        assert {f"sbom:{f}:{DIGEST}" for f in ("anchore-native", "spdx", "cyclonedx")} <= set(run.scopes_read)

    def test_the_cyclonedx_header_fills_the_record_and_nothing_is_parsed_into_packages(self, secrets, monkeypatch):
        run_against(monkeypatch, Instance())
        doc = SbomDocument.objects.get(format="cyclonedx")
        assert (doc.spec_version, doc.serial_number, doc.revision, doc.component_count) == ("1.6", "urn:uuid:3e671687-395b-41f5-a30f-a58921a69b79", 1, 2)
        assert doc.produced_at is not None
        from tap_plugin.computing_core.models.package import Package

        assert Package.objects.count() == 0

    def test_a_format_the_instance_does_not_serve_is_listed_not_read_and_the_image_is_still_read(self, secrets, monkeypatch):
        instance = Instance()
        instance.transport.routes[f"/images/{DIGEST}/sboms/spdx-json"] = lambda r: response(404, {"detail": "no"})
        collector = run_against(monkeypatch, instance)
        assert AnchoreFinding.objects.count() == 2 and {d.format for d in SbomDocument.objects.all()} == {"anchore-native", "cyclonedx"}
        run = AnchoreScanRun.objects.get()
        assert [n["scope"] for n in run.scopes_not_read] == [f"sbom:spdx:{DIGEST}"] and run.scopes_not_read[0]["reason"] == "HTTP 404"
        assert any(w["message_code"] == "SBOM_NOT_READ" for w in collector.results["warn"])

    def test_a_body_that_is_not_json_is_not_recorded(self, secrets, monkeypatch):
        instance = Instance()
        instance.transport.routes[f"/images/{DIGEST}/sboms/native-json"] = lambda r: response(200, b"<xml/>", {"content-type": "application/json"})
        run_against(monkeypatch, instance)
        assert "anchore-native" not in {d.format for d in SbomDocument.objects.all()}

    def test_identical_bytes_for_two_images_are_one_document_describing_both_hosts(self, secrets, monkeypatch):
        instance = Instance(images=[{"image_digest": DIGEST, "analysis_status": "analyzed"}, {"image_digest": OTHER, "analysis_status": "analyzed"}])
        same = {"same": "bytes"}
        for digest in (DIGEST, OTHER):
            instance.sboms[(digest, "spdx-json")] = same
        run_against(monkeypatch, instance)
        spdx = SbomDocument.objects.get(format="spdx")
        assert SbomDocument.objects.filter(format="spdx").count() == 1
        assert {Host.objects.get(entity_id=e.to_entity_id).stable_id for e in edges("DESCRIBES_HOST__computing_core") if e.from_entity_id == spdx.entity_id} == {DIGEST, OTHER}
