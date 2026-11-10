"""An image's CycloneDX SBOM becomes its package inventory, through computing_core's parser (req-anchore-sbom-2, -4, -6, -7, -8).

The document is unsigned and is parsed as source-authenticated: this client fetched it, with the
operator's credential, over verified TLS. Spec-derived payloads, not recorded from an instance.
"""

import hashlib
import json
import types

import pytest
import tap_plugin.anchore.models as anchore  # noqa: F401 — trigger model registration
import tap_plugin.compliance_core.models as compliance  # noqa: F401 — trigger model registration
import tap_plugin.computing_core.models as computing  # noqa: F401 — trigger model registration
from tap_plugin.computing_core.models.host import Host
from tap_plugin.computing_core.models.package import Package
from tap_plugin.computing_core.models.sbom_document import SbomDocument

from tap_grid.models import Edge
from tap_grid.services import create_node
from tap_plugin.anchore.collectors.anchore_collector import collector as collector_module
from tap_plugin.anchore.models.scan_run import AnchoreScanRun
from tap_plugin.anchore.tests.test_anchore_credential import data, write
from tap_plugin.anchore.tests.test_collector_run import DIGEST, KEY, Instance, findings, no_sockets, run_against, secrets, vuln  # noqa: F401 — fixtures

LIBX = "pkg:deb/debian/libx@1.0"
CDX = {
    "bomFormat": "CycloneDX",
    "specVersion": "1.6",
    "serialNumber": "urn:uuid:3e671687-395b-41f5-a30f-a58921a69b79",
    "version": 1,
    "metadata": {"timestamp": "2026-11-03T10:00:00Z"},
    "components": [{"type": "library", "name": "libx", "version": "1.0", "purl": LIBX}, {"type": "library", "name": "liby", "version": "2.1", "purl": "pkg:deb/debian/liby@2.1"}],
}
CONTENT = hashlib.sha256(json.dumps(CDX).encode()).hexdigest()
ON_GRID = {"content_digest": CONTENT, "format": "cyclonedx", "spec_version": "1.6", "serial_number": CDX["serialNumber"], "revision": 1, "subject_digest": DIGEST}


def instance(**over) -> Instance:
    server = Instance(vulns=[vuln("CVE-2024-0001", purl=LIBX), vuln("CVE-2024-0002", purl="pkg:deb/debian/absent@9")], **over)
    server.sboms[(DIGEST, "cyclonedx-json")] = CDX
    return server


def document() -> SbomDocument:
    return SbomDocument.objects.get(content_digest=CONTENT)


def not_read() -> dict[str, str]:
    return {entry["scope"]: entry["reason"] for entry in AnchoreScanRun.objects.order_by("-finished_at").first().scopes_not_read}


def edge_count(slug: str) -> int:
    return Edge.objects.filter(edge_type=slug).count()


@pytest.mark.django_db
class TestParsed:
    def test_the_packages_are_written_and_the_document_names_its_source(self, secrets, monkeypatch):
        run_against(monkeypatch, instance())
        assert {(p.name, p.version) for p in Package.objects.all()} == {("libx", "1.0"), ("liby", "2.1")}
        doc = document()
        assert (doc.verified, doc.signer, doc.verification_note, doc.authenticated_source, doc.subject_digest) == (None, "", "", KEY, DIGEST)
        host = Host.objects.get(stable_id=DIGEST)
        installs = Edge.objects.filter(edge_type="INSTALLS_PACKAGE__computing_core")
        assert installs.count() == 2 and {e.from_entity_id for e in installs} == {host.entity_id}
        describes = Edge.objects.filter(edge_type="DESCRIBES_HOST__computing_core", from_entity_id=doc.entity_id)
        assert [e.to_entity_id for e in describes] == [host.entity_id]

    def test_a_finding_is_joined_to_the_package_its_purl_names_and_to_no_other(self, secrets, monkeypatch):
        run_against(monkeypatch, instance())
        joined = {(e.from_entity.name.split(" ")[0], e.to_entity.name) for e in Edge.objects.filter(edge_type="FOUND_IN_PACKAGE__anchore").select_related("from_entity", "to_entity")}
        assert len(joined) == 1 and next(iter(joined))[0] == "CVE-2024-0001"
        libx = Package.objects.get(name="libx")
        assert Edge.objects.get(edge_type="FOUND_IN_PACKAGE__anchore").to_entity_id == libx.entity_id

    def test_a_second_run_stages_no_inventory_again_and_still_joins_a_new_finding(self, secrets, monkeypatch):
        server = instance()
        run_against(monkeypatch, server)
        before = (Package.objects.count(), edge_count("INSTALLS_PACKAGE__computing_core"), SbomDocument.objects.count())
        server.vulns[DIGEST] = [*server.vulns[DIGEST], vuln("CVE-2024-0003", package="liby-2.1", path="/usr/lib/liby.so", purl="pkg:deb/debian/liby@2.1")]
        collector = run_against(monkeypatch, server)
        assert (Package.objects.count(), edge_count("INSTALLS_PACKAGE__computing_core"), SbomDocument.objects.count()) == before
        (parsed,) = [m for m in collector.results["info"] if m["message_code"] == "SBOMS_PARSED"]
        assert (parsed["message_data"]["parsed"], parsed["message_data"]["staged"]) == (1, 0)
        assert edge_count("FOUND_IN_PACKAGE__anchore") == 2


@pytest.mark.django_db
class TestNotParsed:
    def test_over_plain_http_the_document_is_recorded_and_not_parsed(self, tmp_path, monkeypatch):
        write(tmp_path, "demo", data("basic", base_url="http://anchore.example:8228/v2"))
        monkeypatch.setattr(collector_module, "secrets_root", types.SimpleNamespace(resolve=lambda: tmp_path))
        run_against(monkeypatch, instance())
        assert Package.objects.count() == 0 and edge_count("FOUND_IN_PACKAGE__anchore") == 0
        doc = document()
        assert doc.authenticated_source == "" and doc.verification_note.startswith("unsigned;")
        assert "plain http" in not_read()[f"sbom-inventory:{DIGEST}"]

    def test_a_document_the_parser_refuses_is_recorded_and_says_why(self, secrets, monkeypatch):
        server = instance()
        server.sboms[(DIGEST, "cyclonedx-json")] = {**CDX, "components": [{"name": "no-version"}]}
        run_against(monkeypatch, server)
        assert Package.objects.count() == 0
        (doc,) = SbomDocument.objects.filter(format="cyclonedx")
        assert doc.authenticated_source == "" and doc.verification_note.startswith("unsigned;")
        assert "recorded and not parsed" in not_read()[f"sbom-inventory:{DIGEST}"]
        assert len(findings()) == 2


@pytest.mark.django_db
class TestAnotherCollectorsDocument:
    def test_a_document_a_signer_verified_is_not_rewritten_and_nothing_is_staged(self, secrets, monkeypatch):
        assert create_node("computing_core__sbom_document", {**ON_GRID, "verified": True, "signer": "ci@example.org"}).success
        run_against(monkeypatch, instance())
        doc = document()
        assert (doc.verified, doc.signer, doc.authenticated_source) == (True, "ci@example.org", "")
        # The signed parse is whose inventory it is; this plugin staged none, and joins only to what exists.
        assert Package.objects.count() == 0 and edge_count("FOUND_IN_PACKAGE__anchore") == 0

    def test_a_document_the_grid_holds_as_refused_is_not_parsed(self, secrets, monkeypatch):
        assert create_node("computing_core__sbom_document", {**ON_GRID, "verified": False, "verification_note": "signer-identity"}).success
        collector = run_against(monkeypatch, instance())
        assert document().verified is False and Package.objects.count() == 0
        assert not [m for m in collector.results["info"] if m["message_code"] == "SBOMS_PARSED"]

    def test_a_document_this_plugin_recorded_before_it_could_parse_is_parsed_now(self, secrets, monkeypatch):
        """The upgrade path: a row from an earlier release, recorded with the unsigned note."""
        assert create_node("computing_core__sbom_document", {**ON_GRID, "verified": None, "verification_note": "unsigned; read from https://anchore.example:8228/v2 as acct"}).success
        run_against(monkeypatch, instance())
        doc = document()
        assert (doc.verification_note, doc.authenticated_source) == ("", KEY)
        assert Package.objects.count() == 2 and SbomDocument.objects.filter(content_digest=CONTENT).count() == 1

    @pytest.mark.parametrize(
        "fields",
        [
            {"authenticated_source": '["https://other.example/v2","acct"]'},
            {"verification_note": "unsigned; kept by another collector"},
            {"verification_note": "no attestation was published"},
        ],
    )
    def test_an_unverified_document_from_another_scanner_or_collector_keeps_its_fields(self, secrets, monkeypatch, fields):
        """Its source or its note is not this scanner's, so the row is not this scanner's to restage."""
        assert create_node("computing_core__sbom_document", {**ON_GRID, "verified": None, **fields}).success
        run_against(monkeypatch, instance())
        doc = document()
        assert {name: getattr(doc, name) for name in fields} == fields
        assert doc.authenticated_source == fields.get("authenticated_source", "")
        assert Package.objects.count() == 0


class TestOnlyThePlaceholderIsRewritten:
    def test_the_parser_names_no_entity_id_but_the_host_it_was_given(self):
        """What the collector's rewrite rests on, checked against the real parser and its corpus document."""
        import uuid
        from pathlib import Path

        import tap_plugin.computing_core.sbom as sbom

        corpus = Path(sbom.__file__).resolve().parents[1] / "tests" / "corpus" / "tap-web-latest-arm64.cdx.json"
        if not corpus.exists():
            pytest.skip("computing_core is installed without its test corpus")
        placeholder = str(uuid.uuid4())
        batch = sbom.parse_cyclonedx(corpus.read_bytes(), host_id=placeholder, verification=sbom.Verification("source-authenticated", source=KEY))
        ids = {value for edge in batch.edges for value in (edge.from_entity_id, edge.to_entity_id) if value is not None}
        assert ids == {placeholder}
