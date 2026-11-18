"""The neutral finding beside each Anchore finding, and the shared vulnerability record (req-anchore-neutral).

Written through the real importer into compliance_core's own types. Spec-derived payloads.
"""

import pytest
import tap_plugin.anchore.models as anchore  # noqa: F401 — trigger model registration
import tap_plugin.compliance_core.models as compliance  # noqa: F401 — trigger model registration
import tap_plugin.computing_core.models as computing  # noqa: F401 — trigger model registration
from tap_plugin.compliance_core.models.compliance_finding import ComplianceFinding
from tap_plugin.compliance_core.models.compliance_vulnerability import ComplianceVulnerability
from tap_plugin.computing_core.models.host import Host
from tap_plugin.computing_core.models.package import Package

from tap_grid.models import Edge
from tap_grid.services import create_node
from tap_plugin.anchore import neutral
from tap_plugin.anchore.models.finding import AnchoreFinding
from tap_plugin.anchore.tests.conftest import dimension_view, vulnerability_dimensions_declared
from tap_plugin.anchore.tests.test_collector_run import DIGEST, KEY, Instance, no_sockets, run_against, secrets, vuln  # noqa: F401 — fixtures

NVD = [{"id": "CVE-2024-0001", "type": "Primary", "source": "nvd@nist.gov", "cvss_v2": {"base_score": 5.0}, "cvss_v3": {"base_score": 9.8}}]


@pytest.fixture(autouse=True)
def compliance_types_writable():
    vulnerability_dimensions_declared()


def edges(slug: str) -> list[Edge]:
    return list(Edge.objects.filter(edge_type=slug).select_related("from_entity", "to_entity"))


class TestPure:
    FIELDS = {"scanner_key": KEY, "vulnerability_id": "CVE-2024-0001", "target_kind": "image", "target_key": DIGEST, "package_key": "a" * 64, "state": "current", "severity": "High", "fix": "1.2.3", "package_name": "libx"}

    def test_the_key_is_the_producer_and_a_digest_of_anchores_own_key(self):
        key = neutral.finding_key(self.FIELDS)
        assert key["source"] == "anchore" and len(key["source_key"]) == 64
        assert neutral.finding_key({**self.FIELDS, "severity": "Low"}) == key
        assert neutral.finding_key({**self.FIELDS, "package_key": "b" * 64}) != key

    @pytest.mark.parametrize("state, status", [("current", "open"), ("resolved", "resolved"), (None, "open")])
    def test_status_follows_anchores_state(self, state, status):
        assert neutral.finding_node("r", {**self.FIELDS, "state": state}, {})["node"]["status"] == status

    def test_the_name_and_summary_say_what_and_how_bad(self):
        node = neutral.finding_node("r", self.FIELDS, {"compliance": "finding"})
        assert (node["node"]["name"], node["node"]["summary"]) == ("CVE-2024-0001 in libx", "High, fix 1.2.3")
        assert node["entity"]["dimensions"] == {"compliance": "finding"}

    def test_detection_time_is_sent_only_where_anchore_gave_one(self):
        assert "first_detected_at" not in neutral.finding_node("r", self.FIELDS, {})["node"]
        timed = neutral.finding_node("r", {**self.FIELDS, "detected_at": "2026-11-01T10:00:00Z"}, {})["node"]
        assert timed["first_detected_at"].startswith("2026-11-01T10:00:00")

    @pytest.mark.parametrize(
        "fix, will_not_fix, expected",
        [
            ("1.2.3", None, {"fixed_versions": ["1.2.3"], "fix_state": "fixed"}),
            ("1.2.3, 1.3.0", False, {"fixed_versions": ["1.2.3", "1.3.0"], "fix_state": "fixed"}),
            ("None", None, {"fixed_versions": [], "fix_state": "not-fixed"}),
            ("None", True, {"fixed_versions": [], "fix_state": "wont-fix"}),
            (None, None, {"fixed_versions": []}),
        ],
    )
    def test_the_fix_rides_the_edge_to_the_vulnerability(self, fix, will_not_fix, expected):
        assert neutral.concerns_properties({"fix": fix, "will_not_fix": will_not_fix}) == expected

    def test_the_score_is_nvds_version_three_from_the_primary_entry(self):
        secondary_first = [{"type": "Secondary", "source": "other", "cvss_v3": {"base_score": 4.0}}, *NVD]
        assert neutral.cvss_of({"nvd_data": secondary_first}) == {"cvss_score": 9.8, "cvss_version": "3", "cvss_source": "nvd@nist.gov, as returned by Anchore"}

    @pytest.mark.parametrize("nvd", [None, [], [{"cvss_v3": {"base_score": -1.0}, "cvss_v2": {"base_score": -1.0}}], [{"cvss_v3": None}], ["text"], [{"cvss_v3": {"base_score": 11}}]])
    def test_a_missing_or_negative_score_is_no_score(self, nvd):
        assert neutral.cvss_of({"nvd_data": nvd}) == {}

    def test_a_secondary_version_three_is_used_before_a_primary_version_two(self):
        mixed = [{"type": "Primary", "source": "p", "cvss_v2": {"base_score": 5.0}}, {"type": "Secondary", "source": "s", "cvss_v3": {"base_score": 8.1}}]
        assert neutral.cvss_of({"nvd_data": mixed}) == {"cvss_score": 8.1, "cvss_version": "3", "cvss_source": "s, as returned by Anchore"}

    def test_the_record_carries_exactly_the_dimensions_it_is_given(self):
        assert neutral.vulnerability_node("r", "CVE-1", {"compliance": "vulnerability"}, {})["entity"]["dimensions"] == {"compliance": "vulnerability"}
        assert neutral.vulnerability_node("r", "CVE-1", {"x": "held"}, {"cvss_score": 1.0})["entity"]["dimensions"] == {"x": "held"}

    def test_version_two_is_used_where_there_is_no_version_three(self):
        assert neutral.cvss_of({"nvd_data": [{"cvss_v3": {"base_score": -1.0}, "cvss_v2": {"base_score": 5.0}}]})["cvss_version"] == "2"


@pytest.mark.django_db
class TestWritten:
    def test_each_anchore_finding_has_one_neutral_finding_joined_to_it(self, secrets, monkeypatch):
        run_against(monkeypatch, Instance())
        assert AnchoreFinding.objects.count() == ComplianceFinding.objects.count() == 2
        for edge in edges("DETAILS_COMPLIANCE_FINDING__anchore"):
            own = AnchoreFinding.objects.get(entity_id=edge.from_entity_id)
            shared = ComplianceFinding.objects.get(entity_id=edge.to_entity_id)
            assert (shared.source, shared.status) == ("anchore", "open")
            assert shared.name.startswith(own.vulnerability_id)
        assert len(edges("DETAILS_COMPLIANCE_FINDING__anchore")) == 2

    def test_a_neutral_finding_carries_no_anchore_dimension(self, secrets, monkeypatch):
        run_against(monkeypatch, Instance())
        for row in ComplianceFinding.objects.all():
            assert not [key for key in dimension_view(row.entity) if key.startswith("anchore.")]

    def test_the_image_carries_it_where_no_package_is_known(self, secrets, monkeypatch):
        run_against(monkeypatch, Instance())
        host = Host.objects.get(stable_id=DIGEST)
        carried = edges("CARRIES_COMPLIANCE_FINDING__compliance_core")
        assert len(carried) == 2 and {e.from_entity_id for e in carried} == {host.entity_id}

    def test_the_package_carries_it_where_the_inventory_holds_the_package(self, secrets, monkeypatch):
        from tap_plugin.anchore.tests.test_collector_sbom_inventory import instance

        run_against(monkeypatch, instance())
        by_vuln = {e.to_entity.name.split(" ")[0]: e.from_entity for e in edges("CARRIES_COMPLIANCE_FINDING__compliance_core")}
        assert by_vuln["CVE-2024-0001"].pk == Package.objects.get(name="libx").entity_id
        assert by_vuln["CVE-2024-0002"].entity_type == "computing_core__host"

    def test_it_concerns_the_vulnerability_with_the_fix_on_the_edge(self, secrets, monkeypatch):
        run_against(monkeypatch, Instance())
        by_vuln = {e.to_entity.name: e.properties for e in edges("CONCERNS_COMPLIANCE_VULNERABILITY__compliance_core")}
        assert by_vuln["CVE-2024-0001"] == {"fixed_versions": ["1.2.3"], "fix_state": "fixed"}
        assert by_vuln["CVE-2024-0002"] == {"fixed_versions": []}

    def test_a_second_run_writes_no_second_neutral_finding_or_edge(self, secrets, monkeypatch):
        instance = Instance()
        run_against(monkeypatch, instance)
        run_against(monkeypatch, instance)
        assert ComplianceFinding.objects.count() == 2 and ComplianceVulnerability.objects.count() == 2
        for slug in ("DETAILS_COMPLIANCE_FINDING__anchore", "CARRIES_COMPLIANCE_FINDING__compliance_core", "CONCERNS_COMPLIANCE_VULNERABILITY__compliance_core"):
            assert len(edges(slug)) == 2, slug

    def test_a_finding_that_resolves_closes_its_neutral_finding(self, secrets, monkeypatch):
        instance = Instance()
        run_against(monkeypatch, instance)
        instance.vulns[DIGEST] = [vuln()]
        run_against(monkeypatch, instance)
        status = {f.name.split(" ")[0]: f.status for f in ComplianceFinding.objects.all()}
        assert status == {"CVE-2024-0001": "open", "CVE-2024-0002": "resolved"}
        assert ComplianceFinding.objects.count() == 2


@pytest.mark.django_db
class TestStoredBeforeTheNeutralShape:
    """A finding the grid held before this plugin wrote neutral findings, resolving on its first run after."""

    def test_it_gets_its_neutral_finding_resolved_with_the_carrier_and_the_vulnerability(self, secrets, monkeypatch):
        instance = Instance()
        run_against(monkeypatch, instance)
        # Put the grid back to how an older release left it: Anchore's findings, nothing neutral.
        from tap_grid.services import delete_node

        for row in list(ComplianceFinding.objects.all()):
            assert delete_node(row.entity_id).success
        assert ComplianceFinding.objects.count() == 0
        instance.vulns[DIGEST] = [vuln()]
        run_against(monkeypatch, instance)
        closed = ComplianceFinding.objects.get(name__startswith="CVE-2024-0002")
        assert closed.status == "resolved"
        carriers = [e for e in edges("CARRIES_COMPLIANCE_FINDING__compliance_core") if e.to_entity_id == closed.entity_id]
        assert [e.from_entity.entity_type for e in carriers] == ["computing_core__host"]
        concerns = [e for e in edges("CONCERNS_COMPLIANCE_VULNERABILITY__compliance_core") if e.from_entity_id == closed.entity_id]
        assert [e.to_entity.name for e in concerns] == ["CVE-2024-0002"]

    def test_a_finding_the_image_carries_gains_no_second_carrier_when_the_inventory_arrives(self, secrets, monkeypatch):
        from tap_plugin.anchore.tests.test_collector_sbom_inventory import CDX
        from tap_plugin.anchore.tests.test_collector_sbom_inventory import instance as with_inventory

        # First the SBOM lists no package, so nothing says which one the finding is in.
        server = with_inventory()
        server.sboms[(DIGEST, "cyclonedx-json")] = {**CDX, "components": []}
        run_against(monkeypatch, server)
        finding = ComplianceFinding.objects.get(name__startswith="CVE-2024-0001")
        assert [e.from_entity.entity_type for e in edges("CARRIES_COMPLIANCE_FINDING__compliance_core") if e.to_entity_id == finding.entity_id] == ["computing_core__host"]
        server.sboms[(DIGEST, "cyclonedx-json")] = CDX
        run_against(monkeypatch, server)
        finding = ComplianceFinding.objects.get(name__startswith="CVE-2024-0001")
        carriers = [e.from_entity.entity_type for e in edges("CARRIES_COMPLIANCE_FINDING__compliance_core") if e.to_entity_id == finding.entity_id]
        assert carriers == ["computing_core__host"]

    def test_a_resolving_finding_a_package_carries_gains_no_second_carrier(self, secrets, monkeypatch):
        from tap_plugin.anchore.tests.test_collector_sbom_inventory import instance as with_inventory

        server = with_inventory()
        run_against(monkeypatch, server)
        server.vulns[DIGEST] = []
        run_against(monkeypatch, server)
        closed = ComplianceFinding.objects.get(name__startswith="CVE-2024-0001")
        carriers = [e.from_entity.entity_type for e in edges("CARRIES_COMPLIANCE_FINDING__compliance_core") if e.to_entity_id == closed.entity_id]
        assert closed.status == "resolved" and carriers == ["computing_core__package"]


@pytest.mark.django_db
class TestVulnerabilityRecord:
    def test_an_absent_record_is_created_with_anchores_score(self, secrets, monkeypatch):
        run_against(monkeypatch, Instance(vulns=[vuln(nvd_data=NVD), vuln("CVE-2024-0002")]))
        scored, bare = ComplianceVulnerability.objects.get(vuln_id="CVE-2024-0001"), ComplianceVulnerability.objects.get(vuln_id="CVE-2024-0002")
        assert (scored.cvss_score, scored.cvss_version, scored.cvss_source) == (9.8, "3", "nvd@nist.gov, as returned by Anchore")
        assert bare.cvss_score is None

    def test_a_score_a_later_finding_carries_reaches_a_record_met_first_without_one(self):
        """Order of reading must not decide the score: across images, and across scanners."""
        from tap_plugin.anchore.collectors.anchore_collector.collector import AnchoreCollector, _Scanner, _Shared

        def finding(vuln_id, **fields):
            return {"entity": {"ref": "f"}, "node": {"vulnerability_id": vuln_id, **fields}}

        assert create_node("compliance_core__compliance_vulnerability", {"vuln_id": "CVE-2024-0009"}).success
        collector, first, shared = object.__new__(AnchoreCollector), _Scanner(), _Shared()
        collector._vulnerabilities(first, [finding("CVE-2024-0008"), finding("CVE-2024-0009")], shared)
        # A later image of the same scanner scores the record being created, in place.
        collector._vulnerabilities(first, [finding("CVE-2024-0008", nvd_data=NVD)], shared)
        created = [n for n in first.nodes if n["node"]["vuln_id"] == "CVE-2024-0008"]
        assert len(created) == 1 and created[0]["node"]["cvss_score"] == 9.8
        # A later scanner scores the record the grid held without one.
        shared.absorb(first)
        second = _Scanner()
        collector._vulnerabilities(second, [finding("CVE-2024-0009", nvd_data=NVD)], shared)
        assert [n["node"].get("cvss_score") for n in second.nodes] == [9.8]
        # And once scored, a further score is not staged again.
        collector._vulnerabilities(second, [finding("CVE-2024-0009", nvd_data=NVD)], shared)
        assert len(second.nodes) == 1

    def test_a_record_with_no_score_gains_anchores_and_keeps_its_other_fields(self, secrets, monkeypatch):
        assert create_node("compliance_core__compliance_vulnerability", {"vuln_id": "CVE-2024-0001", "title": "A title another source wrote", "kev": True}).success
        held = ComplianceVulnerability.objects.get(vuln_id="CVE-2024-0001")
        before = (held.entity.name, dimension_view(held.entity))
        run_against(monkeypatch, Instance(vulns=[vuln(nvd_data=NVD)]))
        record = ComplianceVulnerability.objects.get(vuln_id="CVE-2024-0001")
        assert (record.cvss_score, record.title, record.kev) == (9.8, "A title another source wrote", True)
        # The fill changed the score and nothing about the record's identity on the spine.
        assert (record.entity.name, dimension_view(record.entity)) == before

    def test_a_record_that_already_has_a_score_is_not_touched(self, secrets, monkeypatch):
        assert create_node("compliance_core__compliance_vulnerability", {"vuln_id": "CVE-2024-0001", "cvss_score": 7.5, "cvss_source": "another source"}).success
        before = ComplianceVulnerability.objects.get(vuln_id="CVE-2024-0001").entity.version
        run_against(monkeypatch, Instance(vulns=[vuln(nvd_data=NVD)]))
        record = ComplianceVulnerability.objects.get(vuln_id="CVE-2024-0001")
        assert (record.cvss_score, record.cvss_source) == (7.5, "another source")
        assert record.entity.version == before

    def test_an_identifier_too_long_for_the_record_gets_no_record_and_no_edge_to_one(self, secrets, monkeypatch):
        long_id = "X" * 129
        run_against(monkeypatch, Instance(vulns=[vuln(long_id)]))
        assert not ComplianceVulnerability.objects.exists()
        assert ComplianceFinding.objects.count() == 1 and edges("CONCERNS_COMPLIANCE_VULNERABILITY__compliance_core") == []
