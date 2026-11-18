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
class TestVulnerabilityRecord:
    def test_an_absent_record_is_created_with_anchores_score(self, secrets, monkeypatch):
        run_against(monkeypatch, Instance(vulns=[vuln(nvd_data=NVD), vuln("CVE-2024-0002")]))
        scored, bare = ComplianceVulnerability.objects.get(vuln_id="CVE-2024-0001"), ComplianceVulnerability.objects.get(vuln_id="CVE-2024-0002")
        assert (scored.cvss_score, scored.cvss_version, scored.cvss_source) == (9.8, "3", "nvd@nist.gov, as returned by Anchore")
        assert bare.cvss_score is None

    def test_a_record_with_no_score_gains_anchores_and_keeps_its_other_fields(self, secrets, monkeypatch):
        assert create_node("compliance_core__compliance_vulnerability", {"vuln_id": "CVE-2024-0001", "title": "A title another source wrote", "kev": True}).success
        run_against(monkeypatch, Instance(vulns=[vuln(nvd_data=NVD)]))
        record = ComplianceVulnerability.objects.get(vuln_id="CVE-2024-0001")
        assert (record.cvss_score, record.title, record.kev) == (9.8, "A title another source wrote", True)

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
