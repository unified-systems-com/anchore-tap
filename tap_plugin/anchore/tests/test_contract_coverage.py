"""Every read in Anchore's API is landed, planned, or excluded with a reason (req-anchore-coverage)."""

import json
import re

import pytest

from tap_plugin.anchore.contract import coverage

RULES = json.loads(coverage.RULES.read_text(encoding="utf-8"))["rules"]
READS = coverage.classify()
RULED_OUT = re.compile(r"^/(accounts|rbac-manager|user|my-user-groups|registries)(/|$)|/artifacts/(secret-search|retrieved-files|file-content-search)$")


class TestEveryReadIsAccountedFor:
    def test_each_get_of_the_vendor_file_has_exactly_one_status(self):
        vendor = json.loads(coverage.SOURCE.read_text(encoding="utf-8"))["paths"]
        gets = sorted(path for path, item in vendor.items() if "get" in item)
        assert [read.path for read in READS] == gets
        assert {read.status for read in READS} <= {coverage.LANDED, coverage.PLANNED, coverage.EXCLUDED}

    def test_landed_is_what_the_manifest_reads_and_nothing_else(self):
        manifest = {source["path"] for source in json.loads(coverage.MANIFEST.read_text(encoding="utf-8"))["sources"]}
        assert {read.path for read in READS if read.status == coverage.LANDED} == manifest


class TestExclusions:
    def test_every_rule_is_well_formed_and_every_exclusion_gives_its_reason(self):
        for rule in RULES:
            re.compile(rule["pattern"])
            assert rule["status"] in (coverage.PLANNED, coverage.EXCLUDED)
            assert rule["reason"].strip()
        assert all(read.note.strip() for read in READS if read.status == coverage.EXCLUDED)

    def test_every_rule_matches_some_read(self):
        """A rule that matches nothing is a stale line: the read it named is gone or was renamed."""
        for rule in RULES:
            assert any(re.search(rule["pattern"], read.path) for read in READS), rule["pattern"]

    def test_the_ruled_exclusions_hold(self):
        ruled = [read for read in READS if RULED_OUT.search(read.path)]
        assert ruled and all(read.status == coverage.EXCLUDED for read in ruled)


class TestTheTableIsGenerated:
    def test_the_specs_section_is_what_the_generator_prints(self):
        if not coverage.SPEC.exists():
            pytest.skip("the plugin is installed without its spec")
        assert coverage.spec_section(coverage.SPEC.read_text(encoding="utf-8")) == coverage.render(READS)
        assert coverage.main(["--check"]) == 0

    def test_the_counts_add_up_and_the_planned_list_is_the_work_left(self):
        text = coverage.render(READS)
        planned = [read for read in READS if read.status == coverage.PLANNED]
        assert f"has {len(READS)} reads" in text and f"{len(planned)} are planned" in text
        assert all(f"| `{read.path}` |" in text for read in planned)
