"""A large run is written as several batches (req-anchore-limits-7)."""

import pytest
import tap_plugin.anchore.models as anchore  # noqa: F401 — trigger model registration
import tap_plugin.compliance_core.models as compliance  # noqa: F401 — trigger model registration
import tap_plugin.computing_core.models as computing  # noqa: F401 — trigger model registration
from tap_plugin.computing_core.models.package import Package

from tap_grid.models import Edge
from tap_plugin.anchore import batching
from tap_plugin.anchore import credential as cred
from tap_plugin.anchore.collectors.anchore_collector import store
from tap_plugin.anchore.tests.test_anchore_credential import data, envelope
from tap_plugin.anchore.tests.test_collector_run import DIGEST, Instance, findings, no_sockets, run_against, vuln  # noqa: F401 — no_sockets is autouse
from tap_plugin.anchore.tests.test_collector_scope import configure


def node(ref: str, name: str) -> dict:
    return {"entity": {"ref": ref, "entity_type": "thing", "name": name, "dimensions": {}}, "node": {"name": name}}


def edge(ref: str, **ends) -> dict:
    return {"entity": {"ref": ref, "entity_type": "edge", "name": "JOINS", "dimensions": {}}, "edge": {"edge_type": "JOINS", "properties": {}, **ends}}


def by_name(row: dict):
    return {"entity_type": "thing", "key": {"name": row["node"]["name"]}}


NODES = [node(f"n{i}", f"name-{i}") for i in range(5)]
EDGES = [edge("e0", from_ref="n0", to_ref="n4"), edge("e1", from_ref="n1", to_key={"entity_type": "other", "key": {"k": "v"}}), edge("e2", from_ref="n2", to_ref="n3")]


class TestSplit:
    def test_a_run_that_fits_is_one_batch_untouched(self):
        assert batching.split(NODES, EDGES, 8, by_name) == ([(NODES, EDGES)], None)

    def test_a_larger_run_is_nodes_first_then_edges_named_by_key(self):
        batches, why = batching.split(NODES, EDGES, 2, by_name)
        assert why is None
        assert [(len(n), len(e)) for n, e in batches] == [(2, 0), (2, 0), (1, 0), (0, 2), (0, 1)]
        assert [row for nodes, _ in batches for row in nodes] == NODES
        staged = [row for _, edges in batches for row in edges]
        assert staged[0]["edge"] == {"edge_type": "JOINS", "properties": {}, "from_key": {"entity_type": "thing", "key": {"name": "name-0"}}, "to_key": {"entity_type": "thing", "key": {"name": "name-4"}}}
        # An end that already named its node by key is left as it was.
        assert staged[1]["edge"]["to_key"] == {"entity_type": "other", "key": {"k": "v"}}
        assert not any("from_ref" in row["edge"] or "to_ref" in row["edge"] for row in staged)

    def test_the_rows_passed_in_are_not_changed(self):
        before = [dict(row["edge"]) for row in EDGES]
        batching.split(NODES, EDGES, 2, by_name)
        assert [row["edge"] for row in EDGES] == before

    def test_a_node_whose_key_cannot_be_stated_keeps_the_run_whole_and_says_why(self):
        batches, why = batching.split(NODES, EDGES, 2, lambda row: None if row["node"]["name"] == "name-3" else by_name(row))
        assert batches == [(NODES, EDGES)] and "n3" in why

    def test_no_limit_is_one_batch(self):
        assert batching.split(NODES, EDGES, 0, by_name) == ([(NODES, EDGES)], None)


class TestSettings:
    def test_the_default_and_the_envelopes_value(self):
        assert cred.credential_from_envelope(envelope(payload=data())).settings.max_batch_rows == 5000
        assert cred.credential_from_envelope(envelope(payload=data(limits={"max_batch_rows": 100}))).settings.max_batch_rows == 100

    @pytest.mark.parametrize("rows", [0, 99, 200001, "5000", None])
    def test_a_value_out_of_range_is_refused(self, rows):
        with pytest.raises(cred.CredentialError):
            cred.credential_from_envelope(envelope(payload=data(limits={"max_batch_rows": rows})))


@pytest.mark.django_db
class TestARun:
    def test_every_staged_type_has_a_key_the_splitter_can_state(self, tmp_path, monkeypatch):
        """If a type the collector stages had no statable key, a large run could never be split."""
        seen = {}
        real = batching.split

        def spy(nodes, edges, max_rows, key_of):
            seen["unkeyed"] = sorted({n["entity"]["entity_type"] for n in nodes if key_of(n) is None})
            return real(nodes, edges, max_rows, key_of)

        monkeypatch.setattr(batching, "split", spy)
        configure(tmp_path, monkeypatch, {"running_only": False})
        run_against(monkeypatch, Instance())
        assert seen["unkeyed"] == []

    def test_a_run_over_the_limit_lands_whole_in_several_batches(self, tmp_path, monkeypatch):
        configure(tmp_path, monkeypatch, {"running_only": False}, limits={"max_batch_rows": 100})
        server = Instance(vulns=[vuln("CVE-2024-0001", purl="pkg:deb/debian/lib0@1.0")])
        components = [{"type": "library", "name": f"lib{i}", "version": "1.0", "purl": f"pkg:deb/debian/lib{i}@1.0"} for i in range(120)]
        server.sboms[(DIGEST, "cyclonedx-json")] = {"bomFormat": "CycloneDX", "specVersion": "1.6", "serialNumber": "urn:uuid:3e671687-395b-41f5-a30f-a58921a69b79", "version": 1, "metadata": {"timestamp": "2026-11-03T10:00:00Z"}, "components": components}
        collector = run_against(monkeypatch, server)
        (told,) = [m for m in collector.results["info"] if m["message_code"] == "BATCHES"]
        assert told["message_data"]["batches"] >= 3 and told["message_data"]["max_rows"] == 100
        # Everything is there, and the edges that crossed batches found their ends.
        assert Package.objects.count() == 120
        assert Edge.objects.filter(edge_type="INSTALLS_PACKAGE__computing_core").count() == 120
        assert Edge.objects.filter(edge_type="FOUND_IN_PACKAGE__anchore").count() == 1
        assert Edge.objects.filter(edge_type="FOUND_ON_IMAGE__anchore").count() == len(findings()) == 1
        assert Edge.objects.filter(edge_type="RUN_OF_SCANNER__anchore").count() == 1
