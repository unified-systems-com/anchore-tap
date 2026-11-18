"""The standard pages (`req-anchore-pages`): the bundle as written, then its Searches run on a collected grid.

The first class reads the JSON only. The second imports the bundle through the real importer, runs the
collector against a canned instance and executes every Search, so a query the grid refuses fails here
and not in a browser. How the pages look was checked in a browser against a dev stack, not here.
"""

import json
import re
from pathlib import Path

import pytest

from tap_grid.grift.importer import grift_import
from tap_grid.gryphon.executor import execute_gryphon_raw
from tap_plugin.anchore.tests.test_collector_run import DIGEST, Instance, no_sockets, run_against, secrets  # noqa: F401 — fixtures
from tap_plugin.anchore.tests.test_collector_sbom_inventory import instance as with_inventory

BUNDLE = Path(__file__).resolve().parents[1] / "grift" / "pages.grift.json"
PAGES = {"/anchore", "/anchore/images", "/anchore/image", "/anchore/image/sbom", "/anchore/health"}
STANDARD = {"table_panel", "stat_card_panel", "text_panel", "html"}
# What a Search may name: this plugin's own types and the two plugins it depends on for images and packages.
VOCABULARY = ("anchore__", "computing_core__")


def bundle() -> dict:
    return json.loads(BUNDLE.read_text(encoding="utf-8"))


def of(kind: str) -> list[dict]:
    return [n for n in bundle()["batches"][0]["nodes"] if n["entity"]["entity_type"] == kind]


def edges(kind: str) -> list[dict]:
    return [e["edge"] for e in bundle()["batches"][0]["edges"] if e["edge"]["edge_type"] == kind]


class TestBundle:
    def test_the_five_pages_and_only_those(self):
        assert {p["node"]["slug"] for p in of("page")} == PAGES

    def test_the_two_pages_that_need_a_digest_are_not_offered_without_one(self):
        hidden = {p["node"]["slug"] for p in of("page") if p["node"].get("discoverable") is False}
        assert hidden == {"/anchore/image", "/anchore/image/sbom"}

    def test_every_id_is_used_once(self):
        batch = bundle()["batches"][0]
        ids = [batch["batch_entity"]["entity_id"]] + [n["entity"]["entity_id"] for n in batch["nodes"]] + [e["entity"]["entity_id"] for e in batch["edges"]]
        assert len(ids) == len(set(ids))

    def test_every_panel_is_a_standard_type(self):
        """No custom panel type: the pages are data (`req-anchore-pages-2`)."""
        views = {p["node"]["view"] for p in of("panel")}
        assert {v.removeprefix("tap_web/panels/").removesuffix(".html") for v in views} <= STANDARD

    def test_every_slot_has_its_panel_and_every_panel_a_slot(self):
        panels = {p["entity"]["entity_id"]: p["node"]["slug"] for p in of("panel")}
        for page in of("page"):
            slots = {row["panel-id"] for column in page["node"]["layout"]["columns"].values() for row in column["rows"].values()}
            mounted = {e["properties"]["hotlink"]["value"]: panels[e["to_entity_id"]] for e in edges("USES_PANEL") if e["from_entity_id"] == page["entity"]["entity_id"]}
            assert set(mounted) == slots and all(slot == slug for slot, slug in mounted.items()), page["node"]["slug"]
        assert {e["to_entity_id"] for e in edges("USES_PANEL")} == set(panels)

    def test_every_table_and_card_reads_one_search_and_shows_only_what_it_returns(self):
        searches = {s["entity"]["entity_id"]: s["node"] for s in of("search")}
        used = set()
        for panel in of("panel"):
            links = [e["to_entity_id"] for e in edges("USES_SEARCH") if e["from_entity_id"] == panel["entity"]["entity_id"]]
            view = panel["node"]["view"]
            if "table_panel" not in view and "stat_card" not in view:
                assert links == []
                continue
            assert len(links) == 1, panel["node"]["slug"]
            used.add(links[0])
            returned = set(re.findall(r" AS ([a-z_]+)", " ".join(searches[links[0]]["definition"]["query"])))
            config = panel["node"]["config"]
            shown = {c["field"] for c in config["columns"]} if "columns" in config else {config["value_field"]}
            assert shown <= returned, (panel["node"]["slug"], shown - returned)
            for column in config.get("columns", []):
                template = (column.get("formatter_params") or {}).get("href_template", "")
                assert set(re.findall(r"\{([a-z_]+)\}", template)) <= returned, panel["node"]["slug"]
        assert used == set(searches), "a Search no panel reads"

    def test_a_search_names_only_this_plugins_types_and_its_dependencies(self):
        for search in of("search"):
            query = " ".join(search["node"]["definition"]["query"])
            for label in re.findall(r"\(\w+:([a-z0-9_]+)\)", query):
                assert label.startswith(VOCABULARY), (search["node"]["name"], label)

    def test_no_search_orders_a_traversal(self):
        """Gryphon refuses ORDER BY on a traversal pattern; the table sorts instead."""
        for search in of("search"):
            query = " ".join(search["node"]["definition"]["query"])
            assert not ("ORDER BY" in query and "]->" in query), search["node"]["name"]

    def test_links_between_pages_point_at_pages_of_the_bundle(self):
        text = BUNDLE.read_text(encoding="utf-8")
        targets = set(re.findall(r'"(/anchore[a-z/]*)\?', text)) | set(re.findall(r'href=\\"(/anchore[a-z/]*)\\"', text))
        assert targets and targets <= PAGES


@pytest.mark.django_db
class TestSearchesOnACollectedGrid:
    @pytest.fixture
    def rows(self, secrets, monkeypatch):  # noqa: F811
        result = grift_import(bundle())
        assert result.success, result.errors
        server = with_inventory()
        run_against(monkeypatch, server)
        # A second run in which one finding is gone, so the grid holds a resolved finding too.
        server.vulns[DIGEST] = server.vulns[DIGEST][:1]
        run_against(monkeypatch, server)

        queries = {s["node"]["name"].removeprefix("anchore — "): "\n".join(s["node"]["definition"]["query"]) for s in of("search")}

        def run(name: str, **inputs) -> list[dict]:
            # The default connection, not the read-only role: a test's rows are in its own open transaction.
            return execute_gryphon_raw(queries[name], inputs, db_alias="default").get("rows", [])

        return run

    def test_every_search_runs(self, rows):
        for search in of("search"):
            needs = (search["node"].get("input_schema") or {}).get("required", [])
            rows(search["node"]["name"].removeprefix("anchore — "), **{name: DIGEST for name in needs})

    def test_the_cards_count_current_and_resolved_apart(self, rows):
        assert rows("card-open") == [{"n": 1}] and rows("card-resolved") == [{"n": 1}]

    def test_an_open_finding_names_its_image_by_digest(self, rows):
        (row,) = rows("open-findings")
        assert (row["vuln"], row["digest"]) == ("CVE-2024-0001", DIGEST)

    def test_the_image_page_shows_current_and_resolved_findings(self, rows):
        assert {r["state"] for r in rows("image-findings", digest=DIGEST)} == {"current", "resolved"}

    def test_the_sbom_page_lists_the_packages_and_the_documents(self, rows):
        assert {r["package"] for r in rows("sbom-packages", digest=DIGEST)} == {"libx", "liby"}
        assert "cyclonedx" in {r["format"] for r in rows("sbom-documents", digest=DIGEST)}

    def test_an_unknown_digest_is_no_rows_and_not_an_error(self, rows):
        for name in ("image-identity", "image-findings", "image-tags", "sbom-packages", "sbom-documents"):
            assert rows(name, digest="sha256:" + "0" * 64) == []

    def test_health_lists_each_run_with_its_record_id(self, rows):
        runs = rows("runs")
        assert len(runs) == 2 and all(r["id"] and r["selftest"] == "pass" for r in runs)
