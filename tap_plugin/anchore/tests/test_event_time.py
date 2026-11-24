"""Event time (`req-anchore-event-time`): what each model declares, then what a collected grid holds.

Core derives `event_start`, `event_end` and the `time` dimension from the field a model names
(`req-grid-entity-event-time`). The first class reads the declarations only. The second runs the
collector against canned instances and reads the spine, so a declaration that names the wrong field,
or a field the collector leaves in a form core cannot read, fails here.
"""

import json
from pathlib import Path

import pytest

from tap_grid.event_time import NO_EVENT_TIME, Interval, Moment
from tap_grid.registry import get_model_class, list_entity_types
from tap_plugin.anchore.models import (
    AnchoreFinding,
    AnchoreImage,
    AnchorePolicyEvaluation,
    AnchoreRuntimeImage,
    AnchoreScanner,
    AnchoreScanRun,
    AnchoreVexAnnotation,
)
from tap_plugin.anchore.tests import test_collector_policy, test_collector_vex
from tap_plugin.anchore.tests.conftest import dimension_view
from tap_plugin.anchore.tests.test_collector_image_record import IMAGE
from tap_plugin.anchore.tests.test_collector_run import DIGEST, Instance, no_sockets, run_against, secrets  # noqa: F401 — fixtures
from tap_plugin.anchore.tests.test_collector_scope import item
from tap_plugin.anchore.tests.test_collector_sbom_inventory import instance as with_inventory

EDGES = Path(__file__).resolve().parents[1] / "edges"

DECLARED = {
    AnchoreFinding: Moment(field="detected_at", kind="first_seen"),
    AnchoreImage: Interval(start="created_at", kind="first_seen"),
    AnchoreRuntimeImage: Interval(start="created_at", kind="first_seen"),
    AnchorePolicyEvaluation: Moment(field="evaluation_time", kind="occurred"),
    AnchoreVexAnnotation: Interval(start="annotation_created_at", kind="created"),
    AnchoreScanRun: Interval(start="started_at", end="finished_at", kind="occurred"),
    AnchoreScanner: NO_EVENT_TIME,
}


def spine(row) -> tuple:
    """A typed row's event time on the spine: start, end, and the kind held as its `time` dimension."""
    entity = row.entity
    entity.refresh_from_db()
    return entity.event_start, entity.event_end, dimension_view(entity).get("tap.time")


class TestDeclarations:
    def test_every_model_of_the_plugin_decides(self):
        """None is left undeclared (`req-anchore-event-time-1`): this is the list the later failure will read."""
        own = {get_model_class(slug) for slug in list_entity_types() if slug.startswith("anchore__")}
        assert own == set(DECLARED)
        assert {model: model.EVENT_TIME for model in own} == DECLARED

    def test_each_declared_field_is_a_field_of_its_model(self):
        for model, declaration in DECLARED.items():
            names = [n for n in (getattr(declaration, "field", None), getattr(declaration, "start", None), getattr(declaration, "end", None)) if n]
            assert all(model._meta.get_field(name) for name in names)

    def test_no_edge_type_declares_one(self):
        """`req-anchore-event-time-4`: no edge of the plugin carries a time among its properties."""
        definitions = [json.loads(path.read_text(encoding="utf-8")) for path in sorted(EDGES.glob("*.edge.json"))]
        assert definitions and not [d["edge_type"] for d in definitions if "event_time" in d]


@pytest.mark.django_db
class TestOnACollectedGrid:
    def test_a_run_holds_from_its_start_to_its_finish(self, secrets, monkeypatch):  # noqa: F811
        run_against(monkeypatch, with_inventory())
        run = AnchoreScanRun.objects.get()
        assert run.started_at is not None and run.finished_at is not None
        assert spine(run) == (run.started_at, run.finished_at, "occurred")

    def test_a_scanner_has_none(self, secrets, monkeypatch):  # noqa: F811
        """`req-anchore-event-time-3`."""
        run_against(monkeypatch, with_inventory())
        assert spine(AnchoreScanner.objects.get()) == (None, None, None)

    def test_an_image_is_open_from_anchores_record_of_it(self, secrets, monkeypatch):  # noqa: F811
        run_against(monkeypatch, Instance(images=[IMAGE]))
        (image,) = AnchoreImage.objects.all()
        assert image.created_at.isoformat() == "2026-11-01T08:00:00+00:00"
        assert spine(image) == (image.created_at, None, "first_seen")

    def test_a_row_whose_field_is_empty_has_no_event_time(self, secrets, monkeypatch):  # noqa: F811
        """Never defaulted: no collection time or write time stands in for a time Anchore did not give."""
        server = with_inventory()
        server.inventory = [item("prod/default", DIGEST)]
        run_against(monkeypatch, server)
        rows = [*AnchoreImage.objects.filter(created_at=None), *AnchoreFinding.objects.filter(detected_at=None), *AnchoreRuntimeImage.objects.filter(created_at=None)]
        assert {type(row) for row in rows} >= {AnchoreRuntimeImage}
        for row in rows:
            assert spine(row) == (None, None, None)

    def test_a_finding_is_at_anchores_detection(self, secrets, monkeypatch):  # noqa: F811
        server = with_inventory()
        for records in server.vulns.values():
            for record in records:
                record["detected_at"] = "2026-11-01T10:00:00Z"
        run_against(monkeypatch, server)
        findings = list(AnchoreFinding.objects.all())
        assert findings
        for finding in findings:
            assert finding.detected_at == "2026-11-01T10:00:00Z"  # the text as Anchore sent it
            start, end, kind = spine(finding)
            assert (start.isoformat(), end.isoformat(), kind) == ("2026-11-01T10:00:00+00:00", "2026-11-01T10:00:00+00:00", "first_seen")

    def test_a_detection_time_with_no_zone_is_kept_and_not_copied(self, secrets, monkeypatch):  # noqa: F811
        """Core assumes no zone; the plugin keeps Anchore's text and does not repair it."""
        server = with_inventory()
        for records in server.vulns.values():
            for record in records:
                record["detected_at"] = "2026-11-01T10:00:00"
        run_against(monkeypatch, server)
        finding = AnchoreFinding.objects.first()
        assert finding.detected_at == "2026-11-01T10:00:00" and spine(finding) == (None, None, None)

    def test_a_policy_evaluation_is_when_anchore_evaluated(self, secrets, monkeypatch):  # noqa: F811
        run_against(monkeypatch, test_collector_policy.server())
        evaluations = [e for e in AnchorePolicyEvaluation.objects.all() if e.evaluation_time is not None]
        assert evaluations
        for evaluation in evaluations:
            assert spine(evaluation) == (evaluation.evaluation_time, evaluation.evaluation_time, "occurred")

    def test_an_annotation_is_open_from_its_creation(self, secrets, monkeypatch):  # noqa: F811
        run_against(monkeypatch, test_collector_vex.server(test_collector_vex.entry()))
        annotations = [a for a in AnchoreVexAnnotation.objects.all() if a.annotation_created_at is not None]
        assert annotations
        for annotation in annotations:
            assert spine(annotation) == (annotation.annotation_created_at, None, "created")

    def test_a_runtime_image_is_open_and_its_last_sighting_is_not_its_end(self, secrets, monkeypatch):  # noqa: F811
        server = Instance()
        server.inventory = [item("prod/default", DIGEST, created_at="2026-11-01T08:00:00Z")]
        run_against(monkeypatch, server)
        (row,) = AnchoreRuntimeImage.objects.all()
        assert row.last_seen is not None and row.created_at.isoformat() == "2026-11-01T08:00:00+00:00"
        assert spine(row) == (row.created_at, None, "first_seen")
