"""The collector's GRIFT document states core's header: format "1", the spine's version and each type's (tap#1284)."""

import pytest

from tap_plugin.anchore.collectors.anchore_collector.collector import AnchoreCollector
from tap_plugin.anchore.tests.test_collector_run import Instance, no_sockets, run_against, secrets  # noqa: F401 — fixtures


@pytest.mark.django_db
def test_a_run_submits_a_format_one_document_with_core_s_header(secrets, monkeypatch):  # noqa: F811
    sent = []
    original = AnchoreCollector.submit_grift

    def spy(self, document, *args, **kwargs):
        sent.append(document)
        return original(self, document, *args, **kwargs)

    monkeypatch.setattr(AnchoreCollector, "submit_grift", spy)
    run_against(monkeypatch, Instance())
    assert sent
    for document in sent:
        header = document["metadata"]
        assert header["grift_version"] == "1"
        assert isinstance(header["spine_version"], int)
        carried = {node["entity"]["entity_type"] for batch in document["batches"] for node in batch["nodes"]}
        assert carried and carried <= set(header["type_versions"])
