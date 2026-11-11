"""The operator's limits: the response size cap and the run time limit (req-anchore-limits-*)."""

import itertools

import pytest
import tap_plugin.anchore.models as anchore  # noqa: F401 — trigger model registration
import tap_plugin.compliance_core.models as compliance  # noqa: F401 — trigger model registration
import tap_plugin.computing_core.models as computing  # noqa: F401 — trigger model registration

from tap_plugin.anchore import client as cl
from tap_plugin.anchore import credential as cred
from tap_plugin.anchore.collectors.anchore_collector import collector as collector_module
from tap_plugin.anchore.tests.fakes import FakeTransport, response
from tap_plugin.anchore.tests.test_anchore_credential import data, envelope
from tap_plugin.anchore.tests.test_collector_run import DIGEST, OTHER, findings, no_sockets, run_against, vuln  # noqa: F401 — no_sockets is autouse
from tap_plugin.anchore.tests.test_collector_scope import configure, latest_run, not_read, read_images, two_images

MIB = 1024 * 1024


def credential(**limits):
    return cred.credential_from_envelope(envelope(payload=data(limits=limits) if limits else data()))


def ticking(monkeypatch, seconds: float) -> None:
    """A clock that moves on by ``seconds`` every time the collector looks at it."""
    ticks = itertools.count(0, seconds)
    monkeypatch.setattr(collector_module, "_monotonic", lambda: float(next(ticks)))


class TestSettings:
    def test_the_defaults_are_the_cap_as_it_was_and_no_time_limit(self):
        settings = credential().settings
        assert (settings.max_response_bytes, settings.max_run_minutes) == (64 * MIB, None)
        assert settings.as_recorded()["limits"] == {"max_response_mib": 64, "max_run_minutes": None, "max_batch_rows": 5000}

    def test_the_envelope_sets_them(self):
        settings = credential(max_response_mib=256, max_run_minutes=90).settings
        assert (settings.max_response_bytes, settings.max_run_minutes) == (256 * MIB, 90)
        assert settings.as_recorded()["limits"] == {"max_response_mib": 256, "max_run_minutes": 90, "max_batch_rows": 5000}

    @pytest.mark.parametrize(
        "limits",
        [{"max_response_mib": 0}, {"max_response_mib": 1025}, {"max_response_mib": "64"}, {"max_response_mib": 1.5}, {"max_run_minutes": 0}, {"max_run_minutes": 10081}, {"max_run_minutes": None}, {"max_seconds": 5}],
    )
    def test_a_limit_out_of_range_or_unknown_is_refused(self, limits):
        with pytest.raises(cred.CredentialError):
            cred.credential_from_envelope(envelope(payload=data(limits=limits)))


class TestResponseCap:
    def test_the_client_reads_up_to_the_envelopes_cap_and_no_further(self):
        body = b"x" * (MIB + 1)
        small = cl.ReadOnlyClient(credential(max_response_mib=1), transport=FakeTransport(default=response(200, body)), sleep=lambda s: None)
        with pytest.raises(cl.ResponseTooLarge):
            small.get("/images")
        roomy = cl.ReadOnlyClient(credential(max_response_mib=2), transport=FakeTransport(default=response(200, body)), sleep=lambda s: None)
        assert len(roomy.get("/images").body) == MIB + 1

    def test_a_caller_that_names_a_cap_keeps_it(self):
        client = cl.ReadOnlyClient(credential(max_response_mib=2), transport=FakeTransport(default=response(200, b"x" * 2000)), sleep=lambda s: None, max_bytes=1000)
        with pytest.raises(cl.ResponseTooLarge):
            client.get("/images")


@pytest.mark.django_db
class TestRunTimeLimit:
    def test_past_the_limit_no_new_image_is_started_and_what_was_read_is_written(self, tmp_path, monkeypatch):
        configure(tmp_path, monkeypatch, {"running_only": False}, limits={"max_run_minutes": 1})
        # The clock is read once for the deadline, then once per image: 31 s in, then 62 s in.
        ticking(monkeypatch, 31)
        instance = two_images()
        run_against(monkeypatch, instance)
        run = latest_run()
        assert read_images(run) == {DIGEST}
        assert "1-minute limit" in not_read(run)[f"image:{OTHER}"]
        assert {target for _, target in findings()} == {DIGEST}
        assert not any(OTHER in str(call.url) for call in instance.transport.calls)
        # The inventory steps that make further reads are not started, and say so.
        assert "1-minute limit" in not_read(run)["create:kubernetes"]
        assert not any("/kubernetes-" in str(call.url) for call in instance.transport.calls)
        assert run.settings["limits"] == {"max_response_mib": 64, "max_run_minutes": 1, "max_batch_rows": 5000}
        # Anchore's record of an image comes from the list already read, so the image left unread still has one.
        from tap_plugin.anchore.models.image import AnchoreImage

        assert {image.image_digest for image in AnchoreImage.objects.all()} == {DIGEST, OTHER}

    def test_an_image_left_unread_keeps_its_findings_as_they_were(self, tmp_path, monkeypatch):
        configure(tmp_path, monkeypatch, {"running_only": False}, limits={"max_run_minutes": 1})
        instance = two_images()
        ticking(monkeypatch, 1)
        run_against(monkeypatch, instance)
        assert ("CVE-2024-0009", OTHER) in findings()
        # Anchore no longer reports it, but this run never got to the image, so it proves nothing.
        instance.vulns[OTHER] = []
        ticking(monkeypatch, 31)
        run_against(monkeypatch, instance)
        assert findings()[("CVE-2024-0009", OTHER)].state == "current"

    def test_with_no_limit_the_clock_is_never_a_reason(self, tmp_path, monkeypatch):
        configure(tmp_path, monkeypatch, {"running_only": False})
        ticking(monkeypatch, 10**9)
        run_against(monkeypatch, two_images())
        run = latest_run()
        assert read_images(run) == {DIGEST, OTHER}
        assert not any("limit" in reason for reason in not_read(run).values())
