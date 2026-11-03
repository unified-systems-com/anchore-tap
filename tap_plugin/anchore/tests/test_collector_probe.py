"""The probe (req-anchore-probe-1 to -4): account verified first, optional reads recorded as not read.

No socket is opened. The responses are canned and spec-derived, not recorded from an instance.
"""

import socket
from datetime import UTC, datetime, timedelta

import pytest
import requests

from tap_plugin.anchore import client as cl
from tap_plugin.anchore import credential as cred
from tap_plugin.anchore.collectors.anchore_collector.manifest import ManifestError, load_manifest, shipped_manifest
from tap_plugin.anchore.collectors.anchore_collector.probe import NOT_READ, READ, ProbeError, run_probe
from tap_plugin.anchore.tests.fakes import FakeTransport, response
from tap_plugin.anchore.tests.test_anchore_credential import SECRET, envelope

ACCOUNT = "acct"
NOW = datetime(2026, 11, 3, 12, 0, tzinfo=UTC)


@pytest.fixture(autouse=True)
def no_sockets(monkeypatch):
    def refuse(*a, **k):
        raise AssertionError("the probe tests must not open a socket")

    monkeypatch.setattr(socket.socket, "connect", refuse)
    monkeypatch.setattr(socket, "create_connection", refuse)


def routes(**over):
    base = {
        "/account": response(200, {"name": ACCOUNT, "type": "user"}),
        "/status": response(200, {"version": "5.0.1", "up": True}),
        "/system": response(200, {"service_states": []}),
        "/system/feeds": response(
            200,
            [{"name": "vulnerabilities", "groups": [{"name": "alpine:3.19", "last_sync": "2026-11-03T11:00:00Z"}, {"name": "debian:12", "last_sync": "2026-10-20T00:00:00Z"}, {"name": "ubuntu:22.04"}]}],
        ),
    }
    base.update(over)
    return base


def probe(table=None, default=None):
    transport = FakeTransport(table if table is not None else routes(), default)
    credential = cred.credential_from_envelope(envelope())
    client = cl.ReadOnlyClient(credential, transport=transport, sleep=lambda s: None)
    return run_probe(client, ACCOUNT, qualified=credential.qualified), transport


def refusal(table=None, default=None):
    transport = FakeTransport(table if table is not None else routes(), default)
    credential = cred.credential_from_envelope(envelope())
    client = cl.ReadOnlyClient(credential, transport=transport, sleep=lambda s: None)
    with pytest.raises(ProbeError) as raised:
        run_probe(client, ACCOUNT, qualified=credential.qualified)
    return str(raised.value), transport


class TestAProbeThatAnswers:
    def test_every_probe_source_is_read_in_manifest_order(self):
        result, transport = probe()
        assert list(result.outcomes) == ["account", "status", "system", "feeds"]
        assert all(o.state == READ for o in result.outcomes.values())
        assert [str(c.url).split("/v2")[-1] for c in transport.calls] == ["/account", "/status", "/system", "/system/feeds"]

    def test_only_get_requests_are_made(self):
        _, transport = probe()
        assert {c.method for c in transport.calls} == {"GET"}

    def test_the_reported_version_comes_from_status(self):
        assert probe()[0].reported_version == "5.0.1"

    def test_nothing_is_listed_as_not_read(self):
        assert probe()[0].not_read() == []


class TestTheAccountGate:
    def test_a_different_effective_account_stops_the_run_before_anything_else_is_read(self):
        message, transport = refusal(routes(**{"/account": response(200, {"name": "someone-else"})}))
        assert "effective account is not the configured account" in message
        assert len(transport.calls) == 1, "only /account may have been requested"

    @pytest.mark.parametrize("status", [401, 403, 404, 500])
    def test_an_account_that_cannot_be_read_stops_the_run(self, status):
        message, transport = refusal(routes(**{"/account": response(status, {})}))
        assert "could not be read" in message
        assert len(transport.calls) <= 3  # the client may retry a 5xx, but never reads another source

    def test_an_account_body_without_a_name_is_not_a_match(self):
        message, _ = refusal(routes(**{"/account": response(200, {"type": "user"})}))
        assert "effective account is not the configured account" in message

    def test_a_body_that_is_not_json_stops_the_run(self):
        message, _ = refusal(routes(**{"/account": response(200, b"<html>")}))
        assert "could not be read" in message

    def test_the_messages_name_no_account_and_no_secret(self):
        for table in (routes(**{"/account": response(200, {"name": "someone-else"})}), routes(**{"/account": response(403, {})})):
            message, _ = refusal(table)
            assert "someone-else" not in message and ACCOUNT not in message.replace("anchore:", "") and SECRET not in message


class TestTheGateDoesNotDependOnTheListItIsGiven:
    """Both review seats: the gate fired only if the list happened to contain the account source first."""

    def _client(self):
        transport = FakeTransport(routes())
        credential = cred.credential_from_envelope(envelope())
        return cl.ReadOnlyClient(credential, transport=transport, sleep=lambda s: None), transport

    def _sources(self, *ids):
        by_id = {s.id: s for s in shipped_manifest()}
        return tuple(by_id[i] for i in ids)

    def test_a_list_without_the_account_source_is_refused_before_any_request(self):
        client, transport = self._client()
        with pytest.raises(ProbeError, match="exactly one account source"):
            run_probe(client, ACCOUNT, self._sources("status", "system"))
        assert transport.calls == []

    def test_an_empty_list_is_refused_before_any_request(self):
        client, transport = self._client()
        with pytest.raises(ProbeError, match="exactly one account source"):
            run_probe(client, ACCOUNT, ())
        assert transport.calls == []

    def test_a_duplicated_account_source_is_refused_before_any_request(self):
        client, transport = self._client()
        with pytest.raises(ProbeError, match="exactly one account source"):
            run_probe(client, ACCOUNT, self._sources("account", "account"))
        assert transport.calls == []

    def test_the_account_is_read_first_wherever_it_sits_in_the_list(self):
        client, transport = self._client()
        run_probe(client, ACCOUNT, self._sources("status", "system", "feeds", "account"))
        assert str(transport.calls[0].url).endswith("/account")

    def test_a_mismatch_with_the_account_listed_last_still_stops_before_the_others(self):
        transport = FakeTransport(routes(**{"/account": response(200, {"name": "someone-else"})}))
        client = cl.ReadOnlyClient(cred.credential_from_envelope(envelope()), transport=transport, sleep=lambda s: None)
        with pytest.raises(ProbeError):
            run_probe(client, ACCOUNT, self._sources("status", "system", "feeds", "account"))
        assert len(transport.calls) == 1


class TestAnOptionalReadThatIsNotAnswered:
    def test_a_refused_status_leaves_the_version_null_and_is_listed(self):
        result, _ = probe(routes(**{"/status": response(403, {})}))
        assert result.reported_version is None
        assert result.outcomes["status"].state == NOT_READ
        assert result.outcomes["status"].reason == "refused (HTTP 403)"
        assert {"scope": "probe:status", "reason": "refused (HTTP 403)"} in result.not_read()

    def test_a_feed_list_the_instance_does_not_offer_is_not_called_empty(self):
        result, _ = probe(routes(**{"/system/feeds": response(404, {})}))
        assert result.outcomes["feeds"].reason == "not offered (HTTP 404)"
        assert result.body("feeds") is None and result.feed_syncs == ()

    def test_a_server_that_keeps_failing_is_not_read_with_its_status(self):
        result, _ = probe(routes(**{"/system": response(503, {})}))
        assert result.outcomes["system"].state == NOT_READ
        assert "failed after retries" in (result.outcomes["system"].reason or "")
        assert result.outcomes["account"].state == READ, "one optional failure does not stop the others"

    def test_a_body_that_is_not_json_is_not_read(self):
        result, _ = probe(routes(**{"/status": response(200, b"not json")}))
        assert result.outcomes["status"].reason == "the body was not JSON"
        assert result.reported_version is None

    def test_a_version_that_is_not_a_string_is_not_taken(self):
        result, _ = probe(routes(**{"/status": response(200, {"version": 5})}))
        assert result.reported_version is None

    def test_a_transport_error_is_not_read_not_an_exception(self):
        result, _ = probe(routes(**{"/system": requests.ConnectionError("reset")}))
        assert result.outcomes["system"].state == NOT_READ


class TestFeedFreshness:
    def test_a_group_older_than_the_age_is_stale_with_its_age(self):
        result, _ = probe()
        stale = result.stale_feeds(NOW, timedelta(days=7))
        assert [(s["feed"], s["group"]) for s in stale] == [("vulnerabilities", "debian:12")]
        assert stale[0]["age_seconds"] == int((NOW - datetime(2026, 10, 20, tzinfo=UTC)).total_seconds())

    def test_an_unobserved_last_sync_is_neither_stale_nor_fresh(self):
        result, _ = probe()
        unobserved = [s for s in result.feed_syncs if s[1] == "ubuntu:22.04"]
        assert unobserved == [("vulnerabilities", "ubuntu:22.04", None)]
        assert all(s["group"] != "ubuntu:22.04" for s in result.stale_feeds(NOW, timedelta(seconds=1)))

    def test_without_feed_data_nothing_is_reported_stale(self):
        result, _ = probe(routes(**{"/system/feeds": response(403, {})}))
        assert result.stale_feeds(NOW, timedelta(days=1)) == []


class TestTheManifestRefusesAnEmptyFieldPath:
    """The Low from the last review of the manifest: an empty path resolved to the response root."""

    @pytest.mark.parametrize("key", ["required_fields", "optional_fields"])
    def test_an_empty_path_is_refused(self, key):
        entry = {"id": "account", "path": "/account", "scope": "probe", "required": True, "required_fields": ["name"], "optional_fields": []}
        entry[key] = [*entry[key], ""]
        with pytest.raises(ManifestError, match="schema"):
            load_manifest({"description": "x", "sources": [entry]})

    def test_the_shipped_manifest_still_loads(self):
        assert [s.id for s in shipped_manifest()][0] == "account"
