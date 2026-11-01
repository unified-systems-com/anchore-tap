"""The read-only client (req-anchore-client-*, req-anchore-connection-2/-4/-5). No socket is opened."""

import base64
import io
import socket

import pytest
import requests

from tap_plugin.anchore import client as cl
from tap_plugin.anchore import credential as cred
from tap_plugin.anchore.tests.fakes import FakeTransport, response
from tap_plugin.anchore.tests.test_anchore_credential import SECRET, data, envelope


@pytest.fixture(autouse=True)
def no_sockets(monkeypatch):
    def refuse(*a, **k):
        raise AssertionError("the client tests must not open a socket")

    monkeypatch.setattr(socket.socket, "connect", refuse)
    monkeypatch.setattr(socket, "create_connection", refuse)


def make(scheme="basic", routes=None, default=None, **kw):
    transport = FakeTransport(routes or {}, default)
    credential = cred.credential_from_envelope(envelope(scheme=scheme))
    sleeps: list[float] = []
    client = cl.ReadOnlyClient(credential, transport=transport, sleep=sleeps.append, **kw)
    return client, transport, sleeps


class TestAuthentication:
    def test_basic(self):
        client, transport, _ = make("basic", default=response(200))
        client.get("/account")
        sent = transport.calls[0].headers["Authorization"]
        assert sent == "Basic " + base64.b64encode(f"reader:{SECRET}".encode()).decode()

    def test_api_key_uses_the_documented_user(self):
        client, transport, _ = make("api_key", default=response(200))
        client.get("/account")
        assert transport.calls[0].headers["Authorization"] == "Basic " + base64.b64encode(f"_api_key:{SECRET}".encode()).decode()

    def test_bearer(self):
        client, transport, _ = make("bearer", default=response(200))
        client.get("/account")
        assert transport.calls[0].headers["Authorization"] == f"Bearer {SECRET}"

    def test_account_header_is_sent_and_can_be_left_out(self):
        client, transport, _ = make(default=response(200))
        client.get("/account")
        client.get("/account", account_header=False)
        assert transport.calls[0].headers["x-anchore-account"] == "acct"
        assert "x-anchore-account" not in transport.calls[1].headers

    def test_url_is_the_canonical_root_plus_the_path(self):
        client, transport, _ = make(default=response(200))
        client.get("/images", params={"page": 1})
        assert transport.calls[0].url == "https://anchore.example:8228/v2/images?page=1"

    def test_environment_proxy_and_netrc_are_ignored(self):
        client, _, _ = make()
        assert client._session.trust_env is False and client._session.verify is True


class TestReadOnly:
    """req-anchore-client-1: refused before anything is sent."""

    @pytest.mark.parametrize("method", ["POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"])
    def test_other_methods_are_refused_by_the_transport(self, method):
        client, transport, _ = make(default=response(200))
        with pytest.raises(cl.WriteRefused):
            client._session.request(method, "https://anchore.example:8228/v2/images")
        assert transport.calls == []

    def test_an_aliased_call_is_refused_too(self):
        client, transport, _ = make(default=response(200))
        send = requests.Session.request
        with pytest.raises(cl.WriteRefused):
            send(client._session, method="DELETE", url="https://anchore.example:8228/v2/x")
        with pytest.raises(cl.WriteRefused):
            client._session.post("https://anchore.example:8228/v2/x", data=b"body")
        assert transport.calls == []

    def test_plain_http_is_refused_even_for_a_get(self):
        client, transport, _ = make(default=response(200))
        with pytest.raises(cl.InsecureRefused):
            client._session.get("http://anchore.example/v2/images")
        assert transport.calls == []

    def test_the_client_exposes_get_and_nothing_that_writes(self):
        public = {n for n in dir(cl.ReadOnlyClient) if not n.startswith("_")}
        assert public == {"close", "get"}


class TestRedirects:
    """req-anchore-connection-5."""

    @pytest.mark.parametrize("target", ["https://anchore.example:9999/v2/x", "https://elsewhere.example/v2/x", "http://anchore.example:8228/v2/x"])
    def test_a_redirect_is_an_error_and_no_second_request_is_sent(self, target):
        client, transport, _ = make(default=response(302, b"", {"Location": target}))
        with pytest.raises(cl.RedirectRefused):
            client.get("/images")
        assert len(transport.calls) == 1

    def test_not_modified_is_not_a_redirect(self):
        client, _, _ = make(default=response(304, b""))
        assert client.get("/images").status == 304


class TestSizeAndErrors:
    def test_declared_size_over_the_cap_is_refused(self):
        client, _, _ = make(default=response(200, b"{}", {"content-length": "999999"}), max_bytes=1000)
        with pytest.raises(cl.ResponseTooLarge):
            client.get("/images")

    def test_streamed_size_over_the_cap_is_refused(self):
        client, _, _ = make(default=response(200, b"x" * 5000, {"content-length": "10"}), max_bytes=1000)
        with pytest.raises(cl.ResponseTooLarge):
            client.get("/images")

    def test_client_error_statuses_are_returned_not_raised(self):
        client, _, _ = make(default=response(404, {"detail": "no"}))
        reply = client.get("/images")
        assert reply.status == 404 and b"detail" in reply.body

    def test_headers_that_can_carry_a_credential_are_dropped(self):
        client, _, _ = make(default=response(200, b"{}", {"Set-Cookie": "session=abc", "X-Request-Id": "r1"}))
        reply = client.get("/images")
        assert "set-cookie" not in reply.headers and reply.headers["x-request-id"] == "r1"


class TestRetries:
    """req-anchore-client-3."""

    def test_503_then_success(self):
        replies = iter([response(503), response(200, {"ok": True})])
        client, transport, sleeps = make(default=lambda request: next(replies))
        assert client.get("/images").status == 200
        assert len(transport.calls) == 2 and sleeps == [cl.BACKOFF_SECONDS[0]]

    def test_retry_after_is_honoured_and_capped(self):
        replies = iter([response(429, b"", {"Retry-After": "7"}), response(429, b"", {"Retry-After": "9999"}), response(200)])
        client, _, sleeps = make(default=lambda request: next(replies))
        client.get("/images")
        assert sleeps == [7.0, float(cl.MAX_RETRY_AFTER)]

    def test_exhaustion_raises_and_carries_the_last_reply(self):
        client, transport, _ = make(default=response(500, {"detail": "boom"}))
        with pytest.raises(cl.RequestFailed) as err:
            client.get("/images")
        assert len(transport.calls) == cl.MAX_ATTEMPTS and err.value.reply.status == 500

    def test_connection_errors_are_retried_then_raised(self):
        client, transport, _ = make(default=requests.ConnectionError("detail with host"))
        with pytest.raises(cl.RequestFailed) as err:
            client.get("/images")
        assert len(transport.calls) == cl.MAX_ATTEMPTS and "ConnectionError" in str(err.value)


class TestPaths:
    @pytest.mark.parametrize("path", ["images", "http://evil/x", "/a/../b", "/a/%2e%2e/b", "/a/%252e%252e/b", "/a/./b", "/a b", "/a?x=1", "/a#f", "/a\n"])
    def test_bad_paths_are_refused(self, path):
        client, transport, _ = make(default=response(200))
        with pytest.raises(cl.BadPath):
            client.get(path)
        assert transport.calls == []

    def test_fill_quotes_values_and_demands_every_parameter(self):
        assert cl.fill("/images/{image_digest}/vuln/{vuln_type}", image_digest="sha256:ab", vuln_type="all") == "/images/sha256:ab/vuln/all"
        assert cl.fill("/x/{id}", id="a/b c") == "/x/a%2Fb%20c"
        with pytest.raises(cl.BadPath):
            cl.fill("/x/{id}/{other}", id="1")
        with pytest.raises(cl.BadPath):
            cl.fill("/x/{id}", id="")


class TestNothingLeaks:
    """req-anchore-connection-2 and -12: the credential is in no message, repr or URL."""

    @pytest.mark.parametrize("scheme", ["basic", "api_key", "bearer"])
    def test_failures_and_reprs_do_not_contain_the_secret(self, scheme):
        client, transport, _ = make(scheme, default=response(503))
        with pytest.raises(cl.RequestFailed) as err:
            client.get("/images")
        reply = err.value.reply
        for text in (str(err.value), repr(reply), repr(reply.headers), reply.path, *(c.url for c in transport.calls)):
            assert SECRET not in text
        assert SECRET not in repr(cred.credential_from_envelope(envelope(scheme=scheme)))

    def test_custom_ca_bundle_is_passed_as_the_verify_path(self):
        c = cred.credential_from_envelope(envelope(payload=data(ca_bundle="/etc/ssl/private-ca.pem")))
        client = cl.ReadOnlyClient(c, transport=FakeTransport())
        assert client._session.verify == "/etc/ssl/private-ca.pem"


class TestOriginBinding:
    """The session holds the credential, so it can only be used against the configured API root."""

    @pytest.mark.parametrize(
        "url",
        [
            "https://attacker.example/",
            "https://attacker.example/v2/images",
            "https://anchore.example:9999/v2/images",
            "https://anchore.example/v2/images",
            "https://anchore.example:8228.attacker.example/v2/images",
            "https://anchore.example:8228/v2evil/images",
            "https://anchore.example:8228/other/images",
            "https://anchore.example:8228",
            "https://anchore.example:8228/v2/%2e%2e/account",
            "https://anchore.example:8228/v2/%2E%2E/account",
            "https://anchore.example:8228/v2/%252e%252e/account",
            "https://anchore.example:8228/v2/images/../../account",
            "https://anchore.example:8228/v2/images%5c..%5caccount",
        ],
    )
    @pytest.mark.parametrize("scheme", ["basic", "bearer"])
    def test_the_public_session_cannot_send_the_credential_elsewhere(self, scheme, url):
        client, transport, _ = make(scheme, default=response(200))
        # Either our refusal or requests' own refusal of a malformed URL; in both nothing is sent.
        with pytest.raises((cl.OriginRefused, requests.exceptions.InvalidURL)):
            client._session.get(url)
        assert transport.calls == []

    def test_a_plain_dot_segment_is_normalised_by_requests_and_stays_inside_the_root(self):
        client, transport, _ = make(default=response(200))
        client._session.get("https://anchore.example:8228/v2/./images")
        assert transport.calls[0].url == "https://anchore.example:8228/v2/images"

    def test_the_configured_root_is_accepted(self):
        client, transport, _ = make(default=response(200))
        assert client._session.get("https://anchore.example:8228/v2/images").status_code == 200
        assert len(transport.calls) == 1


class TestStreamingDeadline:
    def test_a_response_that_drips_past_the_budget_is_cut_off(self):
        ticks = iter([0.0, 0.0, 1.0, cl.TOTAL_BUDGET_SECONDS + 5.0, cl.TOTAL_BUDGET_SECONDS + 6.0, cl.TOTAL_BUDGET_SECONDS + 7.0] + [cl.TOTAL_BUDGET_SECONDS + 9.0] * 20)
        client, transport, _ = make(default=response(200, b"x" * 200_000, {"content-length": "200000"}), clock=lambda: next(ticks), max_attempts=1)
        with pytest.raises(cl.RequestFailed) as err:
            client.get("/images")
        assert "budget" in str(err.value) and len(transport.calls) == 1


class TestBudgetAroundBlockingCalls:
    def test_each_request_timeout_is_capped_by_what_is_left_of_the_budget(self):
        now = [0.0]

        def slow_503(request):
            now[0] += 99.0  # the first attempt takes 99 of the 120 seconds
            return response(503)

        transport = FakeTransport(default=slow_503)
        credential = cred.credential_from_envelope(envelope())
        client = cl.ReadOnlyClient(credential, transport=transport, sleep=lambda d: now.__setitem__(0, now[0] + d), clock=lambda: now[0], max_attempts=3)
        with pytest.raises(cl.RequestFailed):
            client.get("/images")
        assert transport.timeouts[0] == (cl.CONNECT_TIMEOUT, cl.READ_TIMEOUT)
        # After 99 seconds and a one-second wait, 20 seconds remain: the read timeout may not exceed that.
        assert transport.timeouts[1] == (cl.CONNECT_TIMEOUT, pytest.approx(cl.TOTAL_BUDGET_SECONDS - 99.0 - cl.BACKOFF_SECONDS[0]))

    def test_a_retry_that_cannot_finish_inside_the_budget_is_not_started(self):
        clock_values = iter([0.0, 0.0, 119.5] + [119.5] * 50)
        client, transport, sleeps = make(default=response(503), clock=lambda: next(clock_values), max_attempts=3)
        with pytest.raises(cl.RequestFailed) as err:
            client.get("/images")
        assert sleeps == [] and len(transport.calls) == 1 and "budget" in str(err.value)

    def test_an_exhausted_budget_stops_before_the_next_attempt(self):
        client, transport, _ = make(default=response(503), clock=iter([0.0, 0.0, 0.0, 500.0, 500.0, 500.0] + [500.0] * 20).__next__, max_attempts=3)
        with pytest.raises(cl.RequestFailed):
            client.get("/images")
        assert len(transport.calls) <= 2


class TestBrokenStreams:
    @pytest.mark.parametrize("error", [requests.exceptions.ChunkedEncodingError("bad chunk"), requests.exceptions.ContentDecodingError("bad encoding"), requests.exceptions.InvalidURL("bad")])
    def test_other_requests_errors_become_a_client_error_not_a_bare_exception(self, error):
        from tap_plugin.anchore.tests.fakes import BrokenStream

        client, transport, sleeps = make(default=BrokenStream(error))
        with pytest.raises(cl.RequestFailed) as err:
            client.get("/images")
        assert type(error).__name__ in str(err.value) and len(transport.calls) == 1 and sleeps == []


class TestArrivalByArrival:
    def _drip(self, clock_state, step, chunks=50):
        class Drip(io.BytesIO):
            def __init__(self):
                super().__init__(b"")
                self.n = 0

            def read1(self, amt=-1, decode_content=None):
                self.n += 1
                clock_state[0] += step
                return b"x" if self.n <= chunks else b""

        r = response(200, b"")
        r._content_consumed = False
        r._content = False
        r.raw = Drip()
        r.headers.pop("content-length", None)
        return r

    def test_a_peer_that_drips_a_byte_at_a_time_is_cut_off_at_the_deadline(self):
        now = [0.0]
        transport = FakeTransport(default=self._drip(now, 30.0, chunks=500))
        credential = cred.credential_from_envelope(envelope())
        client = cl.ReadOnlyClient(credential, transport=transport, clock=lambda: now[0], sleep=lambda d: None, max_attempts=1)
        with pytest.raises(cl.RequestFailed) as err:
            client.get("/images")
        assert "budget" in str(err.value)
        assert now[0] < cl.TOTAL_BUDGET_SECONDS + 60  # overshoot is at most one read

    def test_a_real_urllib3_response_is_read_and_decoded(self):
        import gzip

        import urllib3.response

        body = gzip.compress(b'{"ok": true, "pad": "' + b"y" * 200_000 + b'"}')
        raw = urllib3.response.HTTPResponse(body=io.BytesIO(body), headers={"content-encoding": "gzip", "content-type": "application/json"}, status=200, preload_content=False)
        r = requests.Response()
        r.status_code, r.raw = 200, raw
        r.headers.update({"content-encoding": "gzip", "content-type": "application/json"})
        client, _, _ = make(default=r)
        reply = client.get("/images")
        assert reply.status == 200 and reply.body.startswith(b'{"ok": true') and len(reply.body) > 200_000


class TestGuardsSurviveTamperingWithTheSession:
    """The guards are in the session's send, so remounting an adapter or overriding a setting does not defeat them."""

    def _tampered(self, scheme="basic"):
        client, _, _ = make(scheme, default=response(200))
        elsewhere = FakeTransport(default=response(200))
        client._session.mount("https://", elsewhere)
        return client, elsewhere

    @pytest.mark.parametrize("scheme", ["basic", "bearer"])
    def test_a_remounted_adapter_still_cannot_post_or_leave_the_root(self, scheme):
        client, elsewhere = self._tampered(scheme)
        with pytest.raises(cl.WriteRefused):
            client._session.post("https://anchore.example:8228/v2/x")
        with pytest.raises(cl.OriginRefused):
            client._session.get("https://attacker.example/x")
        assert elsewhere.calls == []

    def test_verify_false_and_proxies_and_cert_overrides_are_ignored(self):
        seen = []

        class Spy(FakeTransport):
            def send(self, request, **kwargs):
                seen.append({k: kwargs.get(k) for k in ("verify", "cert", "proxies")})
                return super().send(request, **kwargs)

        credential = cred.credential_from_envelope(envelope())
        client = cl.ReadOnlyClient(credential, transport=Spy(default=response(200)))
        client._session.get("https://anchore.example:8228/v2/x", verify=False, cert="/tmp/c.pem", proxies={"https": "http://attacker.example:3128"})
        assert seen == [{"verify": True, "cert": None, "proxies": {}}]

    def test_the_client_has_no_public_session(self):
        client, _, _ = make()
        assert not hasattr(client, "session")
