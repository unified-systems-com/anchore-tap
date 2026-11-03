"""The read-only Anchore client (req-anchore-client, req-anchore-connection).

A small client over ``requests`` that can only read. Every request leaves through one session
whose send refuses any method but GET and any URL that is not http or https before anything is sent;
a redirect is an error, never followed, so the credential can never reach another origin;
certificate verification is on and nothing turns it off; the environment's proxy, netrc and CA
settings are ignored. A response over the size cap is refused. Retries are bounded in count and
in total time and honour ``Retry-After``; exhausting them raises, never returns an empty result.

No message built here contains the credential: errors name ``anchore:<key>`` and a class of
failure, and the credential is held only by the session's auth.
"""

import time
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import quote, unquote, urlsplit

import requests
from requests.adapters import BaseAdapter, HTTPAdapter

from tap_plugin.anchore.credential import Credential

MAX_RESPONSE_BYTES = 64 * 1024 * 1024
CONNECT_TIMEOUT = 10
READ_TIMEOUT = 60
MAX_ATTEMPTS = 3
BACKOFF_SECONDS = (1.0, 3.0)
MAX_RETRY_AFTER = 30
TOTAL_BUDGET_SECONDS = 120
ACCOUNT_HEADER = "x-anchore-account"

# Response headers that can carry credentials; never kept.
_DROPPED_HEADERS = frozenset({"set-cookie", "authorization", "proxy-authorization", "www-authenticate-token"})


class ClientError(Exception):
    """Base of every error this client raises."""


class WriteRefused(ClientError):
    """A request that is not a GET was refused before it was sent."""


class InsecureRefused(ClientError):
    """A request whose scheme is neither http nor https was refused before it was sent."""


class OriginRefused(ClientError):
    """A request to anywhere but the configured Anchore API root was refused before it was sent."""


class RedirectRefused(ClientError):
    """The server answered with a redirect, which is never followed."""


class ResponseTooLarge(ClientError):
    """The response is over the size cap."""


class BadPath(ClientError):
    """A request path is not a plain API path."""


class RequestFailed(ClientError):
    """Retries were exhausted. ``reply`` holds the last response when there was one."""

    def __init__(self, message: str, reply: "Reply | None" = None) -> None:
        super().__init__(message)
        self.reply = reply


@dataclass(frozen=True)
class Reply:
    """One response. Headers exclude anything that can carry a credential."""

    status: int
    headers: dict[str, str]
    body: bytes
    elapsed_ms: int
    path: str
    attempts: int = 1
    request_headers: tuple[str, ...] = field(default=(), repr=False)

    @property
    def content_type(self) -> str | None:
        return self.headers.get("content-type")


def _plain_remainder(remainder: str) -> bool:
    """True when what follows the API root is an ordinary path.

    A string prefix is not enough: ``/v2/%2e%2e/account`` starts with the root but a server or proxy
    that decodes it reaches ``/account``. The remainder is decoded (repeatedly, so a double encoding
    cannot hide) and refused if any segment is a dot segment or if it holds a backslash, a NUL
    or a control character.
    """
    text = remainder
    for _ in range(4):
        decoded = unquote(text)
        if decoded == text:
            break
        text = decoded
    else:
        return False
    if any(ord(ch) < 32 or ch == "\\" for ch in text):
        return False
    return all(segment not in (".", "..") for segment in text.split("/"))


class _Session(requests.Session):
    """A session that can only read one Anchore API root, whatever it is asked to do.

    Every guard is in ``send``, which every request passes through whatever adapter is mounted, so
    remounting an adapter on this session does not get round them: a method other than GET, a URL
    that is outside the configured API root (which pins its scheme, host and port), a redirect, and any override of
    certificate verification, client certificate or proxies are each refused or ignored here.
    """

    def __init__(self, api_root: str, verify: bool | str) -> None:
        super().__init__()
        self.trust_env = False
        self.verify = verify
        self._prefix = api_root.rstrip("/") + "/"
        self._pinned_verify = verify

    def get_adapter(self, url: str) -> requests.adapters.BaseAdapter:
        """Only an http or https URL has an adapter; any other scheme is refused before anything is sent."""
        if not url.lower().startswith(("https://", "http://")):
            raise InsecureRefused("a request that is not http or https is refused")
        return super().get_adapter(url)

    def send(self, request: requests.PreparedRequest, **kwargs: Any) -> requests.Response:
        if request.method != "GET":
            raise WriteRefused(f"{request.method} is refused: this client only reads")
        url = str(request.url)
        if not url.lower().startswith(("https://", "http://")):
            raise InsecureRefused("a request that is not http or https is refused")
        if not url.startswith(self._prefix) or not _plain_remainder(urlsplit(url).path[len(urlsplit(self._prefix).path):]):
            raise OriginRefused("a request outside the configured Anchore API root is refused")
        kwargs["allow_redirects"] = False
        kwargs["verify"] = self._pinned_verify
        kwargs["cert"] = None
        kwargs["proxies"] = {}
        response = super().send(request, **kwargs)
        if 300 <= response.status_code < 400 and response.status_code != 304:
            response.close()
            raise RedirectRefused(f"a {response.status_code} redirect is refused and not followed")
        return response


def _arrivals(response: requests.Response) -> Any:
    """Yield the body as it arrives, one read at a time.

    ``iter_content(n)`` waits until n bytes have arrived, so a peer that sends a byte less often
    than the read timeout could hold one call open for hours and the deadline would never be
    looked at. ``read1`` returns whatever one read produced, so the caller sees every arrival
    and the overshoot past the deadline is at most one read timeout.
    """
    raw = response.raw
    reader = getattr(raw, "read1", None)
    if reader is None:
        yield from response.iter_content(65536)
        return
    while True:
        try:
            data = reader(65536, decode_content=True)
        except TypeError:  # a plain file-like object (as in tests) takes no decode_content
            data = reader(65536)
        if not data:
            return
        yield data


def fill(template: str, **values: str) -> str:
    """Fill a path template such as ``/images/{image_digest}/vuln/{vuln_type}`` with quoted values."""
    out = template
    for name, value in values.items():
        if not value:
            raise BadPath(f"empty value for {name}")
        out = out.replace("{" + name + "}", quote(str(value), safe=":"))
    if "{" in out or "}" in out:
        raise BadPath("a path parameter was not filled")
    return out


def _check_path(path: str) -> None:
    if not path.startswith("/") or "://" in path or "?" in path or "#" in path:
        raise BadPath("a request path must be a plain path beginning with /")
    if not _plain_remainder(path) or any(ch.isspace() or ord(ch) < 32 for ch in path):
        raise BadPath("a request path must not contain dot segments, encoded dot segments or whitespace")


class ReadOnlyClient:
    """GET reads of one Anchore instance and account."""

    def __init__(
        self,
        credential: Credential,
        *,
        transport: BaseAdapter | None = None,
        sleep: Callable[[float], None] = time.sleep,
        clock: Callable[[], float] = time.monotonic,
        max_bytes: int = MAX_RESPONSE_BYTES,
        timeout: tuple[float, float] = (CONNECT_TIMEOUT, READ_TIMEOUT),
        max_attempts: int = MAX_ATTEMPTS,
    ) -> None:
        self._credential = credential
        self._sleep = sleep
        self._clock = clock
        self._max_bytes = max_bytes
        self._timeout = timeout
        self._max_attempts = max_attempts
        session = _Session(credential.base_url, credential.ca_bundle or True)
        adapter = transport if transport is not None else HTTPAdapter(max_retries=0)
        session.mount("https://", adapter)
        session.mount("http://", adapter)
        session.headers["Accept"] = "application/json"
        auth = credential.auth
        if auth.basic is not None:
            session.auth = auth.basic
        elif auth.bearer_header is not None:
            session.headers["Authorization"] = auth.bearer_header
        self._session = session

    def close(self) -> None:
        self._session.close()

    def __enter__(self) -> "ReadOnlyClient":
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()

    def get(
        self,
        path: str,
        *,
        params: dict[str, Any] | None = None,
        accept: str = "application/json",
        account_header: bool = True,
    ) -> Reply:
        """GET ``path`` under the instance's API root."""
        _check_path(path)
        headers = {"Accept": accept}
        if account_header:
            headers[ACCOUNT_HEADER] = self._credential.account
        url = self._credential.base_url + path
        started = self._clock()
        last: Reply | None = None
        for attempt in range(1, self._max_attempts + 1):
            reason: str | None = None
            remaining = TOTAL_BUDGET_SECONDS - (self._clock() - started)
            if remaining <= 0:
                raise RequestFailed(f"{self._credential.qualified}: GET {path} exceeded the {TOTAL_BUDGET_SECONDS}-second budget", last)
            try:
                reply = self._once(url, path, params, headers, attempt, started + TOTAL_BUDGET_SECONDS, remaining)
            except (requests.ConnectionError, requests.Timeout) as exc:
                reply, reason = None, type(exc).__name__
            except requests.RequestException as exc:
                # A malformed or truncated stream (ChunkedEncodingError, ContentDecodingError) or a
                # malformed URL is not retried, and is never allowed to escape as a bare requests error.
                raise RequestFailed(f"{self._credential.qualified}: GET {path} failed: {type(exc).__name__}", last) from None
            if reply is not None:
                last = reply
                if reply.status != 429 and not 500 <= reply.status < 600:
                    return reply
                reason = f"HTTP {reply.status}"
            if attempt == self._max_attempts or self._clock() - started > TOTAL_BUDGET_SECONDS:
                raise RequestFailed(f"{self._credential.qualified}: GET {path} failed after {attempt} attempt(s): {reason}", last)
            delay = self._delay(reply, attempt)
            if self._clock() - started + delay >= TOTAL_BUDGET_SECONDS:
                raise RequestFailed(f"{self._credential.qualified}: GET {path} would exceed the {TOTAL_BUDGET_SECONDS}-second budget by retrying", last)
            self._sleep(delay)
        raise RequestFailed(f"{self._credential.qualified}: GET {path} failed", last)  # pragma: no cover

    def _delay(self, reply: Reply | None, attempt: int) -> float:
        base = BACKOFF_SECONDS[min(attempt - 1, len(BACKOFF_SECONDS) - 1)]
        if reply is not None:
            retry_after = reply.headers.get("retry-after", "")
            if retry_after.isdigit():
                return float(min(int(retry_after), MAX_RETRY_AFTER))
        return base

    def _once(self, url: str, path: str, params: dict[str, Any] | None, headers: dict[str, str], attempt: int, deadline: float, remaining: float) -> Reply:
        started = self._clock()
        # A connect or read can block for its whole timeout, so neither may be longer than what is
        # left of the total budget.
        timeout = (min(self._timeout[0], remaining), min(self._timeout[1], remaining))
        response = self._session.get(url, params=params, headers=headers, timeout=timeout, stream=True)
        try:
            declared = response.headers.get("content-length", "")
            if declared.isdigit() and int(declared) > self._max_bytes:
                raise ResponseTooLarge(f"{self._credential.qualified}: GET {path} declares {declared} bytes, over the {self._max_bytes} cap")
            chunks: list[bytes] = []
            size = 0
            for chunk in _arrivals(response):
                if self._clock() > deadline:
                    raise RequestFailed(f"{self._credential.qualified}: GET {path} exceeded the {TOTAL_BUDGET_SECONDS}-second budget while streaming")
                size += len(chunk)
                if size > self._max_bytes:
                    raise ResponseTooLarge(f"{self._credential.qualified}: GET {path} is over the {self._max_bytes}-byte cap")
                chunks.append(chunk)
            kept = {k.lower(): v for k, v in response.headers.items() if k.lower() not in _DROPPED_HEADERS}
            sent = tuple(sorted(k.lower() for k in response.request.headers))
            return Reply(
                status=response.status_code,
                headers=kept,
                body=b"".join(chunks),
                elapsed_ms=int((self._clock() - started) * 1000),
                path=path,
                attempts=attempt,
                request_headers=sent,
            )
        finally:
            response.close()
