"""The Anchore credential envelope: validation, canonical identity, discovery (req-anchore-connection).

One envelope per Anchore instance and account, scope ``anchore``, kind ``anchore_api_credential``.
This module is the consumer-side check the secrets spec leaves to the consumer
(``req-tap-cares-secrets-validation``): it validates ``data`` against the plugin's own schema,
derives the canonical API root and the scanner key, and finds every envelope in the scope.

It imports no Django and no ``tap_*`` app: the envelope file is read with core's settings-free
``tap.runtime_secrets`` so the observation command can run from a bare checkout. Secret material
lives only in :class:`Auth`, whose ``repr`` omits it, and no message built here contains a value.
"""

import base64
import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

import jsonschema
from tap.runtime_secrets import RuntimeSecretError, SecretEnvelope, load_secret_envelope
from tap.secret_naming import SECRET_EXAMPLE_SUFFIX, SECRET_SUFFIX

SCOPE = "anchore"
KIND = "anchore_api_credential"
SCHEMA_PATH = Path(__file__).resolve().parent / "schemas" / "anchore_api_credential.schema.json"

# The documented user name an Anchore API key is presented under.
API_KEY_USER = "_api_key"

# What replaces a credential found in text an instance returned. The first candidate is used
# unless it would itself contain a form of the credential (a password that is the word
# "credential" or "REDACTED" would otherwise survive its own redaction); then the next, and as a
# last resort the match is removed.
REDACTED = "[REDACTED:credential]"
_MARKERS = (REDACTED, "[redacted]", "[#]", "#", "\u2588", "")


class CredentialError(Exception):
    """An envelope cannot be used. The message names ``anchore:<key>`` and a reason, never a value."""

    def __init__(self, qualified: str, reason: str) -> None:
        super().__init__(f"{qualified}: {reason}")
        self.qualified = qualified
        self.reason = reason


@dataclass(frozen=True)
class Auth:
    """How a request authenticates. ``repr`` shows only the scheme."""

    scheme: str
    _basic: tuple[str, str] | None = field(default=None, repr=False)
    _bearer: str | None = field(default=None, repr=False)

    def __repr__(self) -> str:
        return f"Auth(scheme={self.scheme!r})"

    @property
    def basic(self) -> tuple[str, str] | None:
        """(user, password) for the Basic and API-key schemes, else None."""
        return self._basic

    @property
    def bearer_header(self) -> str | None:
        """The Authorization header value for the bearer scheme, else None."""
        return f"Bearer {self._bearer}" if self._bearer is not None else None

    def _forms(self) -> tuple[str, ...]:
        """Every form this credential is sent in, longest first, so a redaction takes the whole form."""
        out: set[str] = set()
        if self._basic is not None:
            user, secret = self._basic
            out.update({secret, base64.b64encode(f"{user}:{secret}".encode()).decode()})
        if self._bearer is not None:
            out.update({self._bearer, f"Bearer {self._bearer}"})
        return tuple(sorted((f for f in out if f), key=len, reverse=True))

    def _marker(self) -> str:
        forms = self._forms()
        return next((m for m in _MARKERS if not any(f in m for f in forms)), "")

    def redact(self, text: str) -> tuple[str, int]:
        """Replace every form of the credential in ``text``; returns the text and how many were replaced.

        Longest form first, and the replacement is chosen so that it contains no form.
        """
        marker, count = self._marker(), 0
        for form in self._forms():
            count += text.count(form)
            text = text.replace(form, marker)
        return text, count

    def redact_bytes(self, data: bytes) -> tuple[bytes, int]:
        marker, count = self._marker().encode("utf-8"), 0
        for form in (f.encode("utf-8") for f in self._forms()):
            count += data.count(form)
            data = data.replace(form, marker)
        return data, count


@dataclass(frozen=True)
class Credential:
    """One validated Anchore instance and account."""

    qualified: str
    base_url: str
    account: str
    scheme: str
    ca_bundle: str | None
    annotation_allowlist: tuple[str, ...]
    scanner_key: str
    auth: Auth = field(repr=False)

    def redact(self, text: str) -> tuple[str, int]:
        return self.auth.redact(text)

    def redact_bytes(self, data: bytes) -> tuple[bytes, int]:
        return self.auth.redact_bytes(data)

    def __repr__(self) -> str:
        return f"Credential(qualified={self.qualified!r}, account={self.account!r}, scheme={self.scheme!r}, root={canonical_root(self.base_url)!r})"


def canonical_root(base_url: str) -> str:
    """The lower-cased scheme and host, the port unless it is the https default, and the path as configured.

    Raises ValueError for anything that is not a plain https API root: userinfo, a query, a
    fragment, a trailing slash, or another scheme. URL paths are case-sensitive, so ``/v2`` and
    ``/V2`` are different roots.
    """
    parts = urlsplit(base_url)
    if parts.scheme.lower() != "https":
        raise ValueError("base_url must be https")
    if parts.username is not None or parts.password is not None or "@" in parts.netloc:
        raise ValueError("base_url must not carry userinfo")
    if parts.query or parts.fragment or "?" in base_url or "#" in base_url:
        raise ValueError("base_url must not carry a query or a fragment")
    host = parts.hostname
    if not host:
        raise ValueError("base_url has no host")
    try:
        port = parts.port
    except ValueError:
        raise ValueError("base_url has an invalid port") from None
    if parts.path.endswith("/"):
        raise ValueError("base_url must not end with a slash")
    host_part = f"[{host}]" if ":" in host else host.lower()
    port_part = "" if port in (None, 443) else f":{port}"
    return f"https://{host_part}{port_part}{parts.path}"


def scanner_key(base_url: str, account: str) -> str:
    """The key of the scanner for this instance and account (req-anchore-scope-walk-4/-5).

    A compact JSON array of the canonical root and the account, so no separator can be forged by
    an account name. It carries no credential.
    """
    return json.dumps([canonical_root(base_url), account], separators=(",", ":"), ensure_ascii=False)


def _schema() -> dict[str, Any]:
    return json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))


def _schema_reason(exc: jsonschema.ValidationError) -> str:
    """Where the data failed the schema, without the offending value."""
    where = "/".join(str(p) for p in exc.absolute_path) or "(data)"
    return f"data does not match the {KIND} schema at {where} ({exc.validator})"


def credential_from_envelope(envelope: SecretEnvelope) -> Credential:
    """Validate one envelope and build its :class:`Credential`.

    Raises CredentialError naming ``anchore:<key>`` and a reason. The reason never contains a value.
    """
    qualified = envelope.qualified
    if envelope.scope != SCOPE:
        raise CredentialError(qualified, f"scope is {envelope.scope!r}, expected {SCOPE!r}")
    if envelope.kind != KIND:
        raise CredentialError(qualified, f"kind is {envelope.kind!r}, expected {KIND!r}")
    data = dict(envelope.data)
    try:
        jsonschema.validate(data, _schema())
    except jsonschema.ValidationError as exc:
        raise CredentialError(qualified, _schema_reason(exc)) from None
    try:
        root = canonical_root(data["base_url"])
    except ValueError as exc:
        raise CredentialError(qualified, str(exc)) from None
    scheme = data["scheme"]
    if scheme == "basic":
        auth = Auth(scheme, _basic=(data["username"], data["password"]))
    elif scheme == "api_key":
        auth = Auth(scheme, _basic=(API_KEY_USER, data["key"]))
    else:
        auth = Auth(scheme, _bearer=data["token"])
    return Credential(
        qualified=qualified,
        base_url=root,
        account=data["account"],
        scheme=scheme,
        ca_bundle=data.get("ca_bundle"),
        annotation_allowlist=tuple(data.get("annotation_allowlist", ())),
        scanner_key=scanner_key(root, data["account"]),
        auth=auth,
    )


def discover(root: Path) -> tuple[list[Credential], list[CredentialError]]:
    """Every usable envelope in scope ``anchore`` under ``root``, and every one that is not.

    A malformed envelope fails only itself (req-anchore-connection-10). Two envelopes that give
    the same scanner key are both refused, naming both keys (req-anchore-connection-9). Example
    templates (``*.secret.example.json``) are never read as credentials.
    """
    usable: list[Credential] = []
    errors: list[CredentialError] = []
    if not root.is_dir():
        return usable, [CredentialError(SCOPE, f"secrets root {root} is not a directory")]
    for path in sorted(root.rglob(f"*{SECRET_SUFFIX}")):
        if path.name.endswith(SECRET_EXAMPLE_SUFFIX):
            continue
        try:
            envelope = load_secret_envelope(path)
        except RuntimeSecretError:
            # A file we cannot read as an envelope may or may not be ours; report it by name only.
            errors.append(CredentialError(f"{SCOPE}:{path.name[: -len(SECRET_SUFFIX)]}", "file is not a readable secret envelope"))
            continue
        if envelope.scope != SCOPE:
            continue
        try:
            usable.append(credential_from_envelope(envelope))
        except CredentialError as exc:
            errors.append(exc)
    by_key: dict[str, list[Credential]] = {}
    for credential in usable:
        by_key.setdefault(credential.scanner_key, []).append(credential)
    kept: list[Credential] = []
    for credentials in by_key.values():
        if len(credentials) == 1:
            kept.append(credentials[0])
            continue
        names = " and ".join(c.qualified for c in credentials)
        errors.extend(CredentialError(c.qualified, f"same instance and account as the other envelopes ({names})") for c in credentials)
    return kept, errors
