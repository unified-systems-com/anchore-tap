"""The credential envelope: validation, canonical identity, discovery (req-anchore-connection-*)."""

import json
from pathlib import Path

import pytest
from tap.runtime_secrets import SecretEnvelope

from tap_plugin.anchore import credential as cred

EXAMPLES = Path(cred.__file__).resolve().parent / "schemas" / "examples"
SECRET = "pw-not-a-real-secret-value"


def data(scheme: str = "basic", **over):
    base = {"base_url": "https://anchore.example:8228/v2", "account": "acct", "scheme": scheme}
    if scheme == "basic":
        base.update(username="reader", password=SECRET)
    elif scheme == "api_key":
        base.update(key=SECRET)
    else:
        base.update(token=SECRET)
    base.update(over)
    return base


def envelope(key="a", scheme="basic", payload=None, kind=cred.KIND, scope=cred.SCOPE):
    return SecretEnvelope(scope, key, kind, "test", payload if payload is not None else data(scheme), {}, Path("/nonexistent"))


def write(root: Path, key: str, payload: dict, kind=cred.KIND, scope=cred.SCOPE):
    doc = {"scope": scope, "key": key, "kind": kind, "description": "test", "data": payload}
    (root / f"{key}.secret.json").write_text(json.dumps(doc), encoding="utf-8")


class TestEnvelope:
    @pytest.mark.parametrize("scheme", ["basic", "api_key", "bearer"])
    def test_each_scheme_validates(self, scheme):
        c = cred.credential_from_envelope(envelope(scheme=scheme))
        assert c.scheme == scheme and c.qualified == "anchore:a"

    def test_auth_material_per_scheme(self):
        assert cred.credential_from_envelope(envelope(scheme="basic")).auth.basic == ("reader", SECRET)
        assert cred.credential_from_envelope(envelope(scheme="api_key")).auth.basic == ("_api_key", SECRET)
        bearer = cred.credential_from_envelope(envelope(scheme="bearer")).auth
        assert bearer.basic is None and bearer.bearer_header == f"Bearer {SECRET}"

    @pytest.mark.parametrize("scheme", ["basic", "api_key", "bearer"])
    def test_repr_never_shows_the_secret(self, scheme):
        c = cred.credential_from_envelope(envelope(scheme=scheme))
        assert SECRET not in repr(c) and SECRET not in repr(c.auth) and SECRET not in str(c)

    def test_templates_validate_against_the_schema(self):
        """The shipped example envelopes are valid once their placeholders are filled."""
        files = sorted(EXAMPLES.glob("*.secret.example.json"))
        assert len(files) == 3
        for path in files:
            doc = json.loads(path.read_text(encoding="utf-8"))
            assert doc["kind"] == cred.KIND and doc["scope"] == cred.SCOPE
            cred.credential_from_envelope(SecretEnvelope(doc["scope"], doc["key"], doc["kind"], doc["description"], doc["data"], {}, path))

    @pytest.mark.parametrize(
        "mutate",
        [
            lambda d: d.update(key="extra"),  # a field of another scheme
            lambda d: d.update(unknown_field=1),
            lambda d: d.pop("account"),
            lambda d: d.pop("password"),
            lambda d: d.update(scheme="oauth"),
            lambda d: d.update(base_url="http://anchore.example/v2"),
            lambda d: d.update(ca_bundle="relative/path.pem"),
        ],
    )
    def test_invalid_data_is_refused_without_the_value(self, mutate):
        payload = data()
        mutate(payload)
        with pytest.raises(cred.CredentialError) as err:
            cred.credential_from_envelope(envelope(payload=payload))
        assert SECRET not in str(err.value) and err.value.qualified == "anchore:a"

    def test_wrong_kind_and_scope_are_refused(self):
        with pytest.raises(cred.CredentialError):
            cred.credential_from_envelope(envelope(kind="github_pat"))
        with pytest.raises(cred.CredentialError):
            cred.credential_from_envelope(envelope(scope="other"))


class TestCanonicalRoot:
    def test_scheme_and_host_are_lower_cased_and_the_path_is_not(self):
        assert cred.canonical_root("https://Anchore.Example/v2") == "https://anchore.example/v2"
        assert cred.canonical_root("https://anchore.example/V2") == "https://anchore.example/V2"

    def test_default_port_is_one_spelling(self):
        assert cred.canonical_root("https://h/v2") == cred.canonical_root("https://h:443/v2")
        assert cred.canonical_root("https://h:8228/v2") == "https://h:8228/v2"

    @pytest.mark.parametrize("url", ["http://h/v2", "https://u:p@h/v2", "https://h/v2?x=1", "https://h/v2#f", "https://h/v2/", "https:///v2", "https://h:99999/v2"])
    def test_refused_forms(self, url):
        with pytest.raises(ValueError):
            cred.canonical_root(url)

    def test_scanner_keys(self):
        """req-anchore-scope-walk-5: roots, ports and accounts each give their own key."""
        k = cred.scanner_key
        assert k("https://h/v2", "a") == k("https://H:443/v2", "a")
        assert len({k("https://h/v2", "a"), k("https://h/V2", "a"), k("https://h:8228/v2", "a"), k("https://h/v2", "b")}) == 4

    def test_scanner_key_carries_no_credential(self):
        c = cred.credential_from_envelope(envelope())
        assert SECRET not in c.scanner_key


class TestDiscover:
    def test_each_envelope_in_scope_is_one_instance(self, tmp_path):
        write(tmp_path, "one", data(account="a1"))
        write(tmp_path, "two", data(account="a2"))
        write(tmp_path, "elsewhere", {"token": "x"}, kind="github_pat", scope="github_core")
        usable, errors = cred.discover(tmp_path)
        assert sorted(c.qualified for c in usable) == ["anchore:one", "anchore:two"] and errors == []

    def test_a_malformed_envelope_fails_only_itself(self, tmp_path):
        write(tmp_path, "good", data())
        write(tmp_path, "bad", data(scheme="api_key", username="x"))
        usable, errors = cred.discover(tmp_path)
        assert [c.qualified for c in usable] == ["anchore:good"]
        assert [e.qualified for e in errors] == ["anchore:bad"] and SECRET not in str(errors[0])

    def test_duplicate_scanner_key_refuses_both_naming_both(self, tmp_path):
        write(tmp_path, "first", data(base_url="https://H.example/v2"))
        write(tmp_path, "second", data(base_url="https://h.example:443/v2"))
        usable, errors = cred.discover(tmp_path)
        assert usable == [] and len(errors) == 2
        assert all("anchore:first" in e.reason and "anchore:second" in e.reason for e in errors)

    def test_example_templates_are_never_read_as_credentials(self, tmp_path):
        for template in EXAMPLES.glob("*.secret.example.json"):
            (tmp_path / template.name).write_text(template.read_text(encoding="utf-8"), encoding="utf-8")
        assert cred.discover(tmp_path) == ([], [])

    def test_a_missing_root_is_an_error_not_an_empty_success(self, tmp_path):
        usable, errors = cred.discover(tmp_path / "nope")
        assert usable == [] and len(errors) == 1

    def test_no_credential_pattern_was_added_for_these_credentials(self):
        """req-anchore-connection-11: these credentials are recorded as undetectable by the scanner."""
        import tap.credential_patterns as patterns

        text = " ".join(str(p) for p in patterns.CREDENTIAL_PATTERNS).lower()
        assert "anchore" not in text and "_api_key" not in text


class TestRedactionCannotReproduceTheCredential:
    @pytest.mark.parametrize("secret", ["credential", "REDACTED", "[REDACTED:credential]", "redacted", "[redacted]", "#", "[", "\u2588", "a", "Bearer"])
    def test_the_replacement_never_contains_the_credential(self, secret):
        auth = cred.Auth("basic", _basic=("u", secret))
        text, n = auth.redact(f"before {secret} after {secret}")
        assert n >= 2
        for form in auth._forms():
            assert form not in text
        data, m = auth.redact_bytes(f"x{secret}y".encode())
        assert m >= 1 and all(form.encode() not in data for form in auth._forms())

    def test_an_ordinary_secret_is_replaced_by_the_labelled_marker(self):
        auth = cred.Auth("basic", _basic=("u", SECRET))
        assert auth.redact(f"x {SECRET} y")[0] == f"x {cred.REDACTED} y"


class TestLatinOneCredentials:
    """requests sends Basic credentials as Latin-1; redaction must cover the bytes actually sent."""

    def test_the_form_redacted_is_the_header_requests_sends(self):
        import requests
        from requests.auth import HTTPBasicAuth

        auth = cred.Auth("basic", _basic=("us\u00e9r", "p\u00e4ss\u00e9"))
        prepared = requests.Request("GET", "https://x.invalid/").prepare()
        HTTPBasicAuth("us\u00e9r", "p\u00e4ss\u00e9")(prepared)
        sent = prepared.headers["Authorization"]
        text, n = auth.redact(f"echo: {sent}")
        assert n >= 1 and sent.removeprefix("Basic ") not in text

    def test_a_character_headers_cannot_carry_is_refused_at_load(self):
        with pytest.raises(cred.CredentialError) as err:
            cred.credential_from_envelope(envelope(payload=data(password="pw\u20ac")))
        assert "Latin-1" in str(err.value) and "pw" not in str(err.value)

    def test_a_latin_one_secret_loads(self):
        assert cred.credential_from_envelope(envelope(payload=data(password="p\u00e9"))).auth.basic == ("reader", "p\u00e9")


class TestAccountMask:
    def test_a_standalone_account_name_is_masked_and_a_longer_word_is_not(self):
        c = cred.credential_from_envelope(envelope(payload=data(account="acct")))
        assert c.mask_account("v acct x acct, acct-2 acctual (acct)") == "v [account] x [account], acct-2 acctual ([account])"
