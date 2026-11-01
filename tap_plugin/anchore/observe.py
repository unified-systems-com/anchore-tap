"""Read one Anchore instance and record what it returns, in a fixed order (the trial session).

This is an instrument, not the collector. It makes GET requests only, through the read-only
client; takes every path from the committed consumed list (plus the instance's own spec); saves
each raw response to a private directory under the home directory, outside any repository
(a credential an instance echoes back, in any form it is sent in, is redacted first); and prints
which open questions the responses answered. It writes nothing to the grid and prints no response
body, no credential, and no account or image name.

    python -m tap_plugin.anchore.observe --list
    python -m tap_plugin.anchore.observe --key <envelope key> [--max-images 1] [--no-account-header] [--dry-run]

A step whose prerequisite is missing, or whose operation needs a parameter this command cannot
know, is recorded as *not read* with the reason, never as empty.
"""

import argparse
import base64
import hashlib
import json
import re
import sys
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, TextIO

from requests.adapters import BaseAdapter
from tap import secrets_root

from tap_plugin.anchore.client import ClientError, ReadOnlyClient, Reply, fill
from tap_plugin.anchore.contract import drift
from tap_plugin.anchore.contract.build import CONSUMED, EXTRACT, SOURCE
from tap_plugin.anchore.contract.reduce import ReducerError, load_document
from tap_plugin.anchore.credential import Credential, discover

# The instance's own OpenAPI file, read by the per-run self-test (req-anchore-selftest).
SPEC_PATH = "/openapi.json"
RECORDINGS_DIRNAME = "anchore-recordings"
DIGEST_SHAPES = (("sha256, 64 hex", re.compile(r"^sha256:[0-9a-f]{64}$")), ("sha512, 128 hex", re.compile(r"^sha512:[0-9a-f]{128}$")))
_DIGEST_KEYS = ("imageDigest", "image_digest", "digest")
_ID_KEYS = ("id", "uuid")
_TAG_KEYS = ("fulltag", "tag")
_SEVERITY_KEYS = ("severity",)


@dataclass
class Line:
    step: str
    template: str
    status: str
    elapsed_ms: int | None
    size: int | None
    content_type: str | None
    note: str = ""


@dataclass
class Context:
    credential: Credential
    client: ReadOnlyClient
    out_dir: Path
    consumed: set[str]
    params_by_path: dict[str, dict[str, bool]]
    account_header: bool
    lines: list[Line] = field(default_factory=list)
    answers: list[str] = field(default_factory=list)
    counter: int = 0
    redactions: int = 0


def _load_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def _slug(template: str) -> str:
    return re.sub(r"[^a-z0-9]+", "-", template.lower()).strip("-")[:60] or "root"


def _json_body(reply: Reply) -> Any | None:
    try:
        return json.loads(reply.body)
    except ValueError:
        return None


def safe(text: Any, limit: int = 240) -> str:
    """Make text that came from an instance safe to print: printable characters only, bounded.

    A hostile or broken instance can put control characters or terminal escape sequences in a
    field name, a version or a spec path; none of it reaches the terminal.
    """
    cleaned = "".join(ch if ch.isprintable() else "?" for ch in str(text))
    return cleaned if len(cleaned) <= limit else cleaned[: limit - 3] + "..."


def shape(value: Any) -> str:
    """A compact description of a JSON value: its type, its keys, and the first list it holds."""
    if isinstance(value, list):
        first = value[0] if value and isinstance(value[0], dict) else None
        keys = f", item keys: {sorted(first)[:40]}" if first else ""
        return f"list of {len(value)}{keys}"
    if isinstance(value, dict):
        keys = sorted(value)[:30]
        for key in keys:
            inner = value[key]
            if isinstance(inner, list):
                first = inner[0] if inner and isinstance(inner[0], dict) else None
                extra = f"; first item keys: {sorted(first)[:60]}" if first else ""
                return f"object keys {keys}; list under {key!r} has {len(inner)}{extra}"
        return f"object keys {keys}"
    return type(value).__name__


def items_of(value: Any) -> tuple[str | None, list[dict[str, Any]]]:
    """The list of records in a response and the key it sits under (None for a bare list)."""
    if isinstance(value, list):
        return None, [v for v in value if isinstance(v, dict)]
    if isinstance(value, dict):
        for key in sorted(value):
            inner = value[key]
            if isinstance(inner, list) and inner and isinstance(inner[0], dict):
                return key, inner
    return None, []


def _first_string(item: dict[str, Any], keys: tuple[str, ...]) -> str | None:
    for key in keys:
        if isinstance(item.get(key), str) and item[key]:
            return item[key]
    return None


def _find_key(value: Any, names: tuple[str, ...]) -> str | None:
    stack = [value]
    while stack:
        node = stack.pop()
        if isinstance(node, dict):
            for name in names:
                if isinstance(node.get(name), str) and node[name]:
                    return node[name]
            stack.extend(node.values())
        elif isinstance(node, list):
            stack.extend(node)
    return None


def digest_kind(digest: str) -> str:
    for label, pattern in DIGEST_SHAPES:
        if pattern.match(digest):
            return label
    return f"other (starts {digest.split(':', 1)[0][:12]!r})"


def fetch(ctx: Context, step: str, template: str, *, values: dict[str, str] | None = None, params: dict[str, Any] | None = None, account_header: bool | None = None, accept: str = "application/json") -> Reply | None:
    """One recorded GET. Returns the reply, or None when the request was skipped or failed."""
    if template != SPEC_PATH and template not in ctx.consumed:
        raise ClientError(f"{template} is not in the consumed list; the observation command reads only that list")
    known = ctx.params_by_path.get(template, {})
    missing = [name for name, required in known.items() if required and name not in (params or {})]
    if missing:
        ctx.lines.append(Line(step, template, "not read", None, None, None, f"needs parameter {', '.join(missing)}"))
        return None
    path = fill(template, **(values or {}))
    use_header = ctx.account_header if account_header is None else account_header
    ctx.counter += 1
    record: dict[str, Any] = {"step": step, "template": template, "path": path, "params": params or {}, "account_header_sent": use_header}
    reply: Reply | None = None
    failure: str | None = None
    redactions = 0
    try:
        reply = ctx.client.get(path, params=params, account_header=use_header, accept=accept)
    except ClientError as exc:
        # The full message (which names the path) goes into the recording only; what is printed
        # is the class of failure, so no image or source identifier reaches the terminal.
        failure = type(exc).__name__
        record["error"], n = ctx.credential.redact(str(exc))
        redactions += n
        reply = getattr(exc, "reply", None)
    if reply is not None:
        headers: dict[str, str] = {}
        for name, value in reply.headers.items():
            headers[name], n = ctx.credential.redact(value)
            redactions += n
        body, n = ctx.credential.redact_bytes(reply.body)
        redactions += n
        record.update(status=reply.status, headers=headers, elapsed_ms=reply.elapsed_ms, attempts=reply.attempts, request_header_names=list(reply.request_headers), body_bytes=len(reply.body))
        try:
            record["body_text"] = body.decode("utf-8")
        except UnicodeDecodeError:
            record["body_base64"] = base64.b64encode(body).decode("ascii")
    record["credential_redactions"] = redactions
    ctx.redactions += redactions
    target = ctx.out_dir / f"{ctx.counter:03d}-{_slug(template)}.json"
    target.write_text(json.dumps(record, indent=1, ensure_ascii=False), encoding="utf-8")
    target.chmod(0o600)
    if reply is None:
        ctx.lines.append(Line(step, template, "failed", None, None, None, failure or ""))
        return None
    note = failure or ""
    ctx.lines.append(Line(step, template, str(reply.status), reply.elapsed_ms, len(reply.body), reply.content_type, note))
    return reply if reply.status == 200 else None


def step_account(ctx: Context) -> None:
    with_header = fetch(ctx, "account", "/account", account_header=True)
    without = fetch(ctx, "account", "/account", account_header=False)
    ctx.answers.append(f"scheme {ctx.credential.scheme}: GET /account with the account header -> {'200' if with_header else 'not 200'}, without it -> {'200' if without else 'not 200'}")
    if with_header is not None:
        body = _json_body(with_header)
        names = sorted(body) if isinstance(body, dict) else []
        matches = isinstance(body, dict) and any(v == ctx.credential.account for v in body.values())
        ctx.answers.append(f"/account body keys {names[:20]}; a value equals the configured account: {'yes' if matches else 'no'}")


def step_probe(ctx: Context) -> None:
    for template in ("/status", "/system", "/system/feeds"):
        reply = fetch(ctx, "probe", template)
        if reply is not None:
            ctx.answers.append(f"{template}: {shape(_json_body(reply))}")


def step_spec(ctx: Context) -> None:
    reply = fetch(ctx, "spec", SPEC_PATH)
    if reply is None:
        ctx.answers.append("instance spec: not served or not readable with this credential")
        return
    try:
        fresh = load_document(reply.body)
        baseline = load_document(SOURCE.read_bytes())
        found, other = drift.compare(fresh, _load_json(CONSUMED), _load_json(EXTRACT), baseline)
    except ReducerError as exc:
        ctx.answers.append(f"instance spec: could not be read ({exc})")
        return
    version = (fresh.get("info") or {}).get("version")
    ctx.answers.append(f"instance spec: version {version}; {len(found)} difference(s) in what the plugin consumes, {len(other)} outside it")
    ctx.answers.extend(f"  consumed difference: {line[:200]}" for line in found[:15])


def step_images(ctx: Context, max_images: int) -> None:
    reply = fetch(ctx, "images", "/images")
    if reply is None:
        ctx.answers.append("images: not read")
        return
    body = _json_body(reply)
    wrapper, items = items_of(body)
    ctx.answers.append(f"/images: {shape(body)}; records under {wrapper!r}")
    kinds: dict[str, int] = {}
    chosen: list[tuple[str, str | None]] = []
    for item in items:
        digest = _first_string(item, _DIGEST_KEYS)
        if digest:
            kinds[digest_kind(digest)] = kinds.get(digest_kind(digest), 0) + 1
    ctx.answers.append(f"image digest kinds in the first page: {kinds or 'none found'}")
    ordered = sorted(items, key=lambda i: 0 if "analyzed" in json.dumps(i).lower() else 1)
    for item in ordered:
        digest = _first_string(item, _DIGEST_KEYS)
        if digest and len(chosen) < max_images:
            chosen.append((digest, _find_key(item, _TAG_KEYS)))
    for digest, tag in chosen:
        step_image(ctx, digest, tag)
    if not chosen:
        ctx.answers.append("no image digest found to sample; per-image reads not read")


def step_image(ctx: Context, digest: str, tag: str | None) -> None:
    values = {"image_digest": digest}
    base = "/images/{image_digest}"
    reply = fetch(ctx, "image", f"{base}/vuln/{{vuln_type}}", values={**values, "vuln_type": "all"})
    if reply is not None:
        body = _json_body(reply)
        _, vulns = items_of(body)
        severities: dict[str, int] = {}
        keys: set[str] = set()
        for record in vulns:
            keys.update(record)
            for name in _SEVERITY_KEYS:
                if isinstance(record.get(name), str):
                    severities[record[name]] = severities.get(record[name], 0) + 1
        ctx.answers.append(f"vulnerability records: {len(vulns)}; severity values seen {severities}; fields {sorted(keys)[:60]}")
    for template in ("sboms/native-json", "sboms/spdx-json", "sboms/cyclonedx-json", "vex/openvex", "vex/cyclonedx-json", "vex/cyclonedx-xml"):
        accept = "application/xml" if template.endswith("xml") else "application/json"
        r = fetch(ctx, "image", f"{base}/{template}", values=values, accept=accept)
        if r is not None:
            ctx.answers.append(f"{template}: {len(r.body)} bytes, {r.content_type}")
    for template in ("vuln-annotations", "content", "content-summary", "metadata"):
        fetch(ctx, "image", f"{base}/{template}", values=values)
    if tag:
        fetch(ctx, "image", f"{base}/check", values=values, params={"tag": tag})
    else:
        ctx.lines.append(Line("image", f"{base}/check", "not read", None, None, None, "no tag found in the image record"))


def step_sources(ctx: Context) -> None:
    reply = fetch(ctx, "sources", "/sources")
    if reply is None:
        return
    wrapper, items = items_of(_json_body(reply))
    ctx.answers.append(f"/sources: records under {wrapper!r}, {len(items)} on the first page")
    source_id = _first_string(items[0], _ID_KEYS) if items else None
    if not source_id:
        return
    values = {"source_id": source_id}
    fetch(ctx, "sources", "/sources/{source_id}/vuln/{vuln_type}", values={**values, "vuln_type": "all"})
    for template in ("check", "content-summary", "sbom/native-json"):
        fetch(ctx, "sources", f"/sources/{{source_id}}/{template}", values=values)


def step_apps(ctx: Context) -> None:
    reply = fetch(ctx, "apps", "/apps")
    if reply is not None:
        wrapper, items = items_of(_json_body(reply))
        ctx.answers.append(f"/apps: records under {wrapper!r}, {len(items)} on the first page")
        app_id = _first_string(items[0], ("id", "app_id")) if items else None
        if app_id:
            step_app(ctx, app_id)
    fetch(ctx, "applications", "/applications")


def step_app(ctx: Context, app_id: str) -> None:
    reply = fetch(ctx, "apps", "/apps/{app_id}/versions", values={"app_id": app_id})
    if reply is None:
        return
    _, versions = items_of(_json_body(reply))
    version_id = _first_string(versions[0], ("id", "version_id")) if versions else None
    if not version_id:
        return
    values = {"app_id": app_id, "version_id": version_id}
    for template in ("assets", "packages", "vulnerabilities", "vulnerability-annotations", "policy/status"):
        fetch(ctx, "apps", f"/apps/{{app_id}}/versions/{{version_id}}/{template}", values=values)


def step_inventory(ctx: Context) -> None:
    for template in ("/inventories", "/ecs-containers", "/ecs-tasks", "/ecs-services", "/kubernetes-namespaces", "/kubernetes-nodes", "/kubernetes-pods", "/kubernetes-containers"):
        known = ctx.params_by_path.get(template, {})
        params: dict[str, Any] = {}
        if "page" in known:
            params["page"] = 1
        if "page_size" in known:
            params["page_size"] = 5
        reply = fetch(ctx, "inventory", template, params=params or None)
        if reply is not None:
            ctx.answers.append(f"{template}: {shape(_json_body(reply))}")


def _out_dir(credential: Credential, root: Path | None) -> Path:
    base = root if root is not None else Path.home() / RECORDINGS_DIRNAME
    stamp = datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")
    name = f"{stamp}-{hashlib.sha256(credential.qualified.encode()).hexdigest()[:8]}"
    # The root is made owner-only as well as the per-run directory: mkdir's mode is not applied to
    # parents, and a listable root would show run times and hash prefixes on a shared host.
    base.mkdir(parents=True, exist_ok=True, mode=0o700)
    base.chmod(0o700)
    target = base / name
    target.mkdir(exist_ok=True, mode=0o700)
    target.chmod(0o700)
    return target


def _context(credential: Credential, client: ReadOnlyClient, out_dir: Path, account_header: bool) -> Context:
    consumed = {o["path"] for o in _load_json(CONSUMED)["operations"]}
    params: dict[str, dict[str, bool]] = {}
    for op in _load_json(EXTRACT)["operations"]:
        params[op["path"]] = {p["name"]: bool(p["required"]) for p in op.get("parameters", []) if p.get("in") == "query"}
    return Context(credential, client, out_dir, consumed, params, account_header)


PLAN: tuple[tuple[str, str], ...] = (
    ("account", "Does the scheme work, and is the account header honoured?"),
    ("probe", "What can this credential read of status, system and feeds?"),
    ("spec", "Does the instance serve its spec, and how does it differ from the vendor's?"),
    ("images", "What do digests, paging and the list wrapper look like? Then one image's findings, SBOMs, VEX and policy check."),
    ("sources", "What does a repository source look like?"),
    ("apps", "What do applications, versions, assets and policy status look like?"),
    ("inventory", "What do the runtime inventory lists look like?"),
)


def render(ctx: Context, stdout: TextIO) -> None:
    print(f"\nObserved {ctx.credential.qualified} (scheme {ctx.credential.scheme}); recordings in {ctx.out_dir}\n", file=stdout)
    print(f"{'step':<12}{'status':<10}{'ms':>6}{'bytes':>10}  {'content-type':<28}request", file=stdout)
    for line in ctx.lines:
        ms = "" if line.elapsed_ms is None else str(line.elapsed_ms)
        size = "" if line.size is None else str(line.size)
        note = f"  [{safe(line.note, 160)}]" if line.note else ""
        print(f"{line.step:<12}{safe(line.status, 12):<10}{ms:>6}{size:>10}  {safe(line.content_type or '', 27):<28}GET {line.template}{note}", file=stdout)
    if ctx.redactions:
        print(f"\n{ctx.redactions} occurrence(s) of the credential were found in what the instance returned and redacted from the recordings.", file=stdout)
    print("\nAnswers to the open questions:", file=stdout)
    for answer in ctx.answers:
        print(f"  - {safe(answer)}", file=stdout)


def run(credential: Credential, *, max_images: int = 1, account_header: bool = True, out_root: Path | None = None, transport: BaseAdapter | None = None, sleep: Callable[[float], None] | None = None, stdout: TextIO | None = None) -> Context:
    stdout = stdout if stdout is not None else sys.stdout
    out_dir = _out_dir(credential, out_root)
    kwargs: dict[str, Any] = {"transport": transport}
    if sleep is not None:
        kwargs["sleep"] = sleep
    with ReadOnlyClient(credential, **kwargs) as client:
        ctx = _context(credential, client, out_dir, account_header)
        step_account(ctx)
        step_probe(ctx)
        step_spec(ctx)
        step_images(ctx, max_images)
        step_sources(ctx)
        step_apps(ctx)
        step_inventory(ctx)
    render(ctx, stdout)
    return ctx


def main(argv: list[str] | None = None, *, stdout: TextIO | None = None, out_root: Path | None = None, transport: BaseAdapter | None = None, sleep: Callable[[float], None] | None = None) -> int:
    stdout = stdout if stdout is not None else sys.stdout
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--list", action="store_true", help="list the envelopes found, with no request")
    parser.add_argument("--key", help="the key of the envelope to observe")
    parser.add_argument("--max-images", type=int, default=1, help="how many images to sample (default 1)")
    parser.add_argument("--no-account-header", action="store_true", help="do not send x-anchore-account on the later steps")
    parser.add_argument("--dry-run", action="store_true", help="print the plan and send nothing")
    args = parser.parse_args(argv)
    root = secrets_root.resolve()
    if root is None:
        print("no secrets root: set TAP_SECRETS_ROOT to the directory holding the envelope", file=stdout)
        return 2
    usable, errors = discover(root)
    if args.list or not args.key:
        for c in usable:
            print(f"{c.qualified}: scheme {c.scheme}, root {c.base_url}", file=stdout)
        for e in errors:
            print(f"{e.qualified}: NOT USABLE - {e.reason}", file=stdout)
        if not usable and not errors:
            print("no envelope in scope anchore", file=stdout)
        return 0
    matches = [c for c in usable if c.qualified.split(":", 1)[1] == args.key]
    if not matches:
        refused = [e for e in errors if e.qualified.split(":", 1)[-1] == args.key]
        for e in refused:
            print(f"{e.qualified}: NOT USABLE - {e.reason}", file=stdout)
        print(f"no usable envelope with key {args.key!r} in scope anchore", file=stdout)
        return 2
    credential = matches[0]
    if args.dry_run:
        print(f"Plan for {credential.qualified} (scheme {credential.scheme}); nothing is sent:", file=stdout)
        for name, question in PLAN:
            print(f"  {name}: {question}", file=stdout)
        return 0
    run(credential, max_images=max(1, args.max_images), account_header=not args.no_account_header, out_root=out_root, transport=transport, sleep=sleep, stdout=stdout)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
