"""A fake Anchore transport for tests: canned responses, no socket (req-anchore-contract-extract-2)."""

import io
import json
from pathlib import Path
from typing import Any

import requests
from requests.adapters import BaseAdapter

VENDOR = Path(__file__).resolve().parent / "vendor"
DIGEST = "sha256:" + "ab" * 32


def response(status: int = 200, body: bytes | str | dict | list = b"{}", headers: dict[str, str] | None = None) -> requests.Response:
    if isinstance(body, (dict, list)):
        body = json.dumps(body).encode()
    if isinstance(body, str):
        body = body.encode()
    r = requests.Response()
    r.status_code = status
    r._content = body  # noqa: SLF001 - building a canned response
    r._content_consumed = True  # noqa: SLF001
    r.raw = io.BytesIO(body)
    base = {"content-type": "application/json", "content-length": str(len(body))}
    base.update(headers or {})
    r.headers.update(base)
    return r


class FakeTransport(BaseAdapter):
    """Answers from a path -> response table and records every request it is handed."""

    def __init__(self, routes: dict[str, Any] | None = None, default: Any = None) -> None:
        super().__init__()
        self.routes = routes or {}
        self.default = default
        self.calls: list[requests.PreparedRequest] = []

    def send(self, request: requests.PreparedRequest, **kwargs: Any) -> requests.Response:
        self.calls.append(request)
        path = str(request.url).split("/v2", 1)[-1].split("?", 1)[0]
        route = self.routes.get(path, self.default)
        if callable(route):
            out = route(request)
        else:
            out = route
        if out is None:
            out = response(404, {"detail": "not found"})
        if isinstance(out, Exception):
            raise out
        out.request = request
        return out

    def close(self) -> None:
        pass


def anchore_routes() -> dict[str, Any]:
    """A small but complete fake instance: one analysed image, no sources, apps or inventory."""
    spec = (VENDOR / "openapi-2.20.0.json").read_bytes()
    vulns = {"vulnerabilities": [{"vuln": "CVE-2024-0001", "severity": "High", "fix": "1.2.3", "package": "libx"}, {"vuln": "CVE-2024-0002", "severity": "Low", "fix": "None", "package": "liby"}]}
    image = {"images": [{"imageDigest": DIGEST, "analysis_status": "analyzed", "image_detail": [{"fulltag": "registry.example/app:1"}]}]}
    d = f"/images/{DIGEST}"
    return {
        "/account": response(200, {"name": "demo-account", "type": "user"}),
        "/status": response(200, {"service": "up"}),
        "/system": response(200, {"version": "5.0"}),
        "/system/feeds": response(200, [{"name": "vulnerabilities", "groups": []}]),
        "/openapi.json": response(200, spec),
        "/images": response(200, image),
        f"{d}/vuln/all": response(200, vulns),
        f"{d}/sboms/native-json": response(200, {"artifacts": []}),
        f"{d}/sboms/spdx-json": response(200, {"spdxVersion": "SPDX-2.3"}),
        f"{d}/sboms/cyclonedx-json": response(200, {"bomFormat": "CycloneDX"}),
        f"{d}/vex/openvex": response(200, {"statements": []}),
        f"{d}/check": response(200, [{"sha256": {"docker.io/x": [{"detail": {}, "status": "pass"}]}}]),
        f"{d}/content": response(200, ["os", "npm"]),
        "/sources": response(200, {"sources": []}),
        "/apps": response(200, {"items": []}),
    }
