from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import Any
from urllib.parse import urlparse

import httpx
import yaml


SENSITIVE = ("password", "secret", "token", "api_key", "ssn", "credit_card")
ADMIN_WORDS = ("admin", "role", "permission", "scope")
AUTH_NAMES = ("authorization", "auth", "bearer", "jwt", "oauth", "apikey", "api_key")
ID_WORDS = ("id", "user", "account", "order", "invoice", "profile")


@dataclass
class Finding:
    rule_id: str
    title: str
    severity: str
    target: str
    evidence: str
    remediation: str


def _finding(rule_id: str, title: str, severity: str, target: str, evidence: str, remediation: str) -> Finding:
    return Finding(rule_id, title, severity, target, evidence, remediation)


def load_targets(url: str | None = None, spec: str | None = None, endpoints: str | None = None) -> list[dict[str, Any]]:
    targets: list[dict[str, Any]] = []
    if url:
        targets.append({"method": "GET", "url": url, "path": urlparse(url).path or "/", "security": False, "source": "url"})
    if endpoints:
        for line in open(endpoints, encoding="utf-8"):
            value = line.strip()
            if value and not value.startswith("#"):
                parts = value.split(maxsplit=1)
                method, raw_url = (parts[0].upper(), parts[1]) if len(parts) == 2 else ("GET", value)
                targets.append({"method": method, "url": raw_url, "path": urlparse(raw_url).path or raw_url, "security": False, "source": "endpoints"})
    if spec:
        data = yaml.safe_load(open(spec, encoding="utf-8")) or {}
        global_security = bool(data.get("security"))
        for path, methods in (data.get("paths") or {}).items():
            for method, operation in (methods or {}).items():
                if method.lower() not in {"get", "post", "put", "patch", "delete"}:
                    continue
                security = bool((operation or {}).get("security", data.get("security", [])))
                schema_text = str(operation).lower()
                targets.append({
                    "method": method.upper(),
                    "url": path,
                    "path": path,
                    "security": security or global_security,
                    "schema": schema_text,
                    "source": "openapi",
                })
    return targets


def scan_targets(targets: list[dict[str, Any]], timeout: float = 3.0) -> dict[str, Any]:
    findings: list[Finding] = []
    for target in targets:
        findings.extend(_scan_static(target))
        if target.get("source") == "url" and target["url"].startswith(("http://", "https://")):
            findings.extend(_scan_live(target, timeout))
    return {
        "summary": {"targets": len(targets), "findings": len(findings), "rules": 5},
        "findings": [asdict(item) for item in findings],
    }


def _scan_static(target: dict[str, Any]) -> list[Finding]:
    path = target["path"].lower()
    schema = target.get("schema", "")
    out: list[Finding] = []
    target_name = f"{target['method']} {target['path']}"

    if any(f"/{{{word}" in path or f":{word}" in path for word in ID_WORDS) and not target.get("security"):
        out.append(_finding("API1:2023", "Broken Object Level Authorization", "critical", target_name,
                            "Object identifier route has no declared auth requirement.",
                            "Require authorization checks that bind object access to the caller."))
    if any(word in path for word in ("auth", "login", "password", "token")) and not target.get("security"):
        out.append(_finding("API2:2023", "Broken Authentication", "high", target_name,
                            "Authentication-related endpoint lacks declared security controls.",
                            "Add auth schemes, rate limiting, lockouts, and strict token handling."))
    if any(word in schema for word in SENSITIVE):
        out.append(_finding("API3:2023", "Excessive Data Exposure", "medium", target_name,
                            "Response schema appears to expose sensitive fields.",
                            "Return only required fields and filter secrets server-side."))
    if any(word in path for word in ADMIN_WORDS) and not target.get("security"):
        out.append(_finding("API5:2023", "Broken Function Level Authorization", "critical", target_name,
                            "Privileged route is missing an auth requirement.",
                            "Enforce role checks on every privileged function."))
    if target["method"] in {"PUT", "POST", "PATCH", "DELETE"} and not target.get("security"):
        out.append(_finding("API8:2023", "Security Misconfiguration", "medium", target_name,
                            "State-changing operation has no declared security requirement.",
                            "Require auth and document security requirements for write operations."))
    return out


def _scan_live(target: dict[str, Any], timeout: float) -> list[Finding]:
    try:
        response = httpx.request(target["method"], target["url"], timeout=timeout)
    except httpx.HTTPError as exc:
        return [_finding("API8:2023", "Security Misconfiguration", "low", target["url"],
                         f"Request failed during baseline scan: {exc.__class__.__name__}.",
                         "Verify TLS, DNS, and gateway configuration.")]

    findings: list[Finding] = []
    headers = {key.lower(): value for key, value in response.headers.items()}
    if "server" in headers or "x-powered-by" in headers:
        findings.append(_finding("API8:2023", "Security Misconfiguration", "low", target["url"],
                                 "Response exposes server technology headers.",
                                 "Remove version and framework disclosure headers."))
    if response.status_code < 400 and not any(name in headers for name in AUTH_NAMES):
        findings.append(_finding("API2:2023", "Broken Authentication", "medium", target["url"],
                                 f"Unauthenticated request returned HTTP {response.status_code}.",
                                 "Confirm public access is intentional and protect private routes."))
    body = response.text[:5000].lower()
    if any(word in body for word in SENSITIVE):
        findings.append(_finding("API3:2023", "Excessive Data Exposure", "high", target["url"],
                                 "Response body contains sensitive-looking field names.",
                                 "Redact sensitive fields and use explicit response DTOs."))
    return findings
