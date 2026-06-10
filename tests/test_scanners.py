import httpx

from api_scanner.scanners import rules
from api_scanner.scanners.rules import load_targets, scan_targets


def test_openapi_loads_targets():
    targets = load_targets(spec="examples/sample_openapi.yaml")
    assert len(targets) == 3


def test_api1_bola_detected():
    results = scan_targets([{"method": "GET", "path": "/users/{id}", "url": "/users/{id}", "security": False, "source": "openapi"}])
    assert any(f["rule_id"] == "API1:2023" for f in results["findings"])


def test_api2_auth_endpoint_detected():
    results = scan_targets([{"method": "POST", "path": "/auth/login", "url": "/auth/login", "security": False, "source": "openapi"}])
    assert any(f["rule_id"] == "API2:2023" for f in results["findings"])


def test_api3_sensitive_schema_detected():
    results = scan_targets([{"method": "GET", "path": "/me", "url": "/me", "security": True, "schema": "password token", "source": "openapi"}])
    assert any(f["rule_id"] == "API3:2023" for f in results["findings"])


def test_api5_admin_route_detected():
    results = scan_targets([{"method": "GET", "path": "/admin/users", "url": "/admin/users", "security": False, "source": "openapi"}])
    assert any(f["rule_id"] == "API5:2023" for f in results["findings"])


def test_api8_write_without_security_detected():
    results = scan_targets([{"method": "DELETE", "path": "/posts/1", "url": "/posts/1", "security": False, "source": "openapi"}])
    assert any(f["rule_id"] == "API8:2023" for f in results["findings"])


def test_secured_object_route_avoids_bola():
    results = scan_targets([{"method": "GET", "path": "/users/{id}", "url": "/users/{id}", "security": True, "source": "openapi"}])
    assert not any(f["rule_id"] == "API1:2023" for f in results["findings"])


def test_summary_counts_findings():
    results = scan_targets([{"method": "POST", "path": "/admin/users", "url": "/admin/users", "security": False, "source": "openapi"}])
    assert results["summary"]["targets"] == 1
    assert results["summary"]["findings"] >= 2


def test_endpoint_file_loads_method_and_url():
    targets = load_targets(endpoints="examples/sample_api_endpoints.txt")
    assert targets[0]["method"] == "GET"
    assert targets[1]["path"] == "/admin/users"


def test_url_loader_defaults_to_get():
    targets = load_targets(url="https://api.example.com/users/123")
    assert targets == [{"method": "GET", "url": "https://api.example.com/users/123", "path": "/users/123", "security": False, "source": "url"}]


def test_live_scan_detects_headers_and_sensitive_body(monkeypatch):
    def fake_request(method, url, timeout):
        return httpx.Response(200, headers={"server": "demo"}, text='{"token":"abc"}')

    monkeypatch.setattr(rules.httpx, "request", fake_request)
    results = scan_targets([{"method": "GET", "url": "https://api.example.com/me", "path": "/me", "security": False, "source": "url"}])
    ids = [finding["rule_id"] for finding in results["findings"]]
    assert ids.count("API8:2023") == 1
    assert "API2:2023" in ids
    assert "API3:2023" in ids


def test_live_scan_reports_request_failure(monkeypatch):
    def fake_request(method, url, timeout):
        raise httpx.ConnectError("boom")

    monkeypatch.setattr(rules.httpx, "request", fake_request)
    results = scan_targets([{"method": "GET", "url": "https://api.example.com", "path": "/", "security": False, "source": "url"}])
    assert results["findings"][0]["rule_id"] == "API8:2023"
