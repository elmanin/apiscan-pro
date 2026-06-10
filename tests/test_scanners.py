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
