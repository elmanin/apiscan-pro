# Indie API Scanner

Indie API Scanner is a local-first OWASP API security scanner for developers who ship APIs without a dedicated security team. It runs from your terminal, scans a live endpoint or a local OpenAPI file, and produces JSON plus a clean HTML report you can share with your team.

The free GitHub version is fully usable on its own. It implements five high-signal OWASP API Top 10 checks: Broken Object Level Authorization, Broken Authentication, Excessive Data Exposure, Broken Function Level Authorization, and Security Misconfiguration.

```text
$ api-scanner --spec examples/sample_openapi.yaml --html-output report.html
{
  "summary": { "targets": 3, "findings": 7, "rules": 5 }
}
```

```text
+ API Scanner Report -----------------------------+
| API1:2023 Broken Object Level Authorization     |
| Severity: CRITICAL                              |
| Target: GET /users/{id}                         |
+-------------------------------------------------+
```

## Why Use It

Use it before launching a new API to catch risky object ID routes, login endpoints, and write operations that lack declared security. Add it to pull requests when OpenAPI specs change so insecure paths are flagged before release. Run it during freelance or indie product handoffs to create a readable local security report without sending customer API data to a hosted scanner.

## Install

```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
pip install -e .
```

## Usage

```bash
api-scanner --url https://api.example.com/users/123
api-scanner --spec examples/sample_openapi.yaml --json-output results.json
api-scanner --endpoints examples/sample_api_endpoints.txt --html-output report.html
```

```text
Severity ranking: critical > high > medium > low
Outputs: terminal JSON, optional .json file, optional local .html report
Runtime: local machine only, no accounts, no hosted backend
```

## Free vs Pro

| Feature | Free GitHub | Pro Download |
|---|---:|---:|
| Local CLI scanner | Yes | Yes |
| OWASP API rules | 5 | All 15 + custom rules |
| JSON export | Yes | Yes |
| HTML report | Yes | 5 professional templates |
| PDF report | No | Yes |
| Batch scans | Basic endpoint file | 100+ endpoint YAML batches |
| Remediation | Concise guidance | Code snippets per finding |
| Scan history | No | Local SQLite history |
| Compliance packs | No | SOC 2 and PCI DSS outputs |
| Example specs | 1 | 20+ specs and playbooks |

## Upgrade to Pro on Gumroad

Need deeper coverage for client work, audits, or production release gates? API Scanner Pro is a paid downloadable package that still runs entirely on your machine or server. It adds all 15 OWASP API Top 10 checks, custom rules, PDF reports, professional templates, local scan history, batch scanning, advanced config, remediation snippets, SOC 2 and PCI DSS output packs, and 20+ bonus OpenAPI examples.

Download Pro on Gumroad: [https://gumroad.com](https://1328925096576.gumroad.com/l/txyrfc)

## Development

```bash
pytest
docker build -t indie-api-scanner .
docker run --rm indie-api-scanner --spec examples/sample_openapi.yaml
```

MIT licensed. Built for local-first API security workflows.
