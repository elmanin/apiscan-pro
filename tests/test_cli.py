import json

from click.testing import CliRunner

from api_scanner.cli.main import cli


def test_cli_requires_input():
    result = CliRunner().invoke(cli, [])
    assert result.exit_code != 0
    assert "Provide --url, --spec, or --endpoints" in result.output


def test_cli_spec_json_and_html_outputs(tmp_path):
    json_path = tmp_path / "results.json"
    html_path = tmp_path / "report.html"
    result = CliRunner().invoke(cli, ["--spec", "examples/sample_openapi.yaml", "--json-output", str(json_path), "--html-output", str(html_path)])
    assert result.exit_code == 0
    assert json.loads(json_path.read_text())["summary"]["findings"] >= 5
    assert "API Scanner Report" in html_path.read_text()
