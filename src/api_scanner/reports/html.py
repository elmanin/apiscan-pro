from __future__ import annotations

from pathlib import Path

from jinja2 import Environment, FileSystemLoader, select_autoescape


def render_html_report(results: dict, output: str) -> str:
    repo_template_dir = Path(__file__).resolve().parents[3] / "reports" / "templates"
    template_dir = repo_template_dir if repo_template_dir.exists() else Path(__file__).with_name("templates")
    env = Environment(loader=FileSystemLoader(template_dir), autoescape=select_autoescape())
    html = env.get_template("html_report.jinja2").render(results=results)
    Path(output).write_text(html, encoding="utf-8")
    return output
