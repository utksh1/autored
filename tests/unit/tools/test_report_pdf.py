"""Unit tests for the PDF renderer (Phase 6 Task 7)."""
from pathlib import Path

import pytest

from autored.reporting.pdf import _markdown_to_html, _REPORT_CSS, render_pdf


def test_markdown_to_html_wraps_document_and_converts_tables():
    md = "# Title\n\n| A | B |\n|---|---|\n| 1 | 2 |\n"
    html = _markdown_to_html(md)
    assert html.startswith("<!DOCTYPE html>")
    assert "<title>" in html
    assert _REPORT_CSS in html
    assert "<table>" in html  # tables extension active


def test_markdown_to_html_converts_fenced_code():
    md = "# T\n\n```bash\nnmap -sV target\n```\n"
    html = _markdown_to_html(md)
    assert "<pre>" in html and "nmap" in html

async def test_render_pdf_writes_valid_pdf(tmp_path):
    try:
        import weasyprint  # noqa: PLC0415
    except (ImportError, OSError):
        pytest.skip("weasyprint requires Pango/Cairo system libraries")

    md = "# Engagement Report\n\n## Executive Summary\n\nAll good.\n"
    pdf_path = await render_pdf(md, "e-pdf-test", engagements_dir=str(tmp_path))
    assert pdf_path is not None
    assert pdf_path.exists()
    assert pdf_path.name == "report.pdf"
    magic = pdf_path.read_bytes()[:5]
    assert magic == b"%PDF-"


async def test_render_pdf_degrades_when_weasyprint_missing(monkeypatch, tmp_path):
    """Review Focus #5 — missing renderer must never lose the deliverable."""
    import autored.reporting.pdf as pdf_mod

    def _boom():
        raise ImportError("weasyprint requires Pango/Cairo system libraries")

    monkeypatch.setattr(pdf_mod, "_import_weasyprint", _boom)
    md = "# Report\n\nBody.\n"
    pdf_path = await render_pdf(md, "e-pdf-test2", engagements_dir=str(tmp_path))
    assert pdf_path is None  # graceful: None, not an exception


async def test_render_pdf_degrades_on_render_error(monkeypatch, tmp_path):
    import autored.reporting.pdf as pdf_mod

    class FakeWeasyprintModule:
        class HTML:
            def __init__(self, *args, **kwargs):
                pass

            def write_pdf(self, target):
                raise OSError("cannot load library 'pango'")

    monkeypatch.setattr(pdf_mod, "_import_weasyprint", lambda: FakeWeasyprintModule)
    md = "# Report\n\nBody.\n"
    pdf_path = await render_pdf(md, "e-pdf-test3", engagements_dir=str(tmp_path))
    assert pdf_path is None
