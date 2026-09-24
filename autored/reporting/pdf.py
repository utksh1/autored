"""PDF rendering for engagement reports (Phase 6, spec §13.6).

Markdown → HTML (``markdown`` lib) → PDF (WeasyPrint). WeasyPrint needs
system libraries (Pango, Cairo, GDK-PixBuf) that are standard on Kali but
often absent on slim containers — ``render_pdf`` therefore degrades to
``None`` with a warning instead of raising, and the markdown report is
always written first by the Report Agent (it is the deliverable of
record).
"""
import asyncio
from pathlib import Path

import markdown as markdown_lib

from autored.logging import get_logger

log = get_logger("reporting.pdf")

_REPORT_CSS = """
@page {
    size: A4;
    margin: 2cm 1.8cm;
    @bottom-right { content: "AutoRed — page " counter(page) " / " counter(pages); }
}
body {
    font-family: 'DejaVu Sans', sans-serif;
    font-size: 10pt;
    line-height: 1.45;
    color: #1a1a1a;
}
h1 { font-size: 18pt; border-bottom: 2px solid #444; padding-bottom: 4px; }
h2 { font-size: 13pt; margin-top: 18px; color: #333; }
table { border-collapse: collapse; width: 100%; margin: 8px 0; font-size: 9pt; }
th, td { border: 1px solid #999; padding: 3px 6px; text-align: left; }
th { background: #eee; }
pre { background: #f5f5f5; border: 1px solid #ddd; padding: 6px;
      font-family: 'DejaVu Sans Mono', monospace; font-size: 8.5pt;
      white-space: pre-wrap; word-wrap: break-word; }
code { font-family: 'DejaVu Sans Mono', monospace; font-size: 9pt; }
"""


def _import_weasyprint():
    """Import WeasyPrint lazily — the single import point for test patching."""
    import weasyprint  # noqa: PLC0415 — deliberate lazy import
    return weasyprint


def _markdown_to_html(md: str) -> str:
    body = markdown_lib.markdown(md, extensions=["tables", "fenced_code"])
    return (
        "<!DOCTYPE html>\n"
        "<html>\n"
        "<head>\n"
        "<meta charset=\"utf-8\">\n"
        "<title>AutoRed Engagement Report</title>\n"
        f"<style>{_REPORT_CSS}</style>\n"
        "</head>\n"
        f"<body>\n{body}\n</body>\n</html>\n"
    )


async def render_pdf(
    markdown_text: str,
    engagement_id: str,
    engagements_dir: str = "engagements",
) -> Path | None:
    """Render the markdown report to ``engagements/<id>/report.pdf``.

    Returns the PDF path, or ``None`` when WeasyPrint (or its system
    libraries) is unavailable — never raises (plan Review Focus #5).
    """
    def _render() -> Path:
        weasyprint = _import_weasyprint()
        out_dir = Path(engagements_dir) / engagement_id
        out_dir.mkdir(parents=True, exist_ok=True)
        pdf_path = out_dir / "report.pdf"
        weasyprint.HTML(string=_markdown_to_html(markdown_text)).write_pdf(str(pdf_path))
        return pdf_path

    try:
        return await asyncio.to_thread(_render)
    except ImportError as e:
        log.warning("pdf_renderer_unavailable", engagement_id=engagement_id, error=str(e))
        return None
    except Exception as e:  # noqa: BLE001 — missing Pango/Cairo raises OSError here
        log.warning("pdf_render_failed", engagement_id=engagement_id, error=str(e))
        return None
