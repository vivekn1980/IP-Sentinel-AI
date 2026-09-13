"""HTML Forensic Report Generator utilizing Jinja2 templating."""

import logging
import html
from pathlib import Path
from typing import Optional

from jinja2 import Environment, FileSystemLoader

from ip_sentinel.core.exceptions import ReportError
from ip_sentinel.core.path_utils import get_resource_path
from ip_sentinel.models.report_model import ReportData
from ip_sentinel.reports.base import BaseReportGenerator

logger = logging.getLogger("ip_sentinel.reports.html")


def sanitize_input(value: str) -> str:
    """Escape user inputs to prevent HTML script injection in generated reports."""
    if not isinstance(value, str):
        return str(value)
    return html.escape(value)


class HTMLReportGenerator(BaseReportGenerator):
    """Generates self-contained HTML forensic reports using Jinja2 templates."""

    def __init__(self, template_path: Optional[Path] = None):
        self.template_path = template_path or get_resource_path("templates/report_template.html")

    def generate_report(self, data: ReportData, output_path: Path) -> Path:
        """Render investigation data into standalone HTML file."""
        logger.info(f"Generating HTML report for target IP {data.result.target_ip} at {output_path}")

        if not self.template_path.exists():
            logger.error(f"HTML Template file missing at {self.template_path}")
            raise ReportError(f"Report template file missing at {self.template_path}")

        try:
            env = Environment(
                loader=FileSystemLoader(str(self.template_path.parent)),
                autoescape=True,
            )
            template = env.get_template(self.template_path.name)
            rendered_html = template.render(
                result=data.result,
                metadata=data.metadata,
                notes=data.notes,
                executive_summary=data.executive_summary,
            )

            out_p = Path(output_path)
            out_p.parent.mkdir(parents=True, exist_ok=True)
            with open(out_p, "w", encoding="utf-8") as f:
                f.write(rendered_html)

            logger.info(f"Successfully generated HTML report at {out_p}")
            return out_p
        except Exception as err:
            logger.error(f"Failed to generate HTML report: {err}")
            raise ReportError(f"HTML Report generation failed: {err}")
