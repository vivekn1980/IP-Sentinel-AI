"""PDF Forensic Report Generator using ReportLab Platypus engine."""

import logging
from pathlib import Path
from typing import List

from reportlab.lib import colors
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.platypus import HRFlowable, Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle

from ip_sentinel.core.exceptions import ReportError
from ip_sentinel.models.report_model import ReportData
from ip_sentinel.reports.base import BaseReportGenerator

logger = logging.getLogger("ip_sentinel.reports.pdf")


class PDFReportGenerator(BaseReportGenerator):
    """Generates standalone PDF forensic investigation reports using ReportLab Platypus."""

    def generate_report(self, data: ReportData, output_path: Path) -> Path:
        """Render investigation data into a formatted PDF file."""
        logger.info(f"Generating PDF report for target IP {data.result.target_ip} at {output_path}")

        try:
            output_path.parent.mkdir(parents=True, exist_ok=True)
            doc = SimpleDocTemplate(
                str(output_path),
                pagesize=letter,
                rightMargin=36,
                leftMargin=36,
                topMargin=36,
                bottomMargin=36,
            )

            styles = getSampleStyleSheet()

            # Custom Dark Cybersecurity PDF Styles
            title_style = ParagraphStyle(
                "DocTitle",
                parent=styles["Heading1"],
                fontName="Helvetica-Bold",
                fontSize=20,
                textColor=colors.HexColor("#00E5FF"),
                spaceAfter=4,
            )

            subtitle_style = ParagraphStyle(
                "DocSubtitle",
                parent=styles["Normal"],
                fontName="Helvetica",
                fontSize=10,
                textColor=colors.HexColor("#64748B"),
                spaceAfter=12,
            )

            section_style = ParagraphStyle(
                "SectionHeading",
                parent=styles["Heading2"],
                fontName="Helvetica-Bold",
                fontSize=13,
                textColor=colors.HexColor("#00E5FF"),
                spaceBefore=14,
                spaceAfter=8,
            )

            cell_style = ParagraphStyle(
                "TableCell",
                parent=styles["Normal"],
                fontName="Helvetica",
                fontSize=9,
                textColor=colors.HexColor("#1E293B"),
            )

            bold_cell_style = ParagraphStyle(
                "TableBoldCell",
                parent=cell_style,
                fontName="Helvetica-Bold",
            )

            story = []

            # 1. Mock Data Banner Warning
            if data.result.is_mock:
                mock_style = ParagraphStyle(
                    "MockBanner",
                    parent=styles["Normal"],
                    fontName="Helvetica-Bold",
                    fontSize=11,
                    textColor=colors.HexColor("#FFFFFF"),
                    alignment=1,  # Centered
                )
                mock_table = Table(
                    [[Paragraph("DEMO / MOCK DATA — NOT REAL THREAT INTELLIGENCE", mock_style)]],
                    colWidths=[540],
                )
                mock_table.setStyle(
                    TableStyle([
                        ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#DC2626")),
                        ("PADDING", (0, 0), (-1, -1), 8),
                        ("ALIGN", (0, 0), (-1, -1), "CENTER"),
                        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
                    ])
                )
                story.append(mock_table)
                story.append(Spacer(1, 12))

            # 2. Header Title
            story.append(Paragraph(data.metadata.title, title_style))
            story.append(
                Paragraph(
                    f"Target IP: <b>{data.result.target_ip}</b> | Investigation ID: <b>{data.result.investigation_id}</b> | Date: {data.result.timestamp}",
                    subtitle_style,
                )
            )
            story.append(HRFlowable(width="100%", thickness=1, color=colors.HexColor("#CBD5E1"), spaceAfter=14))

            # 3. Overall Threat Score Box
            level_str = data.result.overall_threat_score.level.value
            score_num = data.result.overall_threat_score.score

            if level_str == "MALICIOUS":
                bg_color = colors.HexColor("#FCA5A5")
                txt_color = colors.HexColor("#991B1B")
            elif level_str == "SUSPICIOUS":
                bg_color = colors.HexColor("#FDE68A")
                txt_color = colors.HexColor("#92400E")
            else:
                bg_color = colors.HexColor("#A7F3D0")
                txt_color = colors.HexColor("#065F46")

            score_style = ParagraphStyle("ScoreBox", fontName="Helvetica-Bold", fontSize=14, textColor=txt_color)
            score_detail = ParagraphStyle("ScoreDetail", fontName="Helvetica", fontSize=10, textColor=txt_color)

            score_table_data = [
                [
                    Paragraph(f"OVERALL THREAT: {level_str}", score_style),
                    Paragraph(f"SCORE: {score_num} / 100", score_style),
                ],
                [
                    Paragraph(f"Confidence: {data.result.overall_threat_score.confidence}%", score_detail),
                    Paragraph(f"Target: {data.result.target_ip}", score_detail),
                ],
            ]

            score_table = Table(score_table_data, colWidths=[270, 270])
            score_table.setStyle(
                TableStyle([
                    ("BACKGROUND", (0, 0), (-1, -1), bg_color),
                    ("PADDING", (0, 0), (-1, -1), 10),
                    ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
                ])
            )
            story.append(score_table)
            story.append(Spacer(1, 14))

            # 4. Network & Geolocation Overview Table
            story.append(Paragraph("1. Network & Geolocation Overview", section_style))
            net_table_data = [
                [Paragraph("Property", bold_cell_style), Paragraph("Value", bold_cell_style)],
                [Paragraph("IP Address", cell_style), Paragraph(data.result.target_ip, cell_style)],
                [Paragraph("Network Type", cell_style), Paragraph("Private (RFC 1918)" if data.result.is_private_ip else "Public Address", cell_style)],
                [Paragraph("Country / City", cell_style), Paragraph(f"{data.result.geoip.country_name} ({data.result.geoip.country_code}) - {data.result.geoip.city or 'Unknown'}", cell_style)],
                [Paragraph("ASN / Organization", cell_style), Paragraph(f"AS{data.result.geoip.asn} - {data.result.geoip.asn_org}", cell_style)],
                [Paragraph("ISP", cell_style), Paragraph(data.result.geoip.isp or "N/A", cell_style)],
            ]

            net_table = Table(net_table_data, colWidths=[180, 360])
            net_table.setStyle(
                TableStyle([
                    ("BACKGROUND", (0, 0), (1, 0), colors.HexColor("#F1F5F9")),
                    ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#CBD5E1")),
                    ("PADDING", (0, 0), (-1, -1), 6),
                ])
            )
            story.append(net_table)
            story.append(Spacer(1, 12))

            # 5. Reverse DNS Resolution Table
            story.append(Paragraph("2. Reverse DNS Resolution", section_style))
            dns_table_data = [
                [Paragraph("Query", bold_cell_style), Paragraph("Resolved Result", bold_cell_style)],
                [Paragraph("Hostname (PTR)", cell_style), Paragraph(data.result.dns.hostname or "No PTR record resolved", cell_style)],
                [Paragraph("Status", cell_style), Paragraph(data.result.dns.status.value, cell_style)],
            ]
            dns_table = Table(dns_table_data, colWidths=[180, 360])
            dns_table.setStyle(
                TableStyle([
                    ("BACKGROUND", (0, 0), (1, 0), colors.HexColor("#F1F5F9")),
                    ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#CBD5E1")),
                    ("PADDING", (0, 0), (-1, -1), 6),
                ])
            )
            story.append(dns_table)
            story.append(Spacer(1, 12))

            # 6. Structured Evidence Table
            story.append(Paragraph("3. Structured Threat Evidence", section_style))
            if data.result.aggregated_evidence:
                ev_data = [[Paragraph("Severity", bold_cell_style), Paragraph("Category", bold_cell_style), Paragraph("Description", bold_cell_style)]]
                for item in data.result.aggregated_evidence:
                    ev_data.append([
                        Paragraph(item.severity, cell_style),
                        Paragraph(item.category, cell_style),
                        Paragraph(item.description, cell_style),
                    ])
                ev_table = Table(ev_data, colWidths=[80, 140, 320])
                ev_table.setStyle(
                    TableStyle([
                        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#F1F5F9")),
                        ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#CBD5E1")),
                        ("PADDING", (0, 0), (-1, -1), 6),
                    ])
                )
                story.append(ev_table)
            else:
                story.append(Paragraph("No malicious indicators or threat evidence reported.", cell_style))

            story.append(Spacer(1, 14))
            story.append(HRFlowable(width="100%", thickness=0.5, color=colors.HexColor("#94A3B8"), spaceAfter=10))
            footer_text = f"Generated by {data.metadata.author} | {data.metadata.organization} | IP Sentinel AI v{data.metadata.app_version}"
            story.append(Paragraph(footer_text, subtitle_style))

            doc.build(story)
            logger.info(f"Successfully generated PDF report at {output_path}")
            return output_path
        except Exception as err:
            logger.error(f"Failed to generate PDF report: {err}")
            raise ReportError(f"PDF Report generation failed: {err}")
