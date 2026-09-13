"""PDF Forensic Report Generator using ReportLab Platypus engine for Phase 2 data."""

import logging
from pathlib import Path

from reportlab.lib import colors
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.platypus import HRFlowable, Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle

from ip_sentinel.core.exceptions import ReportError
from ip_sentinel.models.report_model import ReportData
from ip_sentinel.reports.base import BaseReportGenerator

logger = logging.getLogger("ip_sentinel.reports.pdf")

MANDATORY_DISCLAIMER_TEXT = (
    "Network intelligence and geolocation are informational and may be approximate or incomplete. "
    "They should be correlated with WAF, application, CDN, firewall, and other security telemetry before making enforcement decisions."
)


class PDFReportGenerator(BaseReportGenerator):
    """Generates standalone PDF forensic investigation reports using ReportLab Platypus."""

    def generate_report(self, data: ReportData, output_path: Path) -> Path:
        """Render investigation data into a formatted PDF file."""
        logger.info(f"Generating Phase 2 PDF report for target IP {data.result.target_ip} at {output_path}")

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

            title_style = ParagraphStyle(
                "DocTitle",
                parent=styles["Heading1"],
                fontName="Helvetica-Bold",
                fontSize=18,
                textColor=colors.HexColor("#00E5FF"),
                spaceAfter=4,
            )

            subtitle_style = ParagraphStyle(
                "DocSubtitle",
                parent=styles["Normal"],
                fontName="Helvetica",
                fontSize=9,
                textColor=colors.HexColor("#64748B"),
                spaceAfter=8,
            )

            section_style = ParagraphStyle(
                "SectionHeading",
                parent=styles["Heading2"],
                fontName="Helvetica-Bold",
                fontSize=12,
                textColor=colors.HexColor("#00E5FF"),
                spaceBefore=12,
                spaceAfter=6,
            )

            cell_style = ParagraphStyle(
                "TableCell",
                parent=styles["Normal"],
                fontName="Helvetica",
                fontSize=8.5,
                textColor=colors.HexColor("#1E293B"),
            )

            bold_cell_style = ParagraphStyle(
                "TableBoldCell",
                parent=cell_style,
                fontName="Helvetica-Bold",
            )

            disclaimer_style = ParagraphStyle(
                "DisclaimerStyle",
                parent=styles["Normal"],
                fontName="Helvetica-Oblique",
                fontSize=8,
                textColor=colors.HexColor("#475569"),
                spaceAfter=10,
            )

            story = []

            # 1. Mock Data Banner Warning
            if data.result.is_mock:
                mock_style = ParagraphStyle(
                    "MockBanner",
                    parent=styles["Normal"],
                    fontName="Helvetica-Bold",
                    fontSize=10,
                    textColor=colors.HexColor("#FFFFFF"),
                    alignment=1,
                )
                mock_table = Table(
                    [[Paragraph("DEMO / MOCK DATA — NOT REAL THREAT INTELLIGENCE", mock_style)]],
                    colWidths=[540],
                )
                mock_table.setStyle(
                    TableStyle([
                        ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#DC2626")),
                        ("PADDING", (0, 0), (-1, -1), 6),
                        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
                    ])
                )
                story.append(mock_table)
                story.append(Spacer(1, 8))

            # 2. Header Title & Subtitle
            story.append(Paragraph(data.metadata.title, title_style))
            story.append(
                Paragraph(
                    f"Target IP: <b>{data.result.target_ip}</b> | Investigation ID: <b>{data.result.investigation_id}</b> | Timestamp: {data.result.timestamp}",
                    subtitle_style,
                )
            )
            story.append(HRFlowable(width="100%", thickness=1, color=colors.HexColor("#CBD5E1"), spaceAfter=10))

            # 3. Security Disclaimer Box
            disc_p = Paragraph(f"<b>Security Disclaimer:</b> {MANDATORY_DISCLAIMER_TEXT}", disclaimer_style)
            disc_table = Table([[disc_p]], colWidths=[540])
            disc_table.setStyle(
                TableStyle([
                    ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#F1F5F9")),
                    ("BOX", (0, 0), (-1, -1), 0.5, colors.HexColor("#94A3B8")),
                    ("PADDING", (0, 0), (-1, -1), 6),
                ])
            )
            story.append(disc_table)
            story.append(Spacer(1, 10))

            # 4. Overall Threat Score Card
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

            score_style = ParagraphStyle("ScoreBox", fontName="Helvetica-Bold", fontSize=13, textColor=txt_color)
            score_detail = ParagraphStyle("ScoreDetail", fontName="Helvetica", fontSize=9, textColor=txt_color)

            score_table_data = [
                [
                    Paragraph(f"OVERALL THREAT: {level_str}", score_style),
                    Paragraph(f"RISK SCORE: {score_num} / 100", score_style),
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
                    ("PADDING", (0, 0), (-1, -1), 8),
                    ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
                ])
            )
            story.append(score_table)
            story.append(Spacer(1, 10))

            # Section 1: IP Information
            story.append(Paragraph("1. IP Information", section_style))
            ip_data = [
                [Paragraph("Property", bold_cell_style), Paragraph("Value", bold_cell_style)],
                [Paragraph("Target IP Address", cell_style), Paragraph(data.result.target_ip, cell_style)],
                [Paragraph("IP Version", cell_style), Paragraph("IPv6" if ":" in data.result.target_ip else "IPv4", cell_style)],
                [Paragraph("Category", cell_style), Paragraph("Private (RFC 1918)" if data.result.is_private_ip else "Public Address", cell_style)],
                [Paragraph("Loopback IP", cell_style), Paragraph("Yes" if data.result.is_loopback_ip else "No", cell_style)],
            ]
            t_ip = Table(ip_data, colWidths=[180, 360])
            t_ip.setStyle(self._default_table_style())
            story.append(t_ip)
            story.append(Spacer(1, 10))

            # Section 2: Network / ASN
            story.append(Paragraph("2. Network & Autonomous System (ASN)", section_style))
            asn_val = f"AS{data.result.asn_data.asn}" if data.result.asn_data.asn is not None else "UNAVAILABLE"
            net_data = [
                [Paragraph("Property", bold_cell_style), Paragraph("Value", bold_cell_style)],
                [Paragraph("ASN", cell_style), Paragraph(asn_val, cell_style)],
                [Paragraph("Organization", cell_style), Paragraph(data.result.asn_data.asn_org or data.result.geoip.asn_org or "UNAVAILABLE", cell_style)],
                [Paragraph("Network Prefix / CIDR", cell_style), Paragraph(data.result.rdap.cidr or data.result.asn_data.network_prefix or "UNAVAILABLE", cell_style)],
                [Paragraph("Registry / RIR", cell_style), Paragraph(data.result.rdap.registry or data.result.asn_data.registry or "UNAVAILABLE", cell_style)],
                [Paragraph("Status", cell_style), Paragraph(data.result.asn_status.value, cell_style)],
            ]
            t_net = Table(net_data, colWidths=[180, 360])
            t_net.setStyle(self._default_table_style())
            story.append(t_net)
            story.append(Spacer(1, 10))

            # Section 3: RDAP Details
            story.append(Paragraph("3. Registration Data Access Protocol (RDAP)", section_style))
            rdap_data = [
                [Paragraph("Property", bold_cell_style), Paragraph("Value", bold_cell_style)],
                [Paragraph("Network Name", cell_style), Paragraph(data.result.rdap.network_name or "UNAVAILABLE", cell_style)],
                [Paragraph("Address Range", cell_style), Paragraph(f"{data.result.rdap.start_address or 'N/A'} - {data.result.rdap.end_address or 'N/A'}", cell_style)],
                [Paragraph("Organization", cell_style), Paragraph(data.result.rdap.organization or "UNAVAILABLE", cell_style)],
                [Paragraph("Abuse Contact", cell_style), Paragraph(data.result.rdap.abuse_contact or "UNAVAILABLE", cell_style)],
                [Paragraph("Status", cell_style), Paragraph(data.result.rdap_status.value, cell_style)],
            ]
            t_rdap = Table(rdap_data, colWidths=[180, 360])
            t_rdap.setStyle(self._default_table_style())
            story.append(t_rdap)
            story.append(Spacer(1, 10))

            # Section 4: Geolocation
            story.append(Paragraph("4. Network Geolocation", section_style))
            geo_data = [
                [Paragraph("Property", bold_cell_style), Paragraph("Value", bold_cell_style)],
                [Paragraph("Country", cell_style), Paragraph(f"{data.result.geoip.country_name or 'UNAVAILABLE'} ({data.result.geoip.country_code or 'N/A'})", cell_style)],
                [Paragraph("Region / State", cell_style), Paragraph(data.result.geoip.region or "UNAVAILABLE", cell_style)],
                [Paragraph("City", cell_style), Paragraph(data.result.geoip.city or "UNAVAILABLE", cell_style)],
                [Paragraph("Timezone", cell_style), Paragraph(data.result.geoip.timezone or "UNAVAILABLE", cell_style)],
                [Paragraph("Status", cell_style), Paragraph(data.result.geoip_status.value, cell_style)],
            ]
            t_geo = Table(geo_data, colWidths=[180, 360])
            t_geo.setStyle(self._default_table_style())
            story.append(t_geo)
            story.append(Paragraph(f"Note: {data.result.geoip.disclaimer}", disclaimer_style))
            story.append(Spacer(1, 10))

            # Section 5: DNS Telemetry
            story.append(Paragraph("5. DNS Resolution Telemetry", section_style))
            dns_data = [
                [Paragraph("Record Type", bold_cell_style), Paragraph("Resolved Values", bold_cell_style)],
                [Paragraph("Reverse Hostname (PTR)", cell_style), Paragraph(data.result.dns.hostname or (", ".join(data.result.dns.ptr_records) if data.result.dns.ptr_records else "UNAVAILABLE"), cell_style)],
                [Paragraph("A Records", cell_style), Paragraph(", ".join(data.result.dns.a_records) if data.result.dns.a_records else "UNAVAILABLE", cell_style)],
                [Paragraph("AAAA Records", cell_style), Paragraph(", ".join(data.result.dns.aaaa_records) if data.result.dns.aaaa_records else "UNAVAILABLE", cell_style)],
                [Paragraph("MX Records", cell_style), Paragraph(", ".join(data.result.dns.mx_records) if data.result.dns.mx_records else "UNAVAILABLE", cell_style)],
                [Paragraph("NS Records", cell_style), Paragraph(", ".join(data.result.dns.ns_records) if data.result.dns.ns_records else "UNAVAILABLE", cell_style)],
                [Paragraph("TXT Records", cell_style), Paragraph(", ".join(data.result.dns.txt_records) if data.result.dns.txt_records else "UNAVAILABLE", cell_style)],
                [Paragraph("CNAME Records", cell_style), Paragraph(", ".join(data.result.dns.cname_records) if data.result.dns.cname_records else "UNAVAILABLE", cell_style)],
                [Paragraph("Status", cell_style), Paragraph(data.result.dns_status.value, cell_style)],
            ]
            t_dns = Table(dns_data, colWidths=[180, 360])
            t_dns.setStyle(self._default_table_style())
            story.append(t_dns)
            story.append(Spacer(1, 10))

            # Section 6: Data Source Status Summary
            story.append(Paragraph("6. Data Source Status Summary", section_style))
            status_data = [[Paragraph("Subsystem", bold_cell_style), Paragraph("Status", bold_cell_style), Paragraph("Diagnostics", bold_cell_style)]]
            status_data.append([Paragraph("IP Classification", cell_style), Paragraph("AVAILABLE", cell_style), Paragraph("Normalized IPv4/IPv6 classification", cell_style)])
            status_data.append([Paragraph("RDAP Registration", cell_style), Paragraph(data.result.rdap_status.value, cell_style), Paragraph(data.result.rdap.error_message or "OK", cell_style)])
            status_data.append([Paragraph("ASN Telemetry", cell_style), Paragraph(data.result.asn_status.value, cell_style), Paragraph(data.result.asn_data.error_message or "OK", cell_style)])
            status_data.append([Paragraph("GeoIP Geolocation", cell_style), Paragraph(data.result.geoip_status.value, cell_style), Paragraph(data.result.geoip.error_message or "OK", cell_style)])
            status_data.append([Paragraph("DNS Resolution", cell_style), Paragraph(data.result.dns_status.value, cell_style), Paragraph(data.result.dns.error_message or "OK", cell_style)])

            for name, prov in data.result.provider_results.items():
                status_data.append([Paragraph(f"Provider: {name}", cell_style), Paragraph(prov.status.value, cell_style), Paragraph(prov.error_message or "OK", cell_style)])

            t_stat = Table(status_data, colWidths=[160, 120, 260])
            t_stat.setStyle(self._default_table_style())
            story.append(t_stat)
            story.append(Spacer(1, 12))

            story.append(HRFlowable(width="100%", thickness=0.5, color=colors.HexColor("#94A3B8"), spaceAfter=8))
            footer_text = f"Generated by {data.metadata.author} | {data.metadata.organization} | IP Sentinel AI v{data.metadata.app_version}"
            story.append(Paragraph(footer_text, subtitle_style))

            doc.build(story)
            logger.info(f"Successfully generated Phase 2 PDF report at {output_path}")
            return output_path
        except Exception as err:
            logger.error(f"Failed to generate PDF report: {err}")
            raise ReportError(f"PDF Report generation failed: {err}")

    def _default_table_style(self) -> TableStyle:
        return TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#F1F5F9")),
            ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#CBD5E1")),
            ("PADDING", (0, 0), (-1, -1), 5),
            ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ])
