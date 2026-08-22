"""Report generation service: JSON, CSV, HTML, and PDF exports for a scan."""
import csv
import html
import io
import json
from datetime import datetime

from reportlab.lib import colors
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
from sqlalchemy.orm import Session

from models.scan import Scan
from models.domain import Domain
from models.finding import Finding

SEVERITY_COLORS_PDF = {
    "critical": colors.HexColor("#dc2626"),
    "high": colors.HexColor("#ea580c"),
    "medium": colors.HexColor("#ca8a04"),
    "low": colors.HexColor("#2563eb"),
    "info": colors.HexColor("#71717a"),
}

# Plain CSS hex strings for the HTML report — kept separate from the
# reportlab Color objects above since reportlab's hexval() doesn't produce
# a valid "#rrggbb" CSS string.
SEVERITY_COLORS_CSS = {
    "critical": "#dc2626",
    "high": "#ea580c",
    "medium": "#ca8a04",
    "low": "#2563eb",
    "info": "#71717a",
}
_DEFAULT_CSS_COLOR = "#71717a"


def _safe_severity(f: Finding) -> str:
    return (f.severity or "unknown").upper()


def _get_scan_context(scan_id: int, db: Session):
    scan = db.query(Scan).filter(Scan.id == scan_id).first()
    if not scan:
        return None, None, []
    domain = db.query(Domain).filter(Domain.id == scan.domain_id).first()
    findings = (
        db.query(Finding).filter(Finding.scan_id == scan_id)
        .order_by(Finding.risk_score.desc().nullslast())
        .all()
    )
    return scan, domain, findings


def generate_json_report(scan_id: int, db: Session) -> bytes:
    scan, domain, findings = _get_scan_context(scan_id, db)
    if not scan:
        return b"{}"

    data = {
        "scan_id": scan.id,
        "domain": domain.name if domain else None,
        "status": scan.status.value,
        "started_at": str(scan.started_at),
        "finished_at": str(scan.finished_at),
        "findings": [
            {
                "cve_id": f.cve_id, "severity": f.severity, "cvss_score": f.cvss_score,
                "epss_score": f.epss_score, "kev_status": f.kev_status, "risk_score": f.risk_score,
                "host": f.host, "port": f.port, "endpoint": f.endpoint,
                "description": f.description, "is_resolved": f.is_resolved,
                "is_false_positive": f.is_false_positive,
            }
            for f in findings
        ],
    }
    return json.dumps(data, indent=2).encode()


def generate_csv_report(scan_id: int, db: Session) -> bytes:
    scan, domain, findings = _get_scan_context(scan_id, db)
    buf = io.StringIO()
    writer = csv.writer(buf)
    writer.writerow([
        "CVE ID", "Severity", "CVSS", "EPSS", "KEV", "Risk Score",
        "Host", "Port", "Endpoint", "Description", "Resolved", "False Positive"
    ])
    for f in findings:
        writer.writerow([
            f.cve_id or "", f.severity or "unknown", f.cvss_score or "", f.epss_score or "",
            "Yes" if f.kev_status else "No", f.risk_score or "",
            f.host, f.port or "", f.endpoint or "", f.description or "",
            "Yes" if f.is_resolved else "No", "Yes" if f.is_false_positive else "No",
        ])
    return buf.getvalue().encode()


def generate_html_report(scan_id: int, db: Session) -> bytes:
    scan, domain, findings = _get_scan_context(scan_id, db)
    if not scan:
        return b"<html><body>Scan not found</body></html>"

    def esc(val) -> str:
        return html.escape(str(val)) if val is not None else "-"

    rows = "".join(
        f"""<tr style="border-bottom:1px solid #27272a;">
            <td style="padding:8px;color:{SEVERITY_COLORS_CSS.get((f.severity or '').lower(), _DEFAULT_CSS_COLOR)};font-weight:600;">{esc(_safe_severity(f))}</td>
            <td style="padding:8px;">{esc(f.cve_id or '-')}</td>
            <td style="padding:8px;">{esc(f.risk_score if f.risk_score is not None else '-')}</td>
            <td style="padding:8px;">{esc(f.host)}</td>
            <td style="padding:8px;">{esc(f.description or '-')}</td>
        </tr>"""
        for f in findings
    )

    html_doc = f"""<!DOCTYPE html>
<html><head><meta charset="utf-8"><title>Scan Report #{scan.id}</title>
<style>
body {{ font-family: -apple-system, sans-serif; background: #0a0a0b; color: #e4e4e7; padding: 40px; }}
h1 {{ color: #22d3ee; }}
table {{ width: 100%; border-collapse: collapse; margin-top: 20px; }}
th {{ text-align: left; padding: 8px; color: #71717a; text-transform: uppercase; font-size: 12px; border-bottom: 1px solid #27272a; }}
</style></head>
<body>
<h1>VULN//PLATFORM — Scan Report</h1>
<p>Domain: <strong>{esc(domain.name if domain else 'N/A')}</strong></p>
<p>Scan ID: #{scan.id} &nbsp;|&nbsp; Status: {esc(scan.status.value)} &nbsp;|&nbsp; Findings: {len(findings)}</p>
<p>Generated: {datetime.utcnow().isoformat()} UTC</p>
<table>
<thead><tr><th>Severity</th><th>CVE</th><th>Risk Score</th><th>Host</th><th>Description</th></tr></thead>
<tbody>{rows}</tbody>
</table>
</body></html>"""
    return html_doc.encode()


def generate_pdf_report(scan_id: int, db: Session) -> bytes:
    scan, domain, findings = _get_scan_context(scan_id, db)
    buf = io.BytesIO()
    doc = SimpleDocTemplate(buf, pagesize=letter, topMargin=0.6 * inch)
    styles = getSampleStyleSheet()
    title_style = ParagraphStyle("Title", parent=styles["Heading1"], textColor=colors.HexColor("#0e7490"))

    elements = [
        Paragraph("VULN//PLATFORM — Vulnerability Scan Report", title_style),
        Spacer(1, 12),
        Paragraph(f"<b>Domain:</b> {html.escape(domain.name) if domain else 'N/A'}", styles["Normal"]),
        Paragraph(f"<b>Scan ID:</b> #{scan.id if scan else '-'}", styles["Normal"]),
        Paragraph(f"<b>Status:</b> {scan.status.value if scan else '-'}", styles["Normal"]),
        Paragraph(f"<b>Total Findings:</b> {len(findings)}", styles["Normal"]),
        Paragraph(f"<b>Generated:</b> {datetime.utcnow().strftime('%Y-%m-%d %H:%M UTC')}", styles["Normal"]),
        Spacer(1, 20),
    ]

    table_data = [["Severity", "CVE ID", "Risk Score", "Host", "Description"]]
    for f in findings:
        table_data.append([
            _safe_severity(f), f.cve_id or "-", str(f.risk_score if f.risk_score is not None else "-"),
            (f.host or "-")[:30], (f.description or "-")[:60],
        ])

    table = Table(table_data, repeatRows=1, colWidths=[70, 90, 65, 110, 155])
    table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#18181b")),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.HexColor("#22d3ee")),
        ("FONTSIZE", (0, 0), (-1, -1), 8),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#27272a")),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#f4f4f5")]),
    ]))
    elements.append(table)

    doc.build(elements)
    return buf.getvalue()