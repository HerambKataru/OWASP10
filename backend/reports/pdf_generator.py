import os
from datetime import datetime
from typing import Dict, Any, List
from reportlab.lib.pagesizes import letter
from reportlab.lib import colors
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak, KeepTogether, HRFlowable
)
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch

SEVERITY_COLORS = {
    "Critical": colors.HexColor("#DC2626"),
    "High": colors.HexColor("#EA580C"),
    "Medium": colors.HexColor("#D97706"),
    "Low": colors.HexColor("#2563EB"),
    "Informational": colors.HexColor("#4B5563")
}

def generate_pdf_report(scan_data: Dict[str, Any], findings: List[Dict[str, Any]], output_filepath: str) -> str:
    doc = SimpleDocTemplate(
        output_filepath,
        pagesize=letter,
        rightMargin=40,
        leftMargin=40,
        topMargin=40,
        bottomMargin=40
    )

    styles = getSampleStyleSheet()
    
    # Custom Styles
    primary_color = colors.HexColor("#0F172A")
    accent_color = colors.HexColor("#0284C7")
    text_dark = colors.HexColor("#1E293B")
    bg_dark = colors.HexColor("#0B0F17")

    title_style = ParagraphStyle(
        'CoverTitle',
        parent=styles['Normal'],
        fontName='Helvetica-Bold',
        fontSize=28,
        leading=34,
        textColor=colors.HexColor("#0284C7"),
        alignment=0
    )
    subtitle_style = ParagraphStyle(
        'CoverSubtitle',
        parent=styles['Normal'],
        fontName='Helvetica',
        fontSize=14,
        leading=18,
        textColor=colors.HexColor("#64748B"),
        alignment=0
    )
    h1_style = ParagraphStyle(
        'Heading1_Custom',
        parent=styles['Heading1'],
        fontName='Helvetica-Bold',
        fontSize=18,
        leading=22,
        textColor=colors.HexColor("#0F172A"),
        spaceBefore=14,
        spaceAfter=8
    )
    h2_style = ParagraphStyle(
        'Heading2_Custom',
        parent=styles['Heading2'],
        fontName='Helvetica-Bold',
        fontSize=13,
        leading=16,
        textColor=colors.HexColor("#0284C7"),
        spaceBefore=10,
        spaceAfter=4
    )
    body_style = ParagraphStyle(
        'Body_Custom',
        parent=styles['Normal'],
        fontName='Helvetica',
        fontSize=9.5,
        leading=13,
        textColor=text_dark
    )
    code_style = ParagraphStyle(
        'Code_Custom',
        parent=styles['Normal'],
        fontName='Courier',
        fontSize=8.5,
        leading=11,
        textColor=colors.HexColor("#0F172A")
    )

    story = []

    target = scan_data.get("target", "https://localhost:3000")
    risk_score = scan_data.get("risk_score", 0.0)
    created_at = scan_data.get("created_at", datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S"))

    # ==================== 1. COVER PAGE ====================
    story.append(Spacer(1, 40))
    story.append(Paragraph("SENTINELX", title_style))
    story.append(Paragraph("AI-Powered OWASP Top 10 Security Assessment Report", subtitle_style))
    story.append(Spacer(1, 15))
    story.append(HRFlowable(width="100%", thickness=3, color=accent_color, spaceAfter=30))
    
    meta_table_data = [
        [Paragraph("<b>Target Evaluated:</b>", body_style), Paragraph(str(target), body_style)],
        [Paragraph("<b>Assessment Date:</b>", body_style), Paragraph(str(created_at), body_style)],
        [Paragraph("<b>Overall Risk Score:</b>", body_style), Paragraph(f"<b>{risk_score} / 100</b>", body_style)],
        [Paragraph("<b>Total Findings:</b>", body_style), Paragraph(str(len(findings)), body_style)],
        [Paragraph("<b>Assessment Type:</b>", body_style), Paragraph(f"Automated Web VAPT & SAST ({scan_data.get('scan_type', 'Website')})", body_style)],
        [Paragraph("<b>Classification:</b>", body_style), Paragraph("<font color='#DC2626'><b>CONFIDENTIAL - SECURITY ASSESSMENT</b></font>", body_style)]
    ]
    meta_table = Table(meta_table_data, colWidths=[150, 380])
    meta_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, -1), colors.HexColor("#F8FAFC")),
        ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor("#E2E8F0")),
        ('PADDING', (0, 0), (-1, -1), 8),
    ]))
    story.append(meta_table)

    story.append(Spacer(1, 120))
    story.append(Paragraph("<b>Confidentiality Notice:</b> This document contains proprietary and confidential vulnerability details obtained during authorized educational and diagnostic penetration testing. Unauthorized distribution is prohibited.", ParagraphStyle('Notice', parent=body_style, fontSize=8, textColor=colors.HexColor("#94A3B8"))))
    story.append(PageBreak())

    # ==================== 2. EXECUTIVE SUMMARY ====================
    story.append(Paragraph("1. Executive Summary", h1_style))
    story.append(HRFlowable(width="100%", thickness=1, color=accent_color, spaceAfter=10))
    story.append(Paragraph(
        f"A comprehensive automated security assessment was performed against <b>{target}</b> using the SentinelX VAPT Workstation. "
        f"The system evaluated the target's attack surface against the OWASP Top 10 Web Application Security standard, "
        f"identifying a total of <b>{len(findings)} findings</b> resulting in a consolidated Risk Score of <b>{risk_score}/100</b>.",
        body_style
    ))
    story.append(Spacer(1, 10))

    # Severity Breakdown Table
    crit_c = sum(1 for f in findings if f.get("severity") == "Critical")
    high_c = sum(1 for f in findings if f.get("severity") == "High")
    med_c = sum(1 for f in findings if f.get("severity") == "Medium")
    low_c = sum(1 for f in findings if f.get("severity") == "Low")
    info_c = sum(1 for f in findings if f.get("severity") in ["Informational", "Info"])

    summary_table_data = [
        ["Severity Level", "Finding Count", "Impact Description"],
        ["Critical", str(crit_c), "Immediate threat of total system compromise or data breach"],
        ["High", str(high_c), "High probability of unauthorized access, injection, or data loss"],
        ["Medium", str(med_c), "Significant configuration or access control weakness"],
        ["Low", str(low_c), "Minor information leakage or suboptimal security practices"],
        ["Informational", str(info_c), "Reconnaissance data and contextual service metrics"]
    ]
    summary_table = Table(summary_table_data, colWidths=[100, 90, 340])
    summary_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor("#0F172A")),
        ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
        ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
        ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor("#CBD5E1")),
        ('PADDING', (0, 0), (-1, -1), 5),
        ('TEXTCOLOR', (0, 1), (0, 1), colors.HexColor("#DC2626")),
        ('TEXTCOLOR', (0, 2), (0, 2), colors.HexColor("#EA580C")),
        ('TEXTCOLOR', (0, 3), (0, 3), colors.HexColor("#D97706")),
        ('TEXTCOLOR', (0, 4), (0, 4), colors.HexColor("#2563EB")),
    ]))
    story.append(summary_table)
    story.append(Spacer(1, 15))

    # ==================== 3. SCOPE ====================
    story.append(Paragraph("2. Assessment Scope", h1_style))
    story.append(HRFlowable(width="100%", thickness=1, color=accent_color, spaceAfter=8))
    scope_text = f"<b>Primary Target:</b> {target}<br/><b>Scan Mode:</b> {scan_data.get('scan_type', 'Website')}<br/><b>Crawler Depth:</b> {scan_data.get('crawl_depth', 2)}<br/><b>Execution Mode:</b> Local Non-Destructive Vulnerability Assessment"
    story.append(Paragraph(scope_text, body_style))
    story.append(Spacer(1, 15))

    # ==================== 4. METHODOLOGY ====================
    story.append(Paragraph("3. Testing Methodology", h1_style))
    story.append(HRFlowable(width="100%", thickness=1, color=accent_color, spaceAfter=8))
    method_text = (
        "SentinelX utilizes a multi-phase testing framework aligned with the OWASP Testing Guide (OTG v4) and NIST SP 800-115:<br/>"
        "1. <b>Passive & Active Reconnaissance:</b> Crawling domain boundaries, extracting input vectors, fingerprinting stacks.<br/>"
        "2. <b>Vulnerability Verification:</b> Heuristic probing of SQL injection, XSS reflection & DOM sinks, IDOR access bounds, and cookie flags.<br/>"
        "3. <b>Static Source Code Analysis (SAST):</b> In-depth AST and pattern scanning for hardcoded secrets and dangerous sinks.<br/>"
        "4. <b>Threat Intelligence Correlation:</b> Cross-referencing domains and IPs against VirusTotal, AbuseIPDB, and NIST CVE databases."
    )
    story.append(Paragraph(method_text, body_style))
    story.append(Spacer(1, 15))

    # ==================== 5. RECON RESULTS ====================
    story.append(Paragraph("4. Reconnaissance Results", h1_style))
    story.append(HRFlowable(width="100%", thickness=1, color=accent_color, spaceAfter=8))
    recon_summary = f"<b>Total Discovered Endpoints:</b> {scan_data.get('endpoints_count', 0)}<br/><b>Discovered Form Inputs:</b> {scan_data.get('forms_count', 0)}"
    story.append(Paragraph(recon_summary, body_style))
    story.append(Spacer(1, 15))

    # ==================== 6. TECHNOLOGIES ====================
    story.append(Paragraph("5. Technology Stack Fingerprint", h1_style))
    story.append(HRFlowable(width="100%", thickness=1, color=accent_color, spaceAfter=8))
    techs = scan_data.get("technologies", [])
    tech_str = ", ".join(techs) if techs else "Generic HTTP Web Server / Standard Web Application"
    story.append(Paragraph(f"<b>Detected Technologies:</b> {tech_str}", body_style))
    story.append(Spacer(1, 15))

    # ==================== 7. THREAT INTELLIGENCE ====================
    story.append(Paragraph("6. Threat Intelligence Correlation", h1_style))
    story.append(HRFlowable(width="100%", thickness=1, color=accent_color, spaceAfter=8))
    intel_text = (
        "Threat intelligence enrichment queries VirusTotal, AbuseIPDB, and Shodan to identify historical domain reputation, "
        "malicious activity reports, and exposed ports."
    )
    story.append(Paragraph(intel_text, body_style))
    story.append(Spacer(1, 15))

    # ==================== 8. OWASP FINDINGS ====================
    story.append(PageBreak())
    story.append(Paragraph("7. Detailed OWASP Top 10 Findings", h1_style))
    story.append(HRFlowable(width="100%", thickness=1, color=accent_color, spaceAfter=10))

    if not findings:
        story.append(Paragraph("No significant vulnerabilities were identified during this assessment cycle.", body_style))
    else:
        for idx, f in enumerate(findings, start=1):
            sev = f.get("severity", "Medium")
            sev_color = SEVERITY_COLORS.get(sev, colors.gray)

            f_box = [
                [Paragraph(f"<b>Finding #{idx}: {f.get('title')}</b>", ParagraphStyle('FTitle', parent=body_style, fontName='Helvetica-Bold', textColor=colors.white)),
                 Paragraph(f"<b>[{sev.upper()}] - CVSS {f.get('cvss_score', '5.0')}</b>", ParagraphStyle('FSev', parent=body_style, alignment=2, textColor=colors.white))],
                [Paragraph(f"<b>OWASP Category:</b> {f.get('owasp_category', 'OWASP Top 10')}<br/>"
                           f"<b>Target Endpoint:</b> {f.get('endpoint', 'N/A')}<br/>"
                           f"<b>Vulnerable Parameter:</b> {f.get('parameter', 'N/A')}<br/>"
                           f"<b>Description:</b> {f.get('description', '')}<br/>"
                           f"<b>Payload Used:</b> <font name='Courier'>{f.get('payload', 'N/A')}</font><br/>"
                           f"<b>Evidence:</b> {f.get('evidence', 'N/A')}<br/>"
                           f"<b>Remediation:</b> {f.get('remediation', '')}", body_style), ""]
            ]
            f_table = Table(f_box, colWidths=[400, 130])
            f_table.setStyle(TableStyle([
                ('SPAN', (0, 1), (1, 1)),
                ('BACKGROUND', (0, 0), (-1, 0), sev_color),
                ('BACKGROUND', (0, 1), (-1, 1), colors.HexColor("#F8FAFC")),
                ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor("#CBD5E1")),
                ('PADDING', (0, 0), (-1, -1), 6),
            ]))
            story.append(KeepTogether([f_table, Spacer(1, 12)]))

    # ==================== 9-14. PAYLOADS, EVIDENCE, REMEDIATION, APPENDIX ====================
    story.append(PageBreak())
    story.append(Paragraph("8. Payloads & HTTP Evidence Summary", h1_style))
    story.append(HRFlowable(width="100%", thickness=1, color=accent_color, spaceAfter=8))
    story.append(Paragraph("All active probing was performed using standardized non-destructive payload sets designed to reveal reflection, syntax errors, and authorization anomalies without modifying persistent records.", body_style))
    story.append(Spacer(1, 15))

    story.append(Paragraph("9. CVE & CWE Mapping", h1_style))
    story.append(HRFlowable(width="100%", thickness=1, color=accent_color, spaceAfter=8))
    story.append(Paragraph("Vulnerabilities are mapped to standard Common Weakness Enumeration (CWE) and Common Vulnerabilities and Exposures (CVE) definitions for enterprise compliance reporting.", body_style))
    story.append(Spacer(1, 15))

    story.append(Paragraph("10. Remediation Roadmap & Best Practices", h1_style))
    story.append(HRFlowable(width="100%", thickness=1, color=accent_color, spaceAfter=8))
    remediation_guide = (
        "1. <b>Prioritize Critical/High Vulnerabilities:</b> Address SQL injection via parameterized queries and implement object-level authorization checks.<br/>"
        "2. <b>Harden Security Headers:</b> Implement Content-Security-Policy (CSP), Strict-Transport-Security (HSTS), and anti-clickjacking headers.<br/>"
        "3. <b>Secure Session Storage:</b> Ensure all session cookies have HttpOnly, Secure, and SameSite=Lax flags enabled.<br/>"
        "4. <b>Secrets Hygiene:</b> Remove any exposed API keys from frontend bundles and move them to secure backend vaults."
    )
    story.append(Paragraph(remediation_guide, body_style))
    story.append(Spacer(1, 15))

    story.append(Paragraph("11. Appendix & Assessment Tool Details", h1_style))
    story.append(HRFlowable(width="100%", thickness=1, color=accent_color, spaceAfter=8))
    story.append(Paragraph(
        "Report generated by <b>SentinelX v1.0</b> — Local AI-Powered OWASP Top 10 VAPT Suite.<br/>"
        "Assessment Engine: Python FastAPI, SQLAlchemy, BeautifulSoup4, ReportLab.<br/>"
        "Standards: OWASP Top 10:2021, NIST SP 800-115, CWE/SANS Top 25.",
        body_style
    ))

    # Build Document
    doc.build(story)
    return output_filepath
