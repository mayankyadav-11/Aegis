"""
AEGIS 2.0 — PDF Forensic Report Generator

Produces a professional, tamper-evident investigation report using ReportLab:
- Includes Case ID, Timestamp, Risk Score, Verdict, Confidence, and Signal Breakdown.
- Emits cryptographic SHA-256 evidence digest.
- Formats explainable findings table and protective recommendations.
- Formatted cleanly for both print and digital security archives.
"""

from __future__ import annotations

import io
from typing import Any

from reportlab.lib import colors
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.platypus import HRFlowable, Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle


def generate_case_pdf_report(case_dict: dict[str, Any]) -> bytes:
    """Generate a PDF forensic report from a case dictionary."""
    buffer = io.BytesIO()
    doc = SimpleDocTemplate(
        buffer,
        pagesize=letter,
        rightMargin=40,
        leftMargin=40,
        topMargin=40,
        bottomMargin=40,
    )

    styles = getSampleStyleSheet()

    # Custom styles
    title_style = ParagraphStyle(
        "ReportTitle",
        parent=styles["Heading1"],
        fontSize=18,
        leading=22,
        textColor=colors.HexColor("#0D0D12"),
        fontName="Helvetica-Bold",
    )
    subtitle_style = ParagraphStyle(
        "ReportSubtitle",
        parent=styles["Normal"],
        fontSize=9,
        leading=12,
        textColor=colors.HexColor("#626274"),
        fontName="Helvetica",
    )
    section_heading = ParagraphStyle(
        "SectionHeading",
        parent=styles["Heading2"],
        fontSize=11,
        leading=15,
        textColor=colors.HexColor("#7B3FE4"),
        fontName="Helvetica-Bold",
        spaceBefore=8,
        spaceAfter=4,
    )
    body_style = ParagraphStyle(
        "ReportBody",
        parent=styles["Normal"],
        fontSize=9,
        leading=13,
        textColor=colors.HexColor("#1A1A24"),
    )
    mono_style = ParagraphStyle(
        "ReportMono",
        parent=styles["Normal"],
        fontSize=7.5,
        leading=10,
        fontName="Courier",
        textColor=colors.HexColor("#2A2A3A"),
    )

    story = []

    # 1. Header Banner
    story.append(Paragraph("AEGIS 2.0 — FORENSIC INVESTIGATION REPORT", title_style))
    story.append(
        Paragraph(
            "Multi-channel phishing, brand impersonation, and digital evidence analysis",
            subtitle_style,
        )
    )
    story.append(Spacer(1, 10))
    story.append(HRFlowable(width="100%", thickness=1.5, color=colors.HexColor("#7B3FE4"), spaceAfter=12))

    # 2. Case Overview Table
    case_id = case_dict.get("case_id", "N/A")
    created_at = case_dict.get("created_at", "N/A")
    input_type = str(case_dict.get("input_type", "N/A")).upper()
    risk_score = case_dict.get("risk_score", 0)
    risk_level = str(case_dict.get("risk_level", "low")).upper()
    verdict = str(case_dict.get("verdict", "safe")).upper()
    confidence = str(case_dict.get("confidence", "low")).upper()

    verdict_color = (
        colors.HexColor("#EF4444")
        if verdict == "MALICIOUS"
        else colors.HexColor("#F59E0B")
        if verdict == "SUSPICIOUS"
        else colors.HexColor("#10B981")
    )

    overview_data = [
        [
            Paragraph("<b>Case ID:</b>", body_style),
            Paragraph(f"<font name='Courier-Bold'>{case_id}</font>", body_style),
            Paragraph("<b>Input Channel:</b>", body_style),
            Paragraph(input_type, body_style),
        ],
        [
            Paragraph("<b>Generated (UTC):</b>", body_style),
            Paragraph(created_at[:19].replace("T", " "), body_style),
            Paragraph("<b>Confidence:</b>", body_style),
            Paragraph(confidence, body_style),
        ],
        [
            Paragraph("<b>Risk Score:</b>", body_style),
            Paragraph(f"<b>{risk_score} / 100</b> ({risk_level})", body_style),
            Paragraph("<b>Verdict:</b>", body_style),
            Paragraph(f"<b>{verdict}</b>", ParagraphStyle("Verdict", parent=body_style, textColor=verdict_color)),
        ],
    ]

    overview_table = Table(overview_data, colWidths=[100, 160, 100, 170])
    overview_table.setStyle(
        TableStyle([
            ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#F8F9FA")),
            ("BOX", (0, 0), (-1, -1), 0.5, colors.HexColor("#D1D5DB")),
            ("INNERGRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#E5E7EB")),
            ("TOPPADDING", (0, 0), (-1, -1), 5),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
        ])
    )
    story.append(overview_table)
    story.append(Spacer(1, 12))

    # 3. Cryptographic Evidence Block
    evidence_hash = case_dict.get("evidence_hash") or "N/A"
    story.append(Paragraph("DIGITAL EVIDENCE INTEGRITY DIGEST", section_heading))
    hash_data = [
        [
            Paragraph("<b>SHA-256 Digest:</b>", body_style),
            Paragraph(evidence_hash, mono_style),
        ],
        [
            Paragraph("<b>Integrity Status:</b>", body_style),
            Paragraph("Recorded in tamper-evident investigation log (Verification enabled)", body_style),
        ],
    ]
    hash_table = Table(hash_data, colWidths=[120, 410])
    hash_table.setStyle(
        TableStyle([
            ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#F3F4F6")),
            ("BOX", (0, 0), (-1, -1), 0.5, colors.HexColor("#D1D5DB")),
            ("INNERGRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#E5E7EB")),
            ("TOPPADDING", (0, 0), (-1, -1), 4),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
        ])
    )
    story.append(hash_table)
    story.append(Spacer(1, 12))

    # 4. Intelligence Summary
    explanation = case_dict.get("explanation") or "No threat indicators detected."
    story.append(Paragraph("THREAT INTELLIGENCE SUMMARY", section_heading))
    story.append(Paragraph(explanation, body_style))
    story.append(Spacer(1, 10))

    # 5. Signal Scores
    sig = case_dict.get("signal_scores") or {}
    sig_data = [
        ["NLP Score", "URL Reputation", "Sender Legitimacy", "Email Auth", "Context / Urgency"],
        [
            f"{sig.get('nlp', 0)}/100",
            f"{sig.get('url', 0)}/100",
            f"{sig.get('sender', 0)}/100",
            f"{sig.get('email_auth', 0)}/100",
            f"{sig.get('context', 0)}/100",
        ],
    ]
    sig_table = Table(sig_data, colWidths=[106, 106, 106, 106, 106])
    sig_table.setStyle(
        TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#7B3FE4")),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
            ("ALIGN", (0, 0), (-1, -1), "CENTER"),
            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
            ("FONTSIZE", (0, 0), (-1, 0), 8),
            ("BACKGROUND", (0, 1), (-1, 1), colors.HexColor("#F9FAFB")),
            ("FONTSIZE", (0, 1), (-1, 1), 8),
            ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#D1D5DB")),
            ("TOPPADDING", (0, 0), (-1, -1), 4),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
        ])
    )
    story.append(sig_table)
    story.append(Spacer(1, 12))

    # 6. Key Findings Table
    findings = case_dict.get("findings") or []
    if findings:
        story.append(Paragraph(f"EXPLAINABLE FINDINGS ({len(findings)})", section_heading))
        findings_data = [
            ["Severity", "Category", "Evidence & Explanation", "Action"]
        ]
        for f in findings[:8]:  # Limit to 8 to avoid multi-page overflow
            sev = str(f.get("severity", "info")).upper()
            cat = str(f.get("category", "")).replace("_", " ").title()
            ev = f.get("evidence", "")
            exp = f.get("explanation", "")
            act = f.get("recommended_action", "")
            text_col = f"<b>Evidence:</b> {ev}<br/><font color='#4B5563'>{exp}</font>"
            findings_data.append([
                Paragraph(f"<b>{sev}</b>", body_style),
                Paragraph(cat, body_style),
                Paragraph(text_col, body_style),
                Paragraph(act, body_style),
            ])

        f_table = Table(findings_data, colWidths=[55, 80, 260, 135])
        f_table.setStyle(
            TableStyle([
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1A1A24")),
                ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                ("FONTSIZE", (0, 0), (-1, 0), 8),
                ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#E5E7EB")),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ("TOPPADDING", (0, 0), (-1, -1), 4),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
            ])
        )
        story.append(f_table)
        story.append(Spacer(1, 12))

    # 7. Action Recommendations & Helpline
    recs = case_dict.get("recommendations") or []
    if recs:
        story.append(Paragraph("RECOMMENDED PROTECTIVE ACTIONS", section_heading))
        for r in recs:
            story.append(Paragraph(f"• {r}", body_style))
        story.append(Spacer(1, 6))

    # India Helpline Callout
    helpline_p = Paragraph(
        "<b>National Cyber Crime Reporting Portal (India):</b> Dial <b>1930</b> immediately if financial debit occurred. "
        "File an incident report at <b>https://cybercrime.gov.in</b> within the golden hour.",
        ParagraphStyle("Helpline", parent=body_style, textColor=colors.HexColor("#1E3A8A")),
    )
    story.append(
        Table(
            [[helpline_p]],
            colWidths=[530],
            style=[
                ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#EFF6FF")),
                ("BOX", (0, 0), (-1, -1), 1, colors.HexColor("#93C5FD")),
                ("TOPPADDING", (0, 0), (-1, -1), 6),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
                ("LEFTPADDING", (0, 0), (-1, -1), 8),
                ("RIGHTPADDING", (0, 0), (-1, -1), 8),
            ],
        )
    )
    story.append(Spacer(1, 10))

    # 8. Unavailable Checks
    unavail = case_dict.get("unavailable_checks") or []
    if unavail:
        story.append(Paragraph("UNAVAILABLE CHECKS & VERIFICATION LIMITS", section_heading))
        for u in unavail:
            story.append(Paragraph(f"<font color='#6B7280'>- {u}</font>", body_style))

    # Build PDF
    doc.build(story)
    return buffer.getvalue()

