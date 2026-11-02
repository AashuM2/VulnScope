
import io
from datetime import datetime
from xml.sax.saxutils import escape

from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER, TA_RIGHT
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import mm
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle,
    HRFlowable, PageBreak, KeepTogether
)


def generate_pdf(scan, vulnerabilities):
    buffer = io.BytesIO()
    page_width, page_height = A4

    doc = SimpleDocTemplate(
        buffer,
        pagesize=A4,
        rightMargin=17 * mm,
        leftMargin=17 * mm,
        topMargin=16 * mm,
        bottomMargin=18 * mm,
        title="VulnScope Security Assessment Report",
        author="VulnScope"
    )

    navy = colors.HexColor("#17365D")
    blue = colors.HexColor("#2471A3")
    light_blue = colors.HexColor("#EAF2F8")
    dark = colors.HexColor("#263238")
    muted = colors.HexColor("#607080")
    border = colors.HexColor("#D8E0E8")
    light = colors.HexColor("#F5F7FA")
    white = colors.white

    severity_colors = {
        "Critical": colors.HexColor("#C0392B"),
        "High": colors.HexColor("#E67E22"),
        "Medium": colors.HexColor("#D4AC0D"),
        "Low": colors.HexColor("#239B56")
    }

    styles = getSampleStyleSheet()

    title_style = ParagraphStyle(
        "ReportTitle", parent=styles["Title"],
        fontName="Helvetica-Bold", fontSize=23, leading=27,
        textColor=navy, alignment=TA_CENTER, spaceAfter=4
    )

    subtitle_style = ParagraphStyle(
        "Subtitle", parent=styles["Normal"],
        fontName="Helvetica", fontSize=9, leading=13,
        textColor=muted, alignment=TA_CENTER, spaceAfter=9
    )

    section_style = ParagraphStyle(
        "Section", parent=styles["Heading2"],
        fontName="Helvetica-Bold", fontSize=12, leading=15,
        textColor=navy, spaceBefore=7, spaceAfter=6
    )

    body_style = ParagraphStyle(
        "Body", parent=styles["Normal"],
        fontName="Helvetica", fontSize=8.3, leading=10.8,
        textColor=dark
    )

    small_style = ParagraphStyle(
        "Small", parent=body_style,
        fontSize=7.5, leading=9.5, textColor=muted
    )

    finding_title_style = ParagraphStyle(
        "FindingTitle", parent=body_style,
        fontName="Helvetica-Bold", fontSize=9.2, leading=11,
        textColor=navy
    )

    elements = []

    def safe(value):
        return escape(str(value if value is not None else "Not provided"))

    # Convert scanner findings into report-friendly information.
    def get_finding_info(vuln):
        original_name = str(vuln.get("vuln_type", "Unnamed finding"))
        description = str(vuln.get("description", "No description available."))
        fix = str(vuln.get(
            "fix_suggestion",
            "Review the application configuration."
        ))
        severity = str(vuln.get("severity", "Unknown"))
        method = str(vuln.get("detected_by", "Not specified"))

        if "SSL Certificate Invalid" in original_name:
            name = "SSL Certificate Invalid"
            description = (
                "The scanner reported that SSL certificate validation failed "
                "for the HTTPS website."
            )
            why = (
                "Possible causes include an expired certificate, hostname "
                "mismatch, incomplete certificate chain, or an untrusted issuer."
            )
            solution = (
                "Verify the certificate validity, hostname, issuer, and "
                "certificate chain. Install or renew a valid certificate "
                "if required."
            )
            example = (
                "Use a trusted SSL checker to verify the certificate and "
                "correct any reported issues."
            )

        elif "HTTPS Not Enabled" in original_name:
            name = "HTTPS Not Enabled"
            description = (
                "The target URL uses HTTP instead of HTTPS. Data exchanged "
                "between the browser and server is not protected by TLS encryption."
            )
            why = "TLS may not be configured on the web server."
            solution = (
                "Configure HTTPS using a valid TLS certificate and redirect "
                "HTTP traffic to HTTPS."
            )
            example = "Configure the web server to use HTTPS on port 443."

        elif "X-Frame-Options" in original_name:
            name = "Missing X-Frame-Options Header"
            description = (
                "The server response does not include the X-Frame-Options "
                "header, which can help control whether the page is displayed "
                "inside a frame."
            )
            why = (
                "The header may be absent because clickjacking protection "
                "has not been configured in the web server or application."
            )
            solution = (
                "If the site does not need to be embedded in other websites, "
                "send the header X-Frame-Options: DENY. If trusted framing is "
                "required, SAMEORIGIN may be suitable. Also configure the "
                "Content-Security-Policy frame-ancestors directive."
            )
            example = "Example response header: X-Frame-Options: DENY"

        elif "Content Security Policy" in original_name or "CSP" in original_name:
            name = "Missing Content Security Policy"
            description = (
                "The response does not contain a Content-Security-Policy "
                "header. CSP lets the application restrict the sources from "
                "which scripts, styles, images and other resources can load."
            )
            why = (
                "This usually happens when the application or web server "
                "has no CSP policy configured. Without a suitable policy, "
                "the browser has fewer restrictions if injected content is present."
            )
            solution = (
                "Create a policy based on the resources the application "
                "actually needs. Start with a report-only policy, review "
                "violations, and then enforce it. Avoid allowing unsafe "
                "inline scripts or arbitrary external sources unless necessary."
            )
            example = (
                "Illustrative starting point: "
                "Content-Security-Policy: default-src 'self'; "
                "object-src 'none'; base-uri 'self'; frame-ancestors 'self'. "
                "Adjust this policy for the application's real dependencies."
            )

        elif "HSTS" in original_name or "Strict-Transport" in original_name:
            name = "Missing HSTS Header"
            description = (
                "The HTTPS response does not include the "
                "Strict-Transport-Security header. HSTS tells supported "
                "browsers to use HTTPS for future visits."
            )
            why = (
                "The header may be missing because HSTS has not been "
                "configured, or because the site is currently being served "
                "over HTTP. Browsers should receive HSTS over HTTPS."
            )
            solution = (
                "After HTTPS is correctly deployed, configure the response "
                "header Strict-Transport-Security: max-age=31536000. Add "
                "includeSubDomains only when every subdomain supports HTTPS. "
                "Consider preload only after careful review."
            )
            example = (
                "Example response header: "
                "Strict-Transport-Security: max-age=31536000"
            )

        elif "X-Content-Type-Options" in original_name or "nosniff" in original_name:
            name = "Missing X-Content-Type-Options Header"
            description = (
                "The response does not include X-Content-Type-Options: nosniff. "
                "This header instructs browsers not to guess a resource's "
                "content type."
            )
            why = (
                "The application or web server may not have a common "
                "security-header configuration. Content-type sniffing can "
                "cause browsers to interpret resources differently from "
                "the declared MIME type."
            )
            solution = (
                "Add X-Content-Type-Options: nosniff to application responses. "
                "Also ensure that files are served with the correct "
                "Content-Type header."
            )
            example = "Example response header: X-Content-Type-Options: nosniff"

        elif "HTTP Methods" in original_name or "HTTP Method" in original_name:
            name = "Potentially Unnecessary HTTP Methods Enabled"
            methods = description.split(":")[-1].strip().rstrip(".")
            description = (
                "The server advertises these HTTP methods: "
                + methods
                + ". GET, HEAD, POST and OPTIONS are commonly used by web "
                "applications. TRACE should be reviewed and disabled if "
                "not required. Advertising a method alone does not prove "
                "that it is exploitable."
            )
            why = (
                "The web server or reverse proxy may allow methods by "
                "default. Some methods are required for normal application "
                "operation, while unnecessary methods can increase the "
                "available attack surface."
            )
            solution = (
                "Review the methods required by the application. Disable "
                "unnecessary methods, especially TRACE, at the web server "
                "or reverse proxy. Re-test the endpoint after changing "
                "the configuration. Do not block POST or OPTIONS if the "
                "application depends on them."
            )
            example = (
                "Apache example: TraceEnable off. For other servers, use "
                "their method-allowlist or request-filtering configuration."
            )

        else:
            name = original_name
            why = (
                "The scanner reported this finding based on the response "
                "or behaviour observed during the assessment. The exact "
                "underlying cause should be confirmed manually."
            )
            solution = fix
            example = (
                "Verify the recommended configuration in the relevant "
                "application or server documentation."
            )

        return {
            "name": name,
            "severity": severity,
            "method": method,
            "description": description,
            "why": why,
            "solution": solution,
            "example": example
        }

    findings = [get_finding_info(v) for v in vulnerabilities]

    # PAGE 1: OVERVIEW

    elements.append(Paragraph("VulnScope", title_style))
    elements.append(Paragraph(
        "WEB APPLICATION SECURITY ASSESSMENT REPORT",
        subtitle_style
    ))
    elements.append(HRFlowable(
        width="100%", thickness=2, color=blue, spaceAfter=12
    ))

    elements.append(Paragraph("Assessment Details", section_style))

    info_data = [
        [
            Paragraph("<b>Target URL</b>", body_style),
            Paragraph(safe(scan.get("url")), body_style)
        ],
        [
            Paragraph("<b>Scan Date</b>", body_style),
            Paragraph(safe(scan.get("scanned_at")), body_style)
        ],
        [
            Paragraph("<b>Report Generated</b>", body_style),
            Paragraph(datetime.now().strftime("%d %B %Y, %I:%M %p"), body_style)
        ],
        [
            Paragraph("<b>Total Findings</b>", body_style),
            Paragraph(str(len(findings)), body_style)
        ]
    ]

    info_table = Table(info_data, colWidths=[42 * mm, 125 * mm])
    info_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (0, -1), light_blue),
        ("BACKGROUND", (1, 0), (1, -1), white),
        ("GRID", (0, 0), (-1, -1), 0.5, border),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("LEFTPADDING", (0, 0), (-1, -1), 8),
        ("RIGHTPADDING", (0, 0), (-1, -1), 8),
        ("TOPPADDING", (0, 0), (-1, -1), 7),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 7)
    ]))

    elements.append(info_table)
    elements.append(Spacer(1, 10))

    risk_score = max(0, min(100, int(scan.get("risk_score", 0) or 0)))

    if risk_score >= 75:
        risk_label = "CRITICAL RISK"
        risk_color = severity_colors["Critical"]
    elif risk_score >= 50:
        risk_label = "HIGH RISK"
        risk_color = severity_colors["High"]
    elif risk_score >= 25:
        risk_label = "MEDIUM RISK"
        risk_color = severity_colors["Medium"]
    else:
        risk_label = "LOW RISK"
        risk_color = severity_colors["Low"]

    score_style = ParagraphStyle(
        "Score", parent=body_style, fontName="Helvetica-Bold",
        fontSize=30, leading=34, textColor=risk_color,
        alignment=TA_CENTER
    )

    label_style = ParagraphStyle(
        "RiskLabel", parent=body_style, fontName="Helvetica-Bold",
        fontSize=10, leading=13, textColor=risk_color,
        alignment=TA_CENTER
    )

    score_table = Table(
        [
            [Paragraph(f"{risk_score}/100", score_style)],
            [Paragraph(risk_label, label_style)]
        ],
        colWidths=[167 * mm],
        rowHeights=[40, 23]
    )
    score_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), light),
        ("BOX", (0, 0), (-1, -1), 1.2, risk_color),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE")
    ]))

    elements.append(score_table)
    elements.append(Spacer(1, 4))
    elements.append(Paragraph(
        "The risk score is a project-defined value based on configured "
        "severity weights. It is not a probability of compromise.",
        small_style
    ))

    counts = {
        level: sum(1 for f in findings if f["severity"] == level)
        for level in ["Critical", "High", "Medium", "Low"]
    }

    elements.append(Paragraph("Severity Summary", section_style))

    summary_table = Table(
        [
            ["CRITICAL", "HIGH", "MEDIUM", "LOW"],
            [
                str(counts["Critical"]),
                str(counts["High"]),
                str(counts["Medium"]),
                str(counts["Low"])
            ]
        ],
        colWidths=[41.75 * mm] * 4,
        rowHeights=[24, 31]
    )
    summary_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (0, 0), severity_colors["Critical"]),
        ("BACKGROUND", (1, 0), (1, 0), severity_colors["High"]),
        ("BACKGROUND", (2, 0), (2, 0), severity_colors["Medium"]),
        ("BACKGROUND", (3, 0), (3, 0), severity_colors["Low"]),
        ("TEXTCOLOR", (0, 0), (-1, 0), white),
        ("BACKGROUND", (0, 1), (-1, 1), light),
        ("TEXTCOLOR", (0, 1), (-1, 1), dark),
        ("FONTNAME", (0, 0), (-1, -1), "Helvetica-Bold"),
        ("FONTSIZE", (0, 0), (-1, 0), 8),
        ("FONTSIZE", (0, 1), (-1, 1), 17),
        ("ALIGN", (0, 0), (-1, -1), "CENTER"),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("GRID", (0, 0), (-1, -1), 0.5, border)
    ]))

    elements.append(summary_table)
    elements.append(Spacer(1, 12))

    elements.append(Paragraph("Assessment Overview", section_style))
    elements.append(Paragraph(
        "The scan identified the security findings listed in this report. "
        "The findings are grouped by severity to help prioritize remediation. "
        "Each item should be reviewed and verified in the target environment "
        "before changes are deployed.",
        body_style
    ))

    elements.append(Spacer(1, 12))
    elements.append(Paragraph("Severity Priority", section_style))
    elements.append(Paragraph(
        "<b>Critical:</b> Address immediately. "
        "<b>High:</b> Prioritize remediation. "
        "<b>Medium:</b> Plan and implement corrective controls. "
        "<b>Low:</b> Improve configuration as part of security hardening.",
        body_style
    ))

    # Function to display each finding.
    def add_finding(index, finding):
        sev = finding["severity"]
        sev_color = severity_colors.get(sev, muted)

        heading = ParagraphStyle(
            f"FindingHeading{index}",
            parent=finding_title_style
        )

        sev_style = ParagraphStyle(
            f"FindingSeverity{index}",
            parent=body_style,
            fontName="Helvetica-Bold",
            fontSize=8,
            textColor=sev_color,
            alignment=TA_RIGHT
        )

        content = [
            [
                Paragraph(f"{index}. {safe(finding['name'])}", heading),
                Paragraph(safe(sev).upper(), sev_style)
            ],
            [
                Paragraph(
                    f"<b>Detection method:</b> {safe(finding['method'])}",
                    body_style
                ), ""
            ],
            [
                Paragraph(
                    f"<b>What is it?</b> {safe(finding['description'])}",
                    body_style
                ), ""
            ],
            [
                Paragraph(
                    f"<b>Why may it occur?</b> {safe(finding['why'])}",
                    body_style
                ), ""
            ],
            [
                Paragraph(
                    f"<b>Solution:</b> {safe(finding['solution'])}",
                    body_style
                ), ""
            ],
            [
                Paragraph(
                    f"<b>Configuration example:</b> "
                    f"{safe(finding['example'])}",
                    small_style
                ), ""
            ]
        ]

        table = Table(content, colWidths=[135 * mm, 32 * mm])
        table.setStyle(TableStyle([
            ("SPAN", (0, 1), (1, 1)),
            ("SPAN", (0, 2), (1, 2)),
            ("SPAN", (0, 3), (1, 3)),
            ("SPAN", (0, 4), (1, 4)),
            ("SPAN", (0, 5), (1, 5)),
            ("BACKGROUND", (0, 0), (-1, 0), light_blue),
            ("BOX", (0, 0), (-1, -1), 0.7, border),
            ("LINEBEFORE", (0, 0), (0, -1), 3, sev_color),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ("LEFTPADDING", (0, 0), (-1, -1), 8),
            ("RIGHTPADDING", (0, 0), (-1, -1), 8),
            ("TOPPADDING", (0, 0), (-1, -1), 5),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 5)
        ]))

        elements.append(KeepTogether([table, Spacer(1, 8)]))

    # PAGE 2: FIRST THREE FINDINGS

    elements.append(PageBreak())
    elements.append(Paragraph("Detailed Security Findings", title_style))
    elements.append(Paragraph(
        "Security findings | Description, cause and remediation",
        subtitle_style
    ))
    elements.append(HRFlowable(
        width="100%", thickness=1, color=blue, spaceAfter=10
    ))

    for i in range(min(3, len(findings))):
        add_finding(i + 1, findings[i])

    # PAGE 3: ONLY IF THERE ARE MORE THAN THREE FINDINGS

    if len(findings) > 3:
        elements.append(PageBreak())
        elements.append(Paragraph("Findings and Remediation", title_style))
        elements.append(Paragraph(
            "Remaining findings | Remediation and assessment limitations",
            subtitle_style
        ))
        elements.append(HRFlowable(
            width="100%", thickness=1, color=blue, spaceAfter=10
        ))

        for i in range(3, len(findings)):
            add_finding(i + 1, findings[i])

    # Scope and limitations
    elements.append(Paragraph("Scope and Limitations", section_style))
    elements.append(Paragraph(
        "This report contains the findings produced by the configured "
        "VulnScope checks for the target and scan date shown. Automated "
        "results are preliminary and may require manual verification. "
        "A reported finding does not necessarily establish exploitability, "
        "and the absence of a finding does not guarantee that the application "
        "is secure. Results depend on the checks implemented, the pages "
        "reached and the responses received during this scan. Testing must "
        "only be performed on systems for which authorization has been granted.",
        small_style
    ))

    # Page number footer
    def draw_page(canvas, document):
        canvas.saveState()
        canvas.setStrokeColor(border)
        canvas.setLineWidth(0.5)
        canvas.line(
            17 * mm, 13 * mm,
            page_width - 17 * mm, 13 * mm
        )
        canvas.setFont("Helvetica", 8)
        canvas.setFillColor(muted)
        canvas.drawRightString(
            page_width - 17 * mm,
            8 * mm,
            f"Page {document.page}"
        )
        canvas.restoreState()

    doc.build(
        elements,
        onFirstPage=draw_page,
        onLaterPages=draw_page
    )

    buffer.seek(0)
    return buffer
