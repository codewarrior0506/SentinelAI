from io import BytesIO
from datetime import datetime

from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.lib.units import inch
from reportlab.lib.enums import TA_CENTER, TA_RIGHT
from reportlab.pdfgen import canvas
from reportlab.platypus import (
    SimpleDocTemplate,
    Paragraph,
    Spacer,
    Table,
    TableStyle,
    HRFlowable,
)


def get_threat_level(avg_risk):

    if avg_risk < 30:
        return "LOW", colors.green

    elif avg_risk < 70:
        return "MEDIUM", colors.orange

    return "HIGH", colors.red

def add_page_number(canvas, doc):
    canvas.saveState()

    canvas.setFont("Helvetica", 9)
    canvas.setFillColor(colors.grey)

    footer_text = (
        f"SentinelAI | AI-Powered Cyber Fraud Early Warning Platform"
    )

    canvas.drawString(
        doc.leftMargin,
        20,
        footer_text
    )

    canvas.drawRightString(
        doc.pagesize[0] - doc.rightMargin,
        20,
        f"Page {doc.page}"
    )

    canvas.restoreState()

def generate_security_report(stats):

    buffer = BytesIO()

    doc = SimpleDocTemplate(
        buffer,
        rightMargin=40,
        leftMargin=40,
        topMargin=40,
        bottomMargin=40,
    )

    styles = getSampleStyleSheet()

    title_style = styles["Title"]
    title_style.alignment = TA_CENTER
    title_style.textColor = colors.darkblue

    heading_style = styles["Heading2"]
    heading_style.textColor = colors.darkblue

    normal = styles["BodyText"]

    elements = []

    # -------------------------------------------------
    # Title
    # -------------------------------------------------

    elements.append(
        Paragraph("🛡 <b>SentinelAI</b>", title_style)
    )

    elements.append(
        Paragraph(
            "AI-Powered Cyber Fraud Early Warning Platform",
            styles["Heading3"],
        )
    )

    elements.append(Spacer(1, 0.2 * inch))

    elements.append(
        Paragraph(
            "<b>SECURITY ASSESSMENT REPORT</b>",
            heading_style,
        )
    )

    elements.append(
        Paragraph(
            datetime.now().strftime(
                "Generated on %d %B %Y | %I:%M %p"
            ),
            normal,
        )
    )

    elements.append(Spacer(1, 0.3 * inch))

    elements.append(
        HRFlowable(
            width="100%",
            thickness=2,
            color=colors.HexColor("#1E3A8A"),
        )
    )

    elements.append(Spacer(1, 0.25 * inch))

    # -------------------------------------------------
    # Executive Summary
    # -------------------------------------------------

    elements.append(
        Paragraph(
            "<b>EXECUTIVE SUMMARY</b>",
            heading_style,
        )
    )

    summary = [

        ["Metric", "Value"],

        ["Total Scans", stats["total"]],

        ["Safe URLs", stats["safe"]],

        ["Suspicious URLs", stats["suspicious"]],

        ["Dangerous URLs", stats["dangerous"]],

        ["Average Risk Score", stats["avg_risk"]],

    ]

    summary_table = Table(summary, colWidths=[250, 180])

    summary_table.setStyle(

        TableStyle([

            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1E3A8A")),

            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),

            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),

            ("BOTTOMPADDING", (0, 0), (-1, 0), 10),

            ("BACKGROUND", (0, 1), (-1, -1), colors.whitesmoke),

            ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),

            ("ALIGN", (1, 1), (-1, -1), "CENTER"),

        ])

    )

    elements.append(summary_table)

    elements.append(Spacer(1, 0.3 * inch))

    # -------------------------------------------------
    # Threat Level
    # -------------------------------------------------

    level, color = get_threat_level(stats["avg_risk"])

    elements.append(
        Paragraph(
            "<b>OVERALL THREAT LEVEL</b>",
            heading_style,
        )
    )

    threat_table = Table(
        [[level]],
        colWidths=[150],
    )

    threat_table.setStyle(

        TableStyle([

            ("BACKGROUND", (0, 0), (0, 0), color),

            ("TEXTCOLOR", (0, 0), (0, 0), colors.white),

            ("ALIGN", (0, 0), (0, 0), "CENTER"),

            ("FONTNAME", (0, 0), (0, 0), "Helvetica-Bold"),

            ("FONTSIZE", (0, 0), (0, 0), 16),

            ("BOTTOMPADDING", (0, 0), (0, 0), 12),

            ("TOPPADDING", (0, 0), (0, 0), 12),

        ])

    )

    elements.append(threat_table)

    elements.append(Spacer(1, 0.5 * inch))

    # -------------------------------------------------
    # Highest Risk URLs
    # -------------------------------------------------

    elements.append(
        Paragraph(
            "<b>🔥 HIGHEST RISK URLS</b>",
            heading_style,
        )
    )

    elements.append(Spacer(1, 10))

    threat_data = [
        ["URL", "Risk Score", "Status"]
    ]

    for item in stats["top_threats"]:

        threat_data.append([
            item["url"],
            item["risk_score"],
            item["status"]
        ])

        threat_table = Table(
            threat_data,
            colWidths=[270, 70, 90]
        )

        threat_table.setStyle(

           TableStyle([

                ("BACKGROUND", (0,0), (-1,0), colors.HexColor("#1E3A8A")),

                ("TEXTCOLOR", (0,0), (-1,0), colors.white),

                ("FONTNAME", (0,0), (-1,0), "Helvetica-Bold"),

                ("GRID", (0,0), (-1,-1), 0.5, colors.grey),

                ("ALIGN", (1,1), (-1,-1), "CENTER"),

                ("BOTTOMPADDING", (0,0), (-1,0), 10),

                ("ROWBACKGROUNDS",
                   (0,1),
                   (-1,-1),
                   [
                       colors.whitesmoke,
                       colors.beige
                   ]
                ),

            ])

        )

        elements.append(threat_table)

        elements.append(Spacer(1, 0.35 * inch))

        # -------------------------------------------------
        # Top Scanned Domains
        # -------------------------------------------------

        elements.append(
            Paragraph(
                "<b>🌐 TOP SCANNED DOMAINS</b>",
                heading_style,
            )
        )

        elements.append(Spacer(1, 10))

        domain_data = [
            ["Domain", "Total Scans"]
        ]

        if stats["top_domains"]:
            for domain in stats["top_domains"]:
                domain_data.append([
                    domain["domain"],
                    domain["count"]
                ])
        else:
             domain_data.append([
                 "No Data Available",
                 "-"
            ])

        domain_table = Table(
            domain_data,
            colWidths=[320, 110]
        )

        domain_table.setStyle(

            TableStyle([

                ("BACKGROUND", (0,0), (-1,0), colors.HexColor("#1E3A8A")),

                ("TEXTCOLOR", (0,0), (-1,0), colors.white),

                ("FONTNAME", (0,0), (-1,0), "Helvetica-Bold"),

                ("BOTTOMPADDING", (0,0), (-1,0), 10),

                ("GRID", (0,0), (-1,-1), 0.5, colors.grey),

                ("ROWBACKGROUNDS",
                    (0,1),
                    (-1,-1),
                    [colors.whitesmoke, colors.beige]
                ),

                ("ALIGN", (1,1), (-1,-1), "CENTER")

            ])

        )

        elements.append(domain_table)

        elements.append(Spacer(1, 0.3 * inch))

        # -------------------------------------------------
        # Recent Activity
        # -------------------------------------------------

        elements.append(
           Paragraph(
              "<b>🕒 RECENT ACTIVITY</b>",
              heading_style,
            )
        )

        elements.append(Spacer(1, 10))

        activity_data = [
           ["URL", "Risk", "Status"]
        ]

        if stats["recent"]:

            for item in stats["recent"]:

                activity_data.append([
                   item["url"],
                   item["risk_score"],
                   item["status"]
                ])

        else:

            activity_data.append([
                "No Recent Activity",
                "-",
                "-"
            ])

        activity_table = Table(
            activity_data,
            colWidths=[250, 70, 110]
        )

        activity_table.setStyle(

           TableStyle([

               ("BACKGROUND", (0,0), (-1,0), colors.HexColor("#1E3A8A")),

               ("TEXTCOLOR", (0,0), (-1,0), colors.white),

               ("FONTNAME", (0,0), (-1,0), "Helvetica-Bold"),

               ("BOTTOMPADDING", (0,0), (-1,0), 10),

               ("GRID", (0,0), (-1,-1), 0.5, colors.grey),

               ("ROWBACKGROUNDS",
                   (0,1),
                   (-1,-1),
                   [colors.whitesmoke, colors.beige]
                ),

                ("ALIGN", (1,1), (-1,-1), "CENTER")

            ])

        )

        elements.append(activity_table)

        elements.append(Spacer(1, 0.35 * inch))

        # -------------------------------------------------
        # Security Assessment
        # -------------------------------------------------

        elements.append(
           Paragraph(
               "<b>📊 SECURITY ASSESSMENT</b>",
               heading_style,
            )
        )

        elements.append(Spacer(1, 8))

        assessment = f"""
        This report summarizes the URL security analysis performed by SentinelAI.

        A total of <b>{stats['total']}</b> URLs were analyzed.

        Out of these:

        • <b>{stats['safe']}</b> Safe URLs

        • <b>{stats['suspicious']}</b> Suspicious URLs

        • <b>{stats['dangerous']}</b> Dangerous URLs

        The overall average risk score is
        <b>{stats['avg_risk']}</b>,
        resulting in an overall threat level of
        <b>{level}</b>.
        """

        elements.append(
           Paragraph(
               assessment,
               normal
            )
        )

        elements.append(Spacer(1, 0.25 * inch))

        # -------------------------------------------------
        # Recommendations
        # -------------------------------------------------

        elements.append(
            Paragraph(
               "<b>💡 SECURITY RECOMMENDATIONS</b>",
               heading_style,
            )
        )

        recommendations = []

        if stats["dangerous"] > 0:

            recommendations.extend([

                "• Immediately investigate all dangerous URLs.",

                "• Block malicious domains at the firewall.",

                "• Review affected systems for compromise.",

                "• Inform security administrators.",

            ])

        if stats["suspicious"] > 0:

            recommendations.extend([

                 "• Continue monitoring suspicious URLs.",

                 "• Perform additional reputation checks.",

            ])

        if stats["dangerous"] == 0 and stats["suspicious"] == 0:

            recommendations.extend([

                "• No significant threats detected.",

                "• Continue periodic monitoring.",

                "• Maintain updated threat intelligence feeds.",

            ])

        for recommendation in recommendations:

            elements.append(
                Paragraph(
                    recommendation,
                    normal
                )
            )

        elements.append(
            Spacer(1, 0.35 * inch)
        )

        # -------------------------------------------------
        # FOOTER
        # -------------------------------------------------

        elements.append(
           HRFlowable(
               width="100%",
               thickness=1,
               color=colors.grey,
            )
        )

        elements.append(
            Spacer(1, 8)
        )

        footer_style = styles["BodyText"]
        footer_style.alignment = TA_CENTER
        footer_style.textColor = colors.grey

        elements.append(
            Paragraph(
                "<b>Generated by SentinelAI</b>",
                footer_style
            )
        )

        elements.append(
            Paragraph(
                "AI-Powered Cyber Fraud Early Warning Platform",
                 footer_style
            )
        )

        elements.append(
            Paragraph(
                "Version 1.0",
                footer_style
            )
        )


    doc.build(
        elements,
        onFirstPage=add_page_number,
        onLaterPages=add_page_number,
    )

    buffer.seek(0)

    return buffer