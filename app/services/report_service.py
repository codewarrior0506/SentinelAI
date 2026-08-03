from io import BytesIO
from datetime import datetime

from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.lib.units import inch

from reportlab.platypus import (
    SimpleDocTemplate,
    Paragraph,
    Spacer,
    Table,
    TableStyle,
    HRFlowable,
)


# ---------------------------------------------------------
# Theme Colors
# ---------------------------------------------------------

PRIMARY = colors.HexColor("#1E3A8A")
SUCCESS = colors.HexColor("#10B981")
WARNING = colors.HexColor("#F59E0B")
DANGER = colors.HexColor("#DC2626")

LIGHT = colors.whitesmoke
ALT = colors.beige


# ---------------------------------------------------------
# Threat Level
# ---------------------------------------------------------

def get_threat_level(stats):

    dangerous = stats["dangerous"]
    suspicious = stats["suspicious"]
    avg = stats["avg_risk"]

    if dangerous >= 5 or avg >= 70:
        return "HIGH", DANGER

    if dangerous >= 1 or suspicious >= 3 or avg >= 30:
        return "MEDIUM", WARNING

    return "LOW", SUCCESS


# ---------------------------------------------------------
# Footer
# ---------------------------------------------------------

def add_page_number(canvas, doc):

    canvas.saveState()

    canvas.setFont("Helvetica", 9)

    canvas.setFillColor(colors.grey)

    canvas.drawString(

        doc.leftMargin,

        20,

        "SentinelAI | AI-Powered Cyber Fraud Early Warning Platform"

    )

    canvas.drawRightString(

        doc.pagesize[0] - doc.rightMargin,

        20,

        f"Page {doc.page}"

    )

    canvas.restoreState()


# ---------------------------------------------------------
# Styles
# ---------------------------------------------------------

def build_styles():

    styles = getSampleStyleSheet()

    title = styles["Title"]
    title.alignment = TA_CENTER
    title.textColor = PRIMARY

    heading = styles["Heading2"]
    heading.textColor = PRIMARY

    body = styles["BodyText"]

    footer = styles["BodyText"]
    footer.alignment = TA_CENTER
    footer.textColor = colors.grey

    return {

        "title": title,

        "heading": heading,

        "body": body,

        "footer": footer

    }


# ---------------------------------------------------------
# Summary Table
# ---------------------------------------------------------

def create_summary_table(stats):

    data = [

        ["Metric", "Value"],

        ["Total Scans", stats["total"]],

        ["Safe URLs", stats["safe"]],

        ["Suspicious URLs", stats["suspicious"]],

        ["Dangerous URLs", stats["dangerous"]],

        ["Average Risk Score", stats["avg_risk"]]

    ]

    table = Table(

        data,

        colWidths=[260, 170]

    )

    table.setStyle(

        TableStyle([

            ("BACKGROUND", (0,0), (-1,0), PRIMARY),

            ("TEXTCOLOR", (0,0), (-1,0), colors.white),

            ("FONTNAME", (0,0), (-1,0), "Helvetica-Bold"),

            ("BOTTOMPADDING", (0,0), (-1,0), 10),

            ("GRID", (0,0), (-1,-1), .5, colors.grey),

            ("BACKGROUND", (0,1), (-1,-1), LIGHT),

            ("ALIGN", (1,1), (-1,-1), "CENTER"),

        ])

    )

    return table

def generate_security_report(stats):

    buffer = BytesIO()

    doc = SimpleDocTemplate(
        buffer,
        rightMargin=40,
        leftMargin=40,
        topMargin=40,
        bottomMargin=40
    )

    styles = build_styles()

    elements = []

    # =====================================================
    # HEADER
    # =====================================================

    elements.append(
        Paragraph(
            "🛡 <b>SentinelAI</b>",
            styles["title"]
        )
    )

    elements.append(
        Paragraph(
            "AI-Powered Cyber Fraud Early Warning Platform",
            styles["heading"]
        )
    )

    elements.append(Spacer(1, 0.15 * inch))

    elements.append(
        HRFlowable(
            width="100%",
            thickness=2,
            color=PRIMARY
        )
    )

    elements.append(Spacer(1, 0.25 * inch))

    elements.append(
        Paragraph(
            "<b>SECURITY ASSESSMENT REPORT</b>",
            styles["heading"]
        )
    )

    elements.append(
        Paragraph(
            datetime.now().strftime(
                "Generated on %d %B %Y | %I:%M %p"
            ),
            styles["body"]
        )
    )

    elements.append(Spacer(1, 0.35 * inch))

    # =====================================================
    # EXECUTIVE SUMMARY
    # =====================================================

    elements.append(
        Paragraph(
            "<b>EXECUTIVE SUMMARY</b>",
            styles["heading"]
        )
    )

    elements.append(Spacer(1, 8))

    elements.append(
        create_summary_table(stats)
    )

    elements.append(Spacer(1, 0.35 * inch))

    # =====================================================
    # THREAT LEVEL
    # =====================================================

    level, colour = get_threat_level(stats)

    elements.append(
        Paragraph(
            "<b>OVERALL THREAT LEVEL</b>",
            styles["heading"]
        )
    )

    elements.append(Spacer(1, 8))

    threat_table = Table(
        [[level]],
        colWidths=[170]
    )

    threat_table.setStyle(

        TableStyle([

            ("BACKGROUND", (0,0), (0,0), colour),

            ("TEXTCOLOR", (0,0), (0,0), colors.white),

            ("ALIGN", (0,0), (0,0), "CENTER"),

            ("FONTNAME", (0,0), (0,0), "Helvetica-Bold"),

            ("FONTSIZE", (0,0), (0,0), 18),

            ("BOTTOMPADDING", (0,0), (0,0), 12),

            ("TOPPADDING", (0,0), (0,0), 12),

        ])

    )

    elements.append(threat_table)

    elements.append(Spacer(1, 0.40 * inch))

    # =====================================================
    # HIGHEST RISK URLS
    # =====================================================

    elements.append(

        Paragraph(

            "<b>🔥 HIGHEST RISK URLS</b>",

            styles["heading"]

        )

    )

    elements.append(Spacer(1, 8))

    threat_data = [

        ["URL", "Risk Score", "Status"]

    ]

    if stats["top_threats"]:

        for item in stats["top_threats"]:

            threat_data.append([

                item["url"],

                item["risk_score"],

                item["status"]

            ])

    else:

        threat_data.append([

            "No Data",

            "-",

            "-"

        ])

    threat_table = Table(

        threat_data,

        colWidths=[270, 70, 90]

    )

    threat_table.setStyle(

        TableStyle([

            ("BACKGROUND", (0,0), (-1,0), PRIMARY),

            ("TEXTCOLOR", (0,0), (-1,0), colors.white),

            ("FONTNAME", (0,0), (-1,0), "Helvetica-Bold"),

            ("BOTTOMPADDING", (0,0), (-1,0), 10),

            ("GRID", (0,0), (-1,-1), .5, colors.grey),

            ("ROWBACKGROUNDS",

                (0,1),

                (-1,-1),

                [LIGHT, ALT]

            ),

            ("ALIGN",

                (1,1),

                (-1,-1),

                "CENTER"

            ),

        ])

    )

    elements.append(threat_table)

    elements.append(Spacer(1, 0.35 * inch))

        # =====================================================
    # TOP SCANNED DOMAINS
    # =====================================================

    elements.append(
        Paragraph(
            "<b>🌐 TOP SCANNED DOMAINS</b>",
            styles["heading"]
        )
    )

    elements.append(Spacer(1, 8))

    domain_data = [
        ["Domain", "Scans"]
    ]

    if stats["top_domains"]:

        for domain in stats["top_domains"]:

            domain_data.append([
                domain["domain"],
                domain["count"]
            ])

    else:

        domain_data.append([
            "No Data",
            "-"
        ])

    domain_table = Table(
        domain_data,
        colWidths=[320, 110]
    )

    domain_table.setStyle(
        TableStyle([

            ("BACKGROUND",(0,0),(-1,0),PRIMARY),

            ("TEXTCOLOR",(0,0),(-1,0),colors.white),

            ("FONTNAME",(0,0),(-1,0),"Helvetica-Bold"),

            ("GRID",(0,0),(-1,-1),0.5,colors.grey),

            ("BOTTOMPADDING",(0,0),(-1,0),10),

            ("ROWBACKGROUNDS",
                (0,1),
                (-1,-1),
                [LIGHT,ALT]
            ),

            ("ALIGN",(1,1),(-1,-1),"CENTER")

        ])
    )

    elements.append(domain_table)

    elements.append(Spacer(1,0.35*inch))

    # =====================================================
    # RECENT ACTIVITY
    # =====================================================

    elements.append(
        Paragraph(
            "<b>🕒 RECENT ACTIVITY</b>",
            styles["heading"]
        )
    )

    elements.append(Spacer(1,8))

    activity_data = [
        ["URL","Risk","Status","Scan Time"]
    ]

    if stats["recent"]:

        for item in stats["recent"]:

            activity_data.append([

                item["url"],

                item["risk_score"],

                item["status"],

                str(item["scan_time"])

            ])

    else:

        activity_data.append([
            "No Data",
            "-",
            "-",
            "-"
        ])

    activity_table = Table(
        activity_data,
        colWidths=[220,55,80,105]
    )

    activity_table.setStyle(

        TableStyle([

            ("BACKGROUND",(0,0),(-1,0),PRIMARY),

            ("TEXTCOLOR",(0,0),(-1,0),colors.white),

            ("FONTNAME",(0,0),(-1,0),"Helvetica-Bold"),

            ("GRID",(0,0),(-1,-1),0.5,colors.grey),

            ("BOTTOMPADDING",(0,0),(-1,0),10),

            ("ROWBACKGROUNDS",
                (0,1),
                (-1,-1),
                [LIGHT,ALT]
            ),

            ("ALIGN",(1,1),(-1,-1),"CENTER")

        ])

    )

    elements.append(activity_table)

    elements.append(Spacer(1,0.4*inch))

    # =====================================================
    # SECURITY ASSESSMENT
    # =====================================================

    elements.append(
        Paragraph(
            "<b>📊 SECURITY ASSESSMENT</b>",
            styles["heading"]
        )
    )

    elements.append(Spacer(1,8))

    assessment = f"""

SentinelAI analyzed <b>{stats['total']}</b> URLs.

Safe URLs : <b>{stats['safe']}</b><br/>

Suspicious URLs : <b>{stats['suspicious']}</b><br/>

Dangerous URLs : <b>{stats['dangerous']}</b><br/><br/>

Average Risk Score :
<b>{stats['avg_risk']}</b>

"""

    elements.append(
        Paragraph(
            assessment,
            styles["body"]
        )
    )

    elements.append(Spacer(1,0.3*inch))

    # =====================================================
    # RECOMMENDATIONS
    # =====================================================

    elements.append(
        Paragraph(
            "<b>💡 SECURITY RECOMMENDATIONS</b>",
            styles["heading"]
        )
    )

    elements.append(Spacer(1,8))

    recommendations=[]

    if stats["dangerous"]>=5:

        recommendations.extend([

            "• Immediate action is recommended.",

            "• Block malicious domains.",

            "• Perform endpoint investigation.",

            "• Notify administrators."

        ])

    elif stats["dangerous"]>0:

        recommendations.extend([

            "• Investigate dangerous URLs.",

            "• Continue monitoring."

        ])

    else:

        recommendations.extend([

            "• No major threats detected.",

            "• Continue periodic monitoring."

        ])

    if stats["suspicious"]>0:

        recommendations.append(

            "• Review suspicious URLs manually."

        )

    for text in recommendations:

        elements.append(
            Paragraph(
                text,
                styles["body"]
            )
        )

    elements.append(Spacer(1,0.35*inch))

    # =====================================================
    # FOOTER
    # =====================================================

    elements.append(

        HRFlowable(

            width="100%",

            thickness=1,

            color=colors.grey

        )

    )

    elements.append(Spacer(1,8))

    elements.append(

        Paragraph(

            "<b>Generated by SentinelAI</b>",

            styles["footer"]

        )

    )

    elements.append(

        Paragraph(

            "AI-Powered Cyber Fraud Early Warning Platform",

            styles["footer"]

        )

    )

    elements.append(

        Paragraph(

            "Version 1.0",

            styles["footer"]

        )

    )

    doc.build(

        elements,

        onFirstPage=add_page_number,

        onLaterPages=add_page_number

    )

    buffer.seek(0)

    return buffer