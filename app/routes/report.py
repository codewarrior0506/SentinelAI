from flask import Blueprint, send_file

from app.services.history_service import get_dashboard_stats
from app.services.report_service import generate_security_report

report = Blueprint("report", __name__)


@report.route("/report")
def download_report():

    stats = get_dashboard_stats()

    pdf = generate_security_report(stats)

    return send_file(
        pdf,
        as_attachment=True,
        download_name="SentinelAI_Security_Report.pdf",
        mimetype="application/pdf",
    )