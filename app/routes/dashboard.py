from flask import Blueprint, render_template

from app.services.history_service import get_dashboard_stats

dashboard = Blueprint("dashboard", __name__)


@dashboard.route("/dashboard")
def dashboard_page():

    stats = get_dashboard_stats()

    return render_template(
        "dashboard.html",
        stats=stats
    )