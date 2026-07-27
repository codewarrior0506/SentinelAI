from flask import Blueprint, render_template, request

from app.services.history_service import get_scan_history

history = Blueprint("history", __name__)


@history.route("/history")
def scan_history():

    search = request.args.get("search", "").strip()

    data = get_scan_history(search=search)

    return render_template(
        "history.html",
        history=data["history"],
        total=data["total"],
        safe=data["safe"],
        suspicious=data["suspicious"],
        dangerous=data["dangerous"],
        search=search
    )