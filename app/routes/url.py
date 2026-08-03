from flask import Blueprint, render_template, request

from app.services.url_service import analyze_url

url = Blueprint("url", __name__)


@url.route("/url-analyzer", methods=["GET", "POST"])
def url_analyzer():

    result = None
    submitted_url = ""

    if request.method == "POST":

        submitted_url = request.form.get("url")

        result = analyze_url(submitted_url)

        print("IOC Score:", result["ioc_score"])
        print("IOC Findings:", result["ioc_findings"])

    return render_template(
        "url_analyzer.html",
        result=result,
        submitted_url=submitted_url
    )