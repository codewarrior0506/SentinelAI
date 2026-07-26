from flask import Blueprint, render_template, request

from app.services.url_service import validate_url

url = Blueprint("url", __name__)


@url.route("/url-analyzer", methods=["GET", "POST"])
def url_analyzer():

    result = None

    if request.method == "POST":

        user_url = request.form.get("url")

        result = validate_url(user_url)

    return render_template(
        "url_analyzer.html",
        result=result
    )