import base64
import time
import requests
from flask import current_app

VT_URL = "https://www.virustotal.com/api/v3/urls"
VT_ANALYSIS = "https://www.virustotal.com/api/v3/analyses"


def url_to_id(url):
    """
    Convert URL to VirusTotal URL ID.
    """
    return base64.urlsafe_b64encode(
        url.encode()
    ).decode().strip("=")


def get_headers():
    return {
        "x-apikey": current_app.config["VIRUSTOTAL_API_KEY"]
    }


def get_url_report(url):
    """
    Try to retrieve an existing VirusTotal report.
    """

    url_id = url_to_id(url)

    response = requests.get(
        f"{VT_URL}/{url_id}",
        headers=get_headers(),
        timeout=10
    )

    if response.status_code == 200:

        attributes = response.json()["data"]["attributes"]
        stats = attributes["last_analysis_stats"]

        return {
            "success": True,
            "malicious": stats["malicious"],
            "suspicious": stats["suspicious"],
            "harmless": stats["harmless"],
            "undetected": stats["undetected"]
        }

    return {
        "success": False,
        "message": "No existing report."
    }


def submit_url(url):
    """
    Submit URL for VirusTotal analysis.
    """

    response = requests.post(
        VT_URL,
        headers=get_headers(),
        data={"url": url},
        timeout=10
    )

    if response.status_code != 200:

        return {
            "success": False,
            "message": response.text
        }

    analysis_id = response.json()["data"]["id"]

    return {
        "success": True,
        "analysis_id": analysis_id
    }


def wait_for_analysis(analysis_id):
    """
    Wait briefly for VirusTotal analysis.
    """

    # Maximum wait ≈ 5 seconds
    for _ in range(5):

        response = requests.get(
            f"{VT_ANALYSIS}/{analysis_id}",
            headers=get_headers(),
            timeout=10
        )

        if response.status_code == 200:

            status = response.json()["data"]["attributes"]["status"]

            if status == "completed":
                return True

        time.sleep(1)

    return False


def analyze_url_with_virustotal(url):
    """
    VirusTotal workflow.

    1. Check existing report.
    2. If unavailable, submit URL.
    3. Wait briefly.
    4. Return report if available.
    """

    # Step 1: Check if VirusTotal already has a report
    report = get_url_report(url)

    if report["success"]:
        return report

    # Step 2: Submit URL
    submit = submit_url(url)

    if not submit["success"]:
        return submit

    # Step 3: Wait a short time
    wait_for_analysis(submit["analysis_id"])

    # Step 4: Try getting the report again
    report = get_url_report(url)

    if report["success"]:
        return report

    return {
        "success": False,
        "message": "VirusTotal analysis is still in progress."
    }