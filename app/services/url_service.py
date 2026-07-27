from urllib.parse import urlparse
import ipaddress
import socket

from app.services.whois_service import get_domain_info
from app.services.virustotal_service import analyze_url_with_virustotal
from app.services.history_service import save_scan


SUSPICIOUS_KEYWORDS = [
    "login",
    "verify",
    "secure",
    "update",
    "bank",
    "account",
    "password",
    "signin",
    "wallet",
    "payment"
]


def analyze_url(url):
    """
    Analyze a URL and calculate a phishing risk score.
    """

    parsed = urlparse(url)

    # Validate URL
    if not parsed.scheme or not parsed.netloc:
        return {
            "valid": False
        }

    domain = parsed.netloc.split(":")[0]

    # -------------------------
    # Initialize variables
    # -------------------------

    https = parsed.scheme.lower() == "https"
    risk_score = 0

    # -------------------------
    # Resolve IP Address
    # -------------------------

    try:
        ip_address = socket.gethostbyname(domain)
        dns_status = True

    except socket.gaierror:
        ip_address = "Unable to resolve"
        dns_status = False
        risk_score += 15

    # -------------------------
    # WHOIS Information
    # -------------------------

    whois_info = get_domain_info(domain)

    # Get VirusTotal Information

    vt_result = analyze_url_with_virustotal(url)

    # -------------------------
    # HTTPS Check
    # -------------------------

    if not https:
        risk_score += 20

    # -------------------------
    # URL Length
    # -------------------------

    if len(url) > 75:
        risk_score += 10

    # -------------------------
    # @ Symbol
    # -------------------------

    if "@" in url:
        risk_score += 25

    # -------------------------
    # Double Slash
    # -------------------------

    if "//" in parsed.path:
        risk_score += 15

    # -------------------------
    # IP Address instead of Domain
    # -------------------------

    uses_ip = False

    try:
        ipaddress.ip_address(domain)
        uses_ip = True
        risk_score += 30

    except ValueError:
        pass

    # -------------------------
    # Subdomains
    # -------------------------

    subdomain_count = max(0, len(domain.split(".")) - 2)

    if subdomain_count >= 2:
        risk_score += 10

    # -------------------------
    # Suspicious Keywords
    # -------------------------

    found_keywords = []

    full_url = url.lower()

    for keyword in SUSPICIOUS_KEYWORDS:
        if keyword in full_url:
            found_keywords.append(keyword)

    risk_score += len(found_keywords) * 5

    # -------------------------
    # Domain Age
    # -------------------------

    if whois_info["success"]:

        domain_age = whois_info["domain_age"]

        if domain_age is not None:

            if domain_age < 30:
                risk_score += 40

            elif domain_age < 180:
                risk_score += 20

    # -------------------------
    # VirusTotal Analysis
    # -------------------------

    if vt_result["success"]:

        if vt_result["malicious"] >= 5:
            risk_score += 50

        elif vt_result["malicious"] >= 1:
            risk_score += 30

        if vt_result["suspicious"] >= 3:
            risk_score += 15

    # -------------------------
    # Limit Score
    # -------------------------

    risk_score = min(risk_score, 100)

    # -------------------------
    # Final Status
    # -------------------------

    if risk_score < 20:
        status = "Safe"
        recommendation = "URL appears safe."

    elif risk_score < 50:
        status = "Suspicious"
        recommendation = "Proceed with caution."

    else:
        status = "Dangerous"
        recommendation = "Avoid opening this URL."

        # -------------------------
    # Save Scan History
    # -------------------------

    save_scan(
        url=url,
        risk_score=risk_score,
        status=status,
        registrar=whois_info.get("registrar"),
        domain_age=whois_info.get("domain_age"),
        vt_malicious=vt_result.get("malicious", 0),
        vt_suspicious=vt_result.get("suspicious", 0)
    )

    # -------------------------
    # Return Results
    # -------------------------

    return {

        "valid": True,

        "domain": domain,

        "scheme": parsed.scheme,

        "https": https,

        "length": len(url),

        "ip_address": ip_address,

        "dns_status": dns_status,

        "uses_ip": uses_ip,

        "subdomains": subdomain_count,

        "keywords": found_keywords,

        "registrar": whois_info.get("registrar"),

        "creation_date": whois_info.get("creation_date"),

        "expiration_date": whois_info.get("expiration_date"),

        "domain_age": whois_info.get("domain_age"),

        "vt_success": vt_result.get("success", False),

        "vt_malicious": vt_result.get("malicious", 0),

        "vt_suspicious": vt_result.get("suspicious", 0),

        "vt_harmless": vt_result.get("harmless", 0),

        "vt_undetected": vt_result.get("undetected", 0),

        "risk_score": risk_score,

        "status": status,

        "recommendation": recommendation

    }