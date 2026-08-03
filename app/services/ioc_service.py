from urllib.parse import urlparse
import ipaddress


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

SUSPICIOUS_TLDS = [
    ".xyz",
    ".top",
    ".gq",
    ".cf",
    ".ml",
    ".tk",
    ".click",
    ".work",
    ".zip",
    ".review"
]

SHORTENERS = [
    "bit.ly",
    "tinyurl.com",
    "t.co",
    "is.gd",
    "goo.gl",
    "ow.ly",
    "buff.ly"
]


def analyze_iocs(url):
    """
    Analyze URL for Indicators of Compromise (IOC).
    """

    parsed = urlparse(url)

    domain = parsed.netloc.split(":")[0]

    findings = []

    score = 0

    # ---------------------------------------
    # HTTP
    # ---------------------------------------

    if parsed.scheme.lower() != "https":

        findings.append("Uses HTTP instead of HTTPS")

        score += 20

    # ---------------------------------------
    # IP Address
    # ---------------------------------------

    try:

        ipaddress.ip_address(domain)

        findings.append("Uses an IP address instead of a domain")

        score += 30

    except ValueError:
        pass

    # ---------------------------------------
    # Long URL
    # ---------------------------------------

    if len(url) > 75:

        findings.append("Long URL detected")

        score += 10

    # ---------------------------------------
    # @ Symbol
    # ---------------------------------------

    if "@" in url:

        findings.append("@ symbol detected")

        score += 25

    # ---------------------------------------
    # Double Slash
    # ---------------------------------------

    if "//" in parsed.path:

        findings.append("Multiple // detected")

        score += 15

    # ---------------------------------------
    # Too Many Subdomains
    # ---------------------------------------

    subdomains = max(0, len(domain.split(".")) - 2)

    if subdomains >= 2:

        findings.append("Multiple subdomains detected")

        score += 10

    # ---------------------------------------
    # Suspicious Keywords
    # ---------------------------------------

    found_keywords = []

    for keyword in SUSPICIOUS_KEYWORDS:

        if keyword in url.lower():

            found_keywords.append(keyword)

    if found_keywords:

        findings.append(
            "Suspicious keywords: " +
            ", ".join(found_keywords)
        )

        score += len(found_keywords) * 5

    # ---------------------------------------
    # Suspicious TLD
    # ---------------------------------------

    for tld in SUSPICIOUS_TLDS:

        if domain.endswith(tld):

            findings.append(f"Suspicious TLD ({tld})")

            score += 20

            break

    # ---------------------------------------
    # URL Shortener
    # ---------------------------------------

    for service in SHORTENERS:

        if service == domain:

            findings.append(
                f"URL Shortener ({service})"
            )

            score += 15

            break

    return {

        "ioc_score": score,

        "ioc_findings": findings

    }