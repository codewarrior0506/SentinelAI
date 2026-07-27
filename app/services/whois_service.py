import whois
from datetime import datetime, timezone


def get_domain_info(domain):
    """
    Retrieve WHOIS information for a domain.

    Returns:
        {
            "success": bool,
            "creation_date": datetime | None,
            "expiration_date": datetime | None,
            "registrar": str | None,
            "domain_age": int | None
        }
    """

    try:
        w = whois.whois(domain)

        creation_date = w.creation_date
        expiration_date = w.expiration_date
        registrar = w.registrar

        # Some WHOIS servers return lists
        if isinstance(creation_date, list):
            creation_date = creation_date[0]

        if isinstance(expiration_date, list):
            expiration_date = expiration_date[0]

        domain_age = None

        if isinstance(creation_date, datetime):

            # Convert naive datetime to UTC
            if creation_date.tzinfo is None:
                creation_date = creation_date.replace(tzinfo=timezone.utc)

            domain_age = (
                datetime.now(timezone.utc) - creation_date
            ).days

        return {
            "success": True,
            "creation_date": creation_date,
            "expiration_date": expiration_date,
            "registrar": registrar,
            "domain_age": domain_age
        }

    except Exception as e:
        print(f"[WHOIS ERROR] {domain}: {e}")

        return {
            "success": False,
            "creation_date": None,
            "expiration_date": None,
            "registrar": None,
            "domain_age": None
        }