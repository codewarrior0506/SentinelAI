from app.services.whois_service import get_domain_info

info = get_domain_info("google.com")

print(info)