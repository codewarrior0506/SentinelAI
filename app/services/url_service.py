from urllib.parse import urlparse


def validate_url(url):

    parsed = urlparse(url)

    if parsed.scheme and parsed.netloc:
        return True

    return False