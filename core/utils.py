import re
import json
import os
from urllib.parse import urlparse


def banner():
    print(r"""
 ____  _            _    __        ___     _
| __ )| | __ _  ___| | __\ \      / (_) __| | _____      __
|  _ \| |/ _` |/ __| |/ / \ \ /\ / /| |/ _` |/ _ \ \ /\ / /
| |_) | | (_| | (__|   <   \ V  V / | | (_| | (_) \ V  V /
|____/|_|\__,_|\___|_|\_\   \_/\_/  |_|\__,_|\___/ \_/\_/

    BlackWidow — All-in-One Web Hacking Toolkit
    """)


def is_valid_url(url):
    try:
        result = urlparse(url)
        return all([result.scheme, result.netloc])
    except Exception:
        return False


def normalize_url(url):
    """Add http:// if scheme is missing."""
    if not url.startswith(("http://", "https://")):
        url = "http://" + url
    return url.rstrip("/")


def get_domain(url):
    url = normalize_url(url)
    parsed = urlparse(url)
    domain = parsed.netloc
    if not domain:
        domain = url.split("/")[0]
    if domain.startswith("www."):
        domain = domain[4:]
    return domain


def save_report(data, name):
    os.makedirs("reports", exist_ok=True)
    path = f"reports/{name}.json"
    with open(path, "w") as f:
        json.dump(data, f, indent=2)
    print(f"[+] Report saved: {path}")
