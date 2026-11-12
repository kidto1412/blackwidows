import re
import json
from urllib.parse import urlparse

def banner():
    print(r"""
     ____
    |  _ \| | ___ | |  \ \    __ / _| __  | | | |   _ __
    | |) | |/  \| __|  \ \ | ' \ | /  || ' \| |/  | '|
    | ./| | () | |    \ \| | | || (| || | | | | (| | |
    ||   ||\___/ \__|    \\| |_|  \__,||| |||\__,||

    """)

def is_valid_url(url):
    try:
        result = urlparse(url)
        return all([result.scheme, result.netloc])
    except:
        return False

def get_domain(url):
    parsed = urlparse(url)
    domain = parsed.netloc
    if domain.startswith("www."):
        domain = domain[4:]
    return domain

def save_report(data, name):
    with open(f"reports/{name}.json", "w") as f:
        json.dump(data, f, indent=2)
    print(f"[+] Report saved: reports/{name}.json")
