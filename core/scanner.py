import socket
import requests
from concurrent.futures import ThreadPoolExecutor
from urllib.parse import urlparse
from .utils import get_domain, is_valid_url

class PortScanner:
    def __init__(self, target, threads=20):
        self.target = target
        self.threads = threads
        self.results = []

    def scan_port(self, port):
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(1)
                result = s.connect_ex((self.target, port))
                if result == 0:
                    self.results.append({"port": port, "status": "open"})
                    print(f"[+] Open: {self.target}:{port}")
        except:
            pass

    def scan(self, port_range="1-1000"):
        if "-" in port_range:
            start, end = map(int, port_range.split("-"))
            ports = range(start, end + 1)
        else:
            ports = map(int, port_range.split(","))

        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            for port in ports:
                executor.submit(self.scan_port, port)

class DirScanner:
    def __init__(self, url, wordlist, threads=20):
        self.url = url.rstrip("/")
        self.wordlist = wordlist
        self.threads = threads
        self.results = []

    def scan_dir(self, path):
        test_url = f"{self.url}/{path}"
        try:
            r = requests.get(test_url, timeout=5, allow_redirects=False)
            if r.status_code in [200, 301, 302, 403]:
                self.results.append({"url": test_url, "status": r.status_code})
                print(f"[+] Found: {test_url} ({r.status_code})")
        except:
            pass

    def scan(self):
        with open(self.wordlist) as f:
            paths = f.read().splitlines()

        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            for path in paths:
                executor.submit(self.scan_dir, path)

class SubdomainScanner:
    def __init__(self, domain, wordlist, threads=20):
        self.domain = get_domain(domain)
        self.wordlist = wordlist
        self.threads = threads
        self.results = []

    def scan_subdomain(self, subdomain):
        url = f"http://{subdomain}.{self.domain}"
        try:
            r = requests.get(url, timeout=5)
            if r.status_code < 400:
                self.results.append({"subdomain": f"{subdomain}.{self.domain}", "status": r.status_code})
                print(f"[+] Found: {url} ({r.status_code})")
        except:
            pass

    def scan(self):
        with open(self.wordlist) as f:
            subdomains = f.read().splitlines()

        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            for subdomain in subdomains:
                executor.submit(self.scan_subdomain, subdomain)
