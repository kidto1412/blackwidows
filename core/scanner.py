import socket
import requests
import subprocess
import shutil
import hashlib
from concurrent.futures import ThreadPoolExecutor
from urllib.parse import urlparse
from .utils import get_domain, is_valid_url, normalize_url


# ─────────────────────────── Baseline (SPA / soft-404) fingerprinter ──────

class BaselineFingerprint:
    """
    Detect the site's 'soft-404' response so we can exclude false positives.
    SPAs serve index.html (200) for every unknown route.
    We fetch two junk URLs and record size + content hash.
    Any real response that matches this baseline is a false positive.
    """
    def __init__(self, base_url, session=None):
        self.base_url = base_url.rstrip("/")
        self.session = session or requests.Session()
        self.session.headers.setdefault(
            "User-Agent",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
        )
        self.hashes: set = set()
        self.sizes: set = set()
        self.status_codes: set = set()
        self._computed = False

    def compute(self):
        junk_paths = [
            "/__blackwidow_nonexistent_path_xz9q__",
            "/this-should-404-xzqq99/abc/def",
        ]
        for path in junk_paths:
            try:
                r = self.session.get(
                    self.base_url + path, timeout=5,
                    allow_redirects=True
                )
                self.hashes.add(hashlib.md5(r.content).hexdigest())
                self.sizes.add(len(r.content))
                self.status_codes.add(r.status_code)
            except Exception:
                pass
        self._computed = True
        if self.hashes:
            print(f"[~] SPA/soft-404 baseline: status={self.status_codes} size={self.sizes}")

    def is_false_positive(self, response):
        """Return True if this response matches the soft-404 baseline."""
        if not self._computed:
            return False
        h = hashlib.md5(response.content).hexdigest()
        sz = len(response.content)
        # Match by hash (same content) OR same size within ±5 bytes (gzipped variance)
        if h in self.hashes:
            return True
        for baseline_sz in self.sizes:
            if abs(sz - baseline_sz) <= 5:
                return True
        return False


# ─────────────────────────── Port Scanner ─────────────────────────────────

class PortScanner:
    def __init__(self, target, threads=20):
        # Accept full URL or bare hostname/IP
        if target.startswith("http"):
            parsed = urlparse(target)
            self.target = parsed.hostname
        else:
            self.target = target.split(":")[0].split("/")[0]
        self.threads = threads
        self.results = []

    def scan_port(self, port):
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(1)
                result = s.connect_ex((self.target, port))
                if result == 0:
                    # Try to grab service banner
                    try:
                        service = socket.getservbyport(port)
                    except Exception:
                        service = "unknown"
                    self.results.append({"port": port, "status": "open", "service": service})
                    print(f"[+] Open: {self.target}:{port} ({service})")
        except Exception:
            pass

    def scan(self, port_range="1-1000"):
        print(f"[*] Port scan: {self.target} range={port_range}")
        if "-" in port_range:
            start, end = map(int, port_range.split("-"))
            ports = range(start, end + 1)
        else:
            ports = [int(p) for p in port_range.split(",")]

        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            for port in ports:
                executor.submit(self.scan_port, port)

        print(f"[*] Port scan complete. {len(self.results)} open ports.")


# ─────────────────────────── Dir Scanner ──────────────────────────────────

class DirScanner:
    def __init__(self, url, wordlist, threads=20, extensions=None):
        self.url = normalize_url(url)
        self.wordlist = wordlist
        self.threads = threads
        self.results = []
        self.extensions = extensions or []   # e.g. [".php", ".asp", ".bak"]

    def scan_dir(self, path):
        path = path.lstrip("/")
        targets = [f"{self.url}/{path}"]
        for ext in self.extensions:
            targets.append(f"{self.url}/{path}{ext}")

        for test_url in targets:
            try:
                r = requests.get(test_url, timeout=5, allow_redirects=False)
                if r.status_code in (200, 301, 302, 403):
                    entry = {"url": test_url, "status": r.status_code, "size": len(r.content)}
                    self.results.append(entry)
                    print(f"[+] Found: {test_url} [{r.status_code}] ({len(r.content)} bytes)")
            except Exception:
                pass

    def scan(self):
        try:
            with open(self.wordlist) as f:
                paths = f.read().splitlines()
        except FileNotFoundError:
            print(f"[-] Wordlist not found: {self.wordlist}")
            return

        print(f"[*] Dir scan: {self.url} | wordlist: {self.wordlist} ({len(paths)} entries)")
        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            for raw in paths:
                path = raw.strip()
                if not path or path.startswith("#"):
                    continue
                executor.submit(self.scan_dir, path)

        print(f"[*] Dir scan done. {len(self.results)} paths found.")


# ─────────────────────────── Ffuf / Dirsearch Integration ─────────────────

class FfufScanner:
    """Wrapper around ffuf for directory/file fuzzing."""

    def __init__(self, url, wordlist, extensions=None, threads=40, timeout=10):
        self.url = normalize_url(url)
        self.wordlist = wordlist
        self.extensions = extensions or []
        self.threads = threads
        self.timeout = timeout
        self.results = []
        self.binary = shutil.which("ffuf")

    def available(self):
        return self.binary is not None

    def run(self, output_file="reports/ffuf_output.json"):
        if not self.available():
            print("[-] ffuf not found in PATH. Falling back to internal DirScanner.")
            return False

        import os
        os.makedirs("reports", exist_ok=True)
        fuzz_url = f"{self.url}/FUZZ"
        cmd = [
            self.binary,
            "-u", fuzz_url,
            "-w", self.wordlist,
            "-t", str(self.threads),
            "-timeout", str(self.timeout),
            "-o", output_file,
            "-of", "json",
            "-mc", "200,201,204,301,302,307,401,403,405,500",
            "-c",        # colorize
            "-v",
        ]
        if self.extensions:
            cmd += ["-e", ",".join(self.extensions)]

        print(f"[*] Running ffuf: {' '.join(cmd)}")
        try:
            result = subprocess.run(cmd, capture_output=False, text=True)
            if result.returncode == 0:
                print(f"[+] ffuf output: {output_file}")
                return True
        except Exception as e:
            print(f"[-] ffuf error: {e}")
        return False


class DirsearchScanner:
    """Wrapper around dirsearch for directory enumeration."""

    def __init__(self, url, wordlist=None, extensions=None, threads=20):
        self.url = normalize_url(url)
        self.wordlist = wordlist
        self.extensions = extensions or ["php", "html", "js", "txt", "bak"]
        self.threads = threads
        self.binary = shutil.which("dirsearch")

    def available(self):
        return self.binary is not None

    def run(self, output_file="reports/dirsearch_output.txt"):
        if not self.available():
            print("[-] dirsearch not found in PATH.")
            return False

        import os
        os.makedirs("reports", exist_ok=True)
        cmd = [
            self.binary,
            "-u", self.url,
            "-t", str(self.threads),
            "-o", output_file,
            "--format", "plain",
            "-e", ",".join(self.extensions),
            "--no-color",
        ]
        if self.wordlist:
            cmd += ["-w", self.wordlist]

        print(f"[*] Running dirsearch: {' '.join(cmd)}")
        try:
            result = subprocess.run(cmd, capture_output=False, text=True)
            if result.returncode == 0:
                print(f"[+] dirsearch output: {output_file}")
                return True
        except Exception as e:
            print(f"[-] dirsearch error: {e}")
        return False


# ─────────────────────────── Subdomain Scanner ────────────────────────────

class SubdomainScanner:
    def __init__(self, domain, wordlist, threads=20):
        self.domain = get_domain(domain)
        self.wordlist = wordlist
        self.threads = threads
        self.results = []

    def scan_subdomain(self, subdomain):
        subdomain = subdomain.strip()
        if not subdomain or subdomain.startswith("#"):
            return
        host = f"{subdomain}.{self.domain}"
        for scheme in ("https", "http"):
            url = f"{scheme}://{host}"
            try:
                r = requests.get(url, timeout=5, allow_redirects=True)
                if r.status_code < 500:
                    self.results.append({
                        "subdomain": host,
                        "url": url,
                        "status": r.status_code,
                        "title": self._extract_title(r.text),
                    })
                    print(f"[+] Subdomain: {url} [{r.status_code}]")
                    return  # found on https, skip http
            except Exception:
                continue

    @staticmethod
    def _extract_title(html):
        try:
            from bs4 import BeautifulSoup
            soup = BeautifulSoup(html[:4096], "html.parser")
            t = soup.find("title")
            return t.text.strip() if t else ""
        except Exception:
            return ""

    def scan(self):
        try:
            with open(self.wordlist) as f:
                subdomains = f.read().splitlines()
        except FileNotFoundError:
            print(f"[-] Wordlist not found: {self.wordlist}")
            return

        print(f"[*] Subdomain enum: {self.domain} | {len(subdomains)} candidates")
        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            for sub in subdomains:
                executor.submit(self.scan_subdomain, sub)

        print(f"[*] Subdomain scan done. {len(self.results)} found.")
