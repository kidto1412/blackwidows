import re
import json
import posixpath
import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse
from .utils import normalize_url, is_valid_url


class JSBundleMiner:
    """
    Mines client-side JS bundles for:
    - Vite/Webpack/Rollup chunks and entry points
    - Client SPA routes
    - Backend API endpoints (e.g. /api/v1/...)
    - Hardcoded secrets, API keys, credentials, and env variables
    """

    # Secret and token patterns
    SECRET_PATTERNS = [
        ("AWS Access Key", r"\b(AKIA[0-9A-Z]{16})\b"),
        ("Firebase API Key", r"\b(AIza[0-9A-Za-z\-_]{35})\b"),
        ("Supabase URL", r"\b(https?://[a-z0-9\-]+\.supabase\.(?:co|in))\b"),
        ("Generic JWT", r"\b(eyJ[A-Za-z0-9\-_]{10,}\.[A-Za-z0-9\-_]{10,}\.[A-Za-z0-9\-_]{10,})\b"),
        ("Bearer Token", r"(?i)bearer\s+([a-zA-Z0-9\-_=\.]{20,})"),
        ("Generic Secret/Token", r"(?i)(?:api_?key|auth_?token|secret_?key|client_?secret|access_?token|private_?key)\s*[:=]\s*['\"]([a-zA-Z0-9\-_\.\/+=]{8,64})['\"]"),
        ("Stripe Publishable Key", r"\b(pk_(?:test|live)_[0-9a-zA-Z]{24,})\b"),
        ("Google OAuth Client ID", r"\b([0-9]+-[a-z0-9_]{16,32}\.apps\.googleusercontent\.com)\b"),
        ("Slack Webhook", r"\b(https://hooks\.slack\.com/services/T[a-zA-Z0-9_]+/B[a-zA-Z0-9_]+/[a-zA-Z0-9_]+)\b"),
        ("Discord Webhook", r"\b(https://discord(?:app)?\.com/api/webhooks/[0-9]+/[a-zA-Z0-9_\-]+)\b"),
    ]

    # Regex patterns for API routes and endpoints
    API_PATTERNS = [
        # Explicit relative API paths
        r"['\"](/(?:api|v[0-9]+|auth|graphql|gql|rest|oauth|internal)/[a-zA-Z0-9\-_\.\/]+)['\"]",
        # Axios/fetch calls
        r"(?:axios|client|api|http|fetch)\s*\.\s*(?:get|post|put|delete|patch)\s*\(\s*['\"\`]([^'\"`\s\)]+)['\"\`]",
        # Base URLs or endpoints inside template literals
        r"`(/[a-zA-Z0-9\-_\.\/]*\$\{[^}]+\}[a-zA-Z0-9\-_\.\/]*)`",
        # Full API URLs
        r"['\"](https?://[a-zA-Z0-9\.\-_]+(?:/[a-zA-Z0-9\-_]+)*/api(?:/[a-zA-Z0-9\-_\.\/]+)?)['\"]",
    ]

    # Client SPA route patterns (React Router, Vue Router, etc.)
    CLIENT_ROUTE_PATTERNS = [
        r"path\s*:\s*['\"](/[^'\"?#\s]*)['\"]",
        r"<Route[^>]+path=['\"](/[^'\"?#\s]*)['\"]",
        r"to\s*:\s*['\"](/[^'\"?#\s]*)['\"]",
        r"href\s*:\s*['\"](/[^'\"?#\s]*)['\"]",
        r"navigate\s*\(\s*['\"](/[^'\"?#\s]*)['\"]",
    ]

    # Noise filter
    IGNORE_EXTENSIONS = (
        ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico", ".css", ".woff",
        ".woff2", ".ttf", ".eot", ".mp4", ".webm", ".map"
    )

    IGNORE_KEYWORDS = (
        "node_modules", "schema.org", "w3.org", "google-analytics",
        "googletagmanager", "facebook.net", "sentry.io", "clarity.ms",
        "cloudflare.com", "fonts.googleapis", "gstatic.com"
    )

    def __init__(self, url, depth=2, timeout=8):
        self.url = normalize_url(url)
        self.depth = depth
        self.timeout = timeout
        self.session = requests.Session()
        self.session.headers.update({
            "User-Agent": (
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                "AppleWebKit/537.36 (KHTML, like Gecko) "
                "Chrome/120.0.0.0 Safari/537.36"
            ),
            "Accept": "*/*",
        })
        self.bundles = set()
        self.scraped_content = {}
        self.results = {
            "target": self.url,
            "bundles_analyzed": [],
            "api_endpoints": [],
            "client_routes": [],
            "secrets": [],
            "env_vars": [],
            "interesting_urls": [],
        }

    def _get(self, target_url):
        try:
            r = self.session.get(target_url, timeout=self.timeout, allow_redirects=True)
            if r.status_code == 200:
                return r
        except Exception:
            pass
        return None

    def discover_bundles(self):
        """Scrape HTML entry point to locate initial JS scripts and module preloads."""
        print(f"[*] Crawling entry HTML: {self.url}")
        r = self._get(self.url)
        if not r:
            print(f"[-] Could not reach target {self.url}")
            return set()

        soup = BeautifulSoup(r.text, "html.parser")
        discovered = set()

        # 1. Script tags
        for s in soup.find_all("script", src=True):
            src = s.get("src", "").strip()
            if src:
                full_url = urljoin(self.url, src)
                if not any(k in full_url for k in self.IGNORE_KEYWORDS):
                    discovered.add(full_url)

        # 2. Modulepreload and preload links (Vite standard)
        for link in soup.find_all("link", href=True):
            rel = link.get("rel", [])
            if isinstance(rel, str):
                rel = [rel]
            if any(r in rel for r in ["modulepreload", "preload"]):
                href = link.get("href", "").strip()
                if href.endswith(".js") or "assets/" in href:
                    full_url = urljoin(self.url, href)
                    if not any(k in full_url for k in self.IGNORE_KEYWORDS):
                        discovered.add(full_url)

        # 3. Inline scripts (store for direct analysis)
        inline_scripts = [s.get_text() for s in soup.find_all("script") if not s.get("src")]
        if inline_scripts:
            self.scraped_content["inline_html"] = "\n".join(inline_scripts)

        print(f"[+] Found {len(discovered)} initial JS bundle(s)")
        for b in sorted(discovered):
            print(f"    -> {b}")

        return discovered

    def discover_chunks(self, js_content, base_bundle_url):
        """Find dynamic chunk imports inside bundle content."""
        chunks = set()

        # Match import("./assets/...") or import("/assets/...")
        for m in re.finditer(r'import\s*\(\s*["\']([^"\'\s]+\.js[^"\'\s]*)["\']\s*\)', js_content):
            chunk_rel = m.group(1)
            chunks.add(urljoin(base_bundle_url, chunk_rel))

        # Match Vite __vitePreload or asset paths
        for m in re.finditer(r'["\'](/?assets/[a-zA-Z0-9_\.\-]+\.js)["\']', js_content):
            chunk_rel = m.group(1)
            chunks.add(urljoin(base_bundle_url, chunk_rel))

        # Match webpack chunk loading patterns
        for m in re.finditer(r'["\']([a-zA-Z0-9_\.\-]+\.chunk\.js)["\']', js_content):
            chunk_rel = m.group(1)
            chunks.add(urljoin(base_bundle_url, chunk_rel))

        return {c for c in chunks if not any(k in c for k in self.IGNORE_KEYWORDS)}

    def fetch_all_bundles(self):
        """Recursively fetch JS bundles up to configured depth."""
        pending = self.discover_bundles()
        fetched = set()
        current_depth = 0

        while pending and current_depth < self.depth:
            next_depth = set()
            for bundle_url in pending:
                if bundle_url in fetched:
                    continue
                fetched.add(bundle_url)
                r = self._get(bundle_url)
                if r and r.text:
                    content = r.text
                    self.scraped_content[bundle_url] = content
                    # Find recursive chunks
                    new_chunks = self.discover_chunks(content, bundle_url)
                    for c in new_chunks:
                        if c not in fetched:
                            next_depth.add(c)
            pending = next_depth
            current_depth += 1

        self.bundles = fetched
        print(f"[+] Total JS bundles fetched and indexed: {len(self.scraped_content)}")

    def mine_secrets(self, text, source_label):
        """Extract hardcoded tokens and credentials."""
        found = []
        for label, pattern in self.SECRET_PATTERNS:
            for match in re.finditer(pattern, text):
                val = match.group(1) if match.groups() else match.group(0)
                # Filter false positives
                if len(val) < 8 or val.lower() in ("true", "false", "undefined", "null"):
                    continue
                # Truncate overly long blocks
                cleaned_val = val[:120]
                entry = {
                    "type": label,
                    "value": cleaned_val,
                    "source": source_label,
                }
                found.append(entry)
        return found

    def mine_endpoints(self, text):
        """Extract backend API paths and full URLs."""
        endpoints = set()
        for pattern in self.API_PATTERNS:
            for m in re.finditer(pattern, text):
                ep = m.group(1)
                if not ep:
                    continue
                # Clean path
                ep = ep.strip()
                if any(ep.lower().endswith(ext) for ext in self.IGNORE_EXTENSIONS):
                    continue
                if any(k in ep for k in self.IGNORE_KEYWORDS):
                    continue
                # Reject SVG path noise (e.g. M10 20 L30 ...)
                if re.match(r"^/[MmLlHhVvCcSsQqTtAaZz0-9,\.\s-]+$", ep) and len(ep) > 20:
                    continue
                # Format check
                if ep.startswith("/") or ep.startswith("http"):
                    endpoints.add(ep)
        return endpoints

    def mine_client_routes(self, text):
        """Extract SPA client routes."""
        routes = set()
        for pattern in self.CLIENT_ROUTE_PATTERNS:
            for m in re.finditer(pattern, text):
                r = m.group(1).strip()
                if not r or r == "/" or r.startswith("//"):
                    continue
                if any(r.lower().endswith(ext) for ext in self.IGNORE_EXTENSIONS):
                    continue
                if any(k in r for k in ["http:", "https:", "data:", "blob:"]):
                    continue
                # Reject SVG or noise
                if len(r) > 60 or " " in r or "<" in r or ">" in r:
                    continue
                routes.add(r)
        return routes

    def mine_env_vars(self, text):
        """Extract referenced frontend environment variables."""
        env_pattern = r"\b((?:VITE|REACT_APP|NEXT_PUBLIC)_[A-Z0-9_]{3,})\b"
        return set(re.findall(env_pattern, text))

    def run(self):
        """Execute full mining run."""
        self.fetch_all_bundles()

        all_endpoints = set()
        all_routes = set()
        all_secrets = []
        all_envs = set()

        for source, text in self.scraped_content.items():
            # Secrets
            sec = self.mine_secrets(text, source)
            all_secrets.extend(sec)

            # API Endpoints
            eps = self.mine_endpoints(text)
            all_endpoints.update(eps)

            # Client Routes
            rts = self.mine_client_routes(text)
            all_routes.update(rts)

            # Env vars
            envs = self.mine_env_vars(text)
            all_envs.update(envs)

        # Deduplicate secrets by type and value
        seen_secrets = set()
        dedup_secrets = []
        for s in all_secrets:
            key = (s["type"], s["value"])
            if key not in seen_secrets:
                seen_secrets.add(key)
                dedup_secrets.append(s)

        # Filter client routes from API endpoints if overlap
        pure_api = sorted([e for e in all_endpoints if "api" in e or "v1" in e or "auth" in e or "graphql" in e])
        other_endpoints = sorted([e for e in all_endpoints if e not in pure_api])
        sorted_routes = sorted(list(all_routes))
        sorted_envs = sorted(list(all_envs))

        self.results = {
            "target": self.url,
            "bundles_analyzed": list(self.scraped_content.keys()),
            "api_endpoints": pure_api + other_endpoints,
            "client_routes": sorted_routes,
            "secrets": dedup_secrets,
            "env_vars": sorted_envs,
        }

        self._print_summary()
        return self.results

    def _print_summary(self):
        print("\n" + "═" * 60)
        print(" [!] JS BUNDLE MINING RESULTS")
        print("═" * 60)

        # Bundles
        print(f"\n[*] Analyzed Bundles ({len(self.results['bundles_analyzed'])}):")
        for b in self.results["bundles_analyzed"]:
            print(f"    • {b}")

        # Secrets / Keys
        print(f"\n[*] Potential Secrets & Tokens ({len(self.results['secrets'])}):")
        if self.results["secrets"]:
            for s in self.results["secrets"]:
                print(f"    [!] {s['type']:<22} : {s['value']}")
        else:
            print("    [-] None detected.")

        # Env Vars
        print(f"\n[*] Exposed Environment Variables ({len(self.results['env_vars'])}):")
        if self.results["env_vars"]:
            for ev in self.results["env_vars"]:
                print(f"    • {ev}")
        else:
            print("    [-] None detected.")

        # API Endpoints
        api_eps = self.results["api_endpoints"]
        print(f"\n[*] Mined Endpoints & Paths ({len(api_eps)}):")
        if api_eps:
            for ep in api_eps:
                print(f"    -> {ep}")
        else:
            print("    [-] None detected.")

        # Client Routes
        print(f"\n[*] Mined Client SPA Routes ({len(self.results['client_routes'])}):")
        if self.results["client_routes"]:
            for cr in self.results["client_routes"][:30]:
                print(f"    • {cr}")
            if len(self.results["client_routes"]) > 30:
                print(f"    ... and {len(self.results['client_routes']) - 30} more")
        else:
            print("    [-] None detected.")

        print("═" * 60)

    def export_wordlist(self, output_path):
        """Export mined API endpoints to a wordlist file for Stage 2 fuzzing."""
        paths = set()
        for ep in self.results.get("api_endpoints", []):
            if ep.startswith("http"):
                parsed = urlparse(ep)
                p = parsed.path
            else:
                p = ep
            # Normalize path for wordlists
            p = p.strip("/").strip()
            if p:
                paths.add(p)
                # Also add sub-segments
                parts = p.split("/")
                for i in range(1, len(parts) + 1):
                    sub = "/".join(parts[:i])
                    if sub:
                        paths.add(sub)

        with open(output_path, "w") as f:
            for p in sorted(paths):
                f.write(p + "\n")
        print(f"[+] Exported {len(paths)} endpoint paths to wordlist: {output_path}")
