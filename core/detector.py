import re
import json
import requests
from urllib.parse import urljoin, urlparse
from .utils import normalize_url


# ─────────────────────────── JS Bundle Signatures ─────────────────────────

JS_FRAMEWORK_SIGS = {
    "React": [
        "react.transitional.element", "symbol.for(`react.", "__reactFiber",
        "isReactComponent", "createRoot", "createElement", "useEffect", "useState",
        "ReactDOM", "react-dom", "_jsx", "jsxs(", "jsxDEV(",
    ],
    "Vue.js": [
        "__vue_component__", "createApp", "defineComponent", "__vueParentComponent",
        "vue-router", "ref(", "reactive(", "computed(", "v-model",
    ],
    "Angular": [
        "platformBrowserDynamic", "NgModule", "Component({", "Injectable({",
        "@angular/core", "zone.js",
    ],
    "Svelte": [
        "__svelte", "SvelteComponent", "create_fragment", "mount(component",
    ],
    "Next.js": [
        "__NEXT_DATA__", "/_next/", "next/router", "next/link", "NextJS",
    ],
    "Nuxt.js": [
        "__nuxt", "nuxtApp", "useNuxtApp", "/_nuxt/",
    ],
    "Vite": [
        "modulepreload", "import.meta.env", "import.meta.hot", "@vite/client",
        "vite/modulepreload-polyfill",
    ],
    "Webpack": [
        "__webpack_require__", "__webpack_exports__", "webpackChunk",
    ],
}

JS_BACKEND_SIGS = {
    "Node.js + Express": [
        "X-Powered-By: Express",           # from headers, injected as fake pattern
        '"error":"Not Found"',             # Express/NestJS 404
        '"statusCode":404',                # NestJS
        'Cannot GET /',                    # Express default 404
    ],
    "NestJS": [
        '"statusCode":401', '"statusCode":404',
        '"message":"Unauthorized"',
        '"error":"Not Found"',
        '"statusCode":',
    ],
    "Laravel": [
        "laravel_session", "X-Powered-By: PHP",
        "XSRF-TOKEN", "\"exception\":",
    ],
    "Django": [
        "csrftoken", "X-Frame-Options: SAMEORIGIN",
        "Django", "CSRF verification failed",
    ],
    "FastAPI / Python": [
        '"detail":"Not Found"', '"detail":',
        "FastAPI", "Starlette",
    ],
    "Flask": [
        "Werkzeug", "flask.pocoo.org",
        "X-Powered-By: Werkzeug",
    ],
    "Ruby on Rails": [
        "X-Runtime", "X-Request-Id",
        "ActionDispatch", "Rack",
    ],
    "Spring Boot": [
        '"timestamp":', '"status":404,',
        '"error":"Not Found"', 'WhitelabelError',
    ],
    "ASP.NET Core": [
        "X-Powered-By: ASP.NET",
        "X-AspNet-Version", "__RequestVerificationToken",
    ],
    "Supabase (BaaS)": [
        "supabase.co", "supabase.io",
        "sb-access-token",
    ],
    "Firebase (BaaS)": [
        "firebase", "firebaseapp.com",
        "firestore", "__session",
    ],
}

# Backend paths to probe — if they respond with JSON 4xx (not HTML) the backend is live
BACKEND_PROBE_PATHS = [
    "/api/v1", "/api/v1/", "/api/v2", "/api/",
    "/api/v1/items", "/api/v1/users", "/api/v1/me",
    "/api/v1/auth/me", "/api/v1/auth/login",
    "/api/v1/health", "/api/v1/status", "/api/v1/ping",
    "/api/health", "/api/status", "/api/ping",
    "/graphql", "/gql",
    "/actuator/health",          # Spring Boot
    "/swagger.json", "/openapi.json", "/api-docs",
    "/swagger/index.html", "/swagger-ui/",
]

# NestJS/Express canonical 404 — definitive backend fingerprint
NESTJS_404_PATTERN = re.compile(r'"message":"Cannot (GET|POST|PUT|DELETE|PATCH) /[^"]*","error":"Not Found","statusCode":404')
GENERIC_JSON_404 = re.compile(r'"(error|detail|message)":\s*"[^"]*"')


# ─────────────────────────── Main Detector ────────────────────────────────

class FrameworkDetector:
    def __init__(self, url, timeout=8):
        self.url = normalize_url(url)
        self.timeout = timeout
        self.session = requests.Session()
        self.session.headers.update({
            "User-Agent": (
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                "AppleWebKit/537.36 (KHTML, like Gecko) "
                "Chrome/120.0.0.0 Safari/537.36"
            ),
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.9",
        })

    def _get(self, url, json_accept=False):
        try:
            hdrs = {"Accept": "application/json"} if json_accept else {}
            return self.session.get(url, timeout=self.timeout, allow_redirects=True, headers=hdrs)
        except Exception:
            return None

    # ── 1. Fetch page HTML + headers ──────────────────────────────────────
    def _analyze_html_headers(self, r, evidence):
        html = r.text.lower()
        hdrs = {k.lower(): v for k, v in r.headers.items()}

        result = {}

        # Cloudflare detection
        if "cloudflare" in hdrs.get("server", "").lower() or "cf-ray" in hdrs:
            result["CDN"] = {"name": "Cloudflare", "evidence": ["header:server=cloudflare", "header:cf-ray"]}

        # Server header
        server = r.headers.get("Server", r.headers.get("server", ""))
        xpb = r.headers.get("X-Powered-By", r.headers.get("x-powered-by", ""))

        # WordPress
        if any(p in html for p in ["/wp-content/", "/wp-includes/", "wp-login"]):
            result["WordPress"] = {"name": "WordPress", "evidence": ["html:wp-content"]}
        meta_gen = re.search(r'<meta[^>]+name=["\']?generator["\']?[^>]+content=["\']?([^"\'>\s]+)', r.text, re.I)
        if meta_gen:
            gen = meta_gen.group(1).lower()
            for fw in ["wordpress", "joomla", "drupal", "ghost"]:
                if fw in gen:
                    result[fw.capitalize()] = {"name": fw.capitalize(), "evidence": [f"meta:generator={meta_gen.group(1)}"]}

        # div#root or div#app → SPA
        if re.search(r'<div\s+id=["\']?(root|app)["\']?', r.text, re.I):
            evidence.append("html:div#root → SPA")

        # Google Fonts
        if "fonts.googleapis.com" in r.text:
            result["Google Font API"] = {"name": "Google Font API", "evidence": ["html:fonts.googleapis.com"]}

        # Lucide icons in HTML (unlikely, but just in case)
        if "lucide" in html:
            result["Lucide Icons"] = {"name": "Lucide Icons", "evidence": ["html:lucide"]}

        return result, server, xpb, hdrs

    # ── 2. Fetch JS bundle(s) and analyze ─────────────────────────────────
    def _analyze_js_bundles(self, r):
        result = {}
        api_base = None

        js_srcs = re.findall(r'<script[^>]+src=["\']([^"\']+)["\']', r.text, re.IGNORECASE)
        all_js_content = ""

        for src in js_srcs[:5]:
            js_url = urljoin(self.url, src)
            jr = self._get(js_url)
            if jr and jr.status_code == 200:
                chunk = jr.text
                all_js_content += chunk

        if not all_js_content:
            return result, api_base

        # Score each frontend framework
        for fw, patterns in JS_FRAMEWORK_SIGS.items():
            hits = [p for p in patterns if p in all_js_content]
            if hits:
                result[fw] = {"name": fw, "evidence": [f"js:{h[:40]}" for h in hits[:5]], "score": len(hits)}

        # Extract axios/fetch baseURL
        base_match = re.search(r'baseURL\s*[=:]\s*["`\']([^`\'"]+)["`\']', all_js_content)
        if base_match:
            api_base = base_match.group(1)

        # Also look for hardcoded API domains
        api_domains = re.findall(r'https?://[a-zA-Z0-9._-]+\.[a-zA-Z]{2,}(?:/api/[^\s"\'>]*)?', all_js_content)
        # Filter for interesting ones
        interesting = [u for u in api_domains if any(k in u for k in ["api", "supabase", "firebase", "neon", "planetscale"])]
        if interesting:
            result["External API"] = {"name": "External API", "evidence": list(set(interesting))[:5], "score": 1}

        # Supabase / Firebase BaaS
        if "supabase.co" in all_js_content or "supabase.io" in all_js_content:
            result["Supabase"] = {"name": "Supabase (BaaS)", "evidence": ["js:supabase.co"], "score": 10}
        if "firebase" in all_js_content.lower() and "firebaseapp.com" in all_js_content:
            result["Firebase"] = {"name": "Firebase (BaaS)", "evidence": ["js:firebaseapp.com"], "score": 10}

        return result, api_base

    # ── 3. Probe backend API paths ────────────────────────────────────────
    def _probe_backend(self, api_base=None):
        result = {}
        live_endpoints = []

        # Build probe list — custom baseURL first if found
        probes = list(BACKEND_PROBE_PATHS)
        if api_base and api_base.startswith("/"):
            # inject discovered base into probe list
            custom = [
                api_base, api_base + "/",
                api_base + "/health", api_base + "/status",
                api_base + "/me", api_base + "/users",
                api_base + "/auth/me", api_base + "/auth/login",
                api_base + "/items",
            ]
            probes = custom + probes

        for path in probes:
            full_url = urljoin(self.url, path)
            r = self._get(full_url, json_accept=True)
            if not r:
                continue

            ct = r.headers.get("Content-Type", "").lower()
            is_json = "application/json" in ct
            xpb = r.headers.get("X-Powered-By", r.headers.get("x-powered-by", ""))
            body = r.text[:300] if r.text else ""

            # Only care about JSON responses — means real backend
            if not is_json and r.status_code == 404:
                continue

            if r.status_code in (200, 401, 403, 405) or (is_json and r.status_code == 404):
                entry = {
                    "path": path,
                    "status": r.status_code,
                    "content_type": ct,
                    "x_powered_by": xpb,
                    "body": body,
                }
                live_endpoints.append(entry)

                # Backend fingerprint from X-Powered-By
                if "express" in xpb.lower():
                    result["Express"] = {"name": "Node.js + Express", "evidence": [f"header:X-Powered-By=Express @ {path}"], "score": 10}
                if "php" in xpb.lower():
                    result["PHP"] = {"name": "PHP", "evidence": [f"header:X-Powered-By={xpb}"], "score": 8}
                if "asp.net" in xpb.lower():
                    result["ASP.NET"] = {"name": "ASP.NET Core", "evidence": [f"header:X-Powered-By={xpb}"], "score": 10}

                # NestJS fingerprint — very specific error format
                if NESTJS_404_PATTERN.search(body):
                    result["NestJS"] = {"name": "NestJS (Node.js)", "evidence": [f"json:NestJS 404 format @ {path}"], "score": 15}

                # FastAPI fingerprint
                if '"detail":' in body and r.status_code in (401, 404, 422):
                    result["FastAPI"] = {"name": "FastAPI (Python)", "evidence": [f"json:detail field @ {path}"], "score": 8}

                # Spring Boot fingerprint
                if '"timestamp":' in body and '"status":' in body and '"error":' in body:
                    result["SpringBoot"] = {"name": "Spring Boot (Java)", "evidence": [f"json:Spring error format @ {path}"], "score": 10}

        return result, live_endpoints

    # ── Main entry ────────────────────────────────────────────────────────
    def detect(self):
        r = self._get(self.url)
        if not r:
            return {"error": f"Could not connect to {self.url}"}

        evidence_log = []
        all_frameworks = {}

        # 1. HTML + headers
        html_result, server, xpb, hdrs = self._analyze_html_headers(r, evidence_log)
        all_frameworks.update(html_result)

        # 2. JS bundles
        js_result, api_base = self._analyze_js_bundles(r)
        all_frameworks.update(js_result)

        # 3. Backend probe
        backend_result, live_endpoints = self._probe_backend(api_base)
        all_frameworks.update(backend_result)

        # Sort by score
        scored = sorted(
            [{"name": v["name"], "evidence": v["evidence"], "score": v.get("score", len(v["evidence"]))}
             for v in all_frameworks.values()],
            key=lambda x: x["score"],
            reverse=True,
        )

        # Best non-CDN match for wordlist
        non_cdn = [f for f in scored if f["name"] not in ("Cloudflare", "Google Font API", "Lucide Icons", "External API")]
        top = non_cdn[0] if non_cdn else (scored[0] if scored else None)

        # Map to wordlist
        wl_map = {
            "React": "wordlists/framework/common.txt",
            "Vue.js": "wordlists/framework/common.txt",
            "Angular": "wordlists/framework/common.txt",
            "Next.js": "wordlists/framework/nextjs.txt",
            "Nuxt.js": "wordlists/framework/nuxt.txt",
            "SvelteKit": "wordlists/framework/sveltekit.txt",
            "WordPress": "wordlists/framework/wordpress.txt",
            "Laravel": "wordlists/framework/laravel.txt",
            "Django": "wordlists/framework/django.txt",
            "ASP.NET Core": "wordlists/framework/dotnet.txt",
            "NestJS (Node.js)": "wordlists/framework/common.txt",
            "Node.js + Express": "wordlists/framework/common.txt",
            "FastAPI (Python)": "wordlists/framework/common.txt",
        }

        return {
            "url": self.url,
            "final_url": r.url,
            "status": r.status_code,
            "server": server,
            "x_powered_by": xpb,
            "frameworks": scored,
            "top": {**top, "wordlist": wl_map.get(top["name"], "wordlists/framework/common.txt")} if top else None,
            "api_base": api_base,
            "live_api_endpoints": live_endpoints,
            "raw_headers": dict(r.headers),
        }
