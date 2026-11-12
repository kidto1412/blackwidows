#!/usr/bin/env python3
import argparse
import json
import os
import sys
from core.scanner import PortScanner, DirScanner, SubdomainScanner
from core.exploit import SQLiScanner, XSSScanner, WPScanner
from core.brute import BruteForcer
from core.utils import banner, save_report

def load_targets():
    if os.path.exists("config/targets.json"):
        with open("config/targets.json") as f:
            return json.load(f)
    return {"targets": []}

def save_target(url, name=None):
    targets = load_targets()
    targets["targets"].append({"url": url, "name": name or url})
    os.makedirs("config", exist_ok=True)
    with open("config/targets.json", "w") as f:
        json.dump(targets, f, indent=2)
    print(f"[+] Saved target: {url}")

def setup_detect_parser(subparsers):
    parser = subparsers.add_parser("detect", help="Detect frontend tech and map to wordlist")
    parser.add_argument("-u", "--url", required=True, help="Target URL to analyze")
    parser.add_argument("--auto-scan", action="store_true", help="Auto-scan with mapped wordlist")
    return parser

def main():
    parser = argparse.ArgumentParser(
        description="BlackWidow - All-in-One Web Hacking Toolkit",
        formatter_class=argparse.RawTextHelpFormatter,
        epilog="""Examples:
  python3 blackwidow.py scan -u example.com --full
  python3 blackwidow.py exploit -u example.com --sqli --xss
  python3 blackwidow.py brute -u example.com/login --users users.txt --passwords «redacted-secret»
  python3 blackwidow.py report --export html
        """
    )

    subparsers = parser.add_subparsers(dest="command", required=True)

    # SCAN COMMAND
    scan_parser = subparsers.add_parser("scan", help="Scan targets")
    scan_parser.add_argument("-u", "--url", help="Target URL")
    scan_parser.add_argument("--ports", help="Port range (e.g., 1-1000)")
    scan_parser.add_argument("--dirs", action="store_true", help="Directory brute force")
    scan_parser.add_argument("--subdomains", action="store_true", help="Subdomain enumeration")
    scan_parser.add_argument("--full", action="store_true", help="Full scan (ports + dirs + subdomains)")
    scan_parser.add_argument("-t", "--threads", type=int, default=20, help="Threads (default: 20)")
    scan_parser.add_argument("-w", "--wordlist", help="Custom wordlist path")
    scan_parser.add_argument("-f", "--framework", choices=[
        "wordpress", "laravel", "java-spring", "dotnet", "nextjs", "django"
    ], help="Use wordlists/framework/<name>.txt for directory scanning")

    # EXPLOIT COMMAND
    exploit_parser = subparsers.add_parser("exploit", help="Exploit vulnerabilities")
    exploit_parser.add_argument("-u", "--url", required=True, help="Target URL")
    exploit_parser.add_argument("--sqli", action="store_true", help="SQL Injection scan")
    exploit_parser.add_argument("--xss", action="store_true", help="XSS scan")
    exploit_parser.add_argument("--wp", action="store_true", help="WordPress scan")
    exploit_parser.add_argument("--cms", action="store_true", help="CMS detection")

    # BRUTE COMMAND
    brute_parser = subparsers.add_parser("brute", help="Brute force attacks")
    brute_parser.add_argument("-u", "--url", required=True, help="Target URL (e.g., http://example.com/login)")
    brute_parser.add_argument("--users", help="Username wordlist")
    brute_parser.add_argument("--passwords", help="Password wordlist")  # FIXED: Changed from --pass to --passwords
    brute_parser.add_argument("--form", help="Form data (e.g., 'user={}&pass={}')")
    brute_parser.add_argument("-t", "--threads", type=int, default=10, help="Threads (default: 10)")

    # REPORT COMMAND
    report_parser = subparsers.add_parser("report", help="Generate reports")
    report_parser.add_argument("--export", help="Export format (txt, json, html)")
    report_parser.add_argument("--output", help="Output file path")

    # TARGETS COMMAND
    targets_parser = subparsers.add_parser("targets", help="Manage targets")
    targets_parser.add_argument("--add", help="Add target URL")
    targets_parser.add_argument("--list", action="store_true", help="List saved targets")
    targets_parser.add_argument("--name", help="Target name")

    # DETECT COMMAND
    setup_detect_parser(subparsers)

    args = parser.parse_args()

    if args.command == "scan":
        banner()
        if args.full:
            args.ports = "1-1000"
            args.dirs = True
            args.subdomains = True

        if args.ports:
            scanner = PortScanner(args.url, threads=args.threads)
            scanner.scan(port_range=args.ports)
            save_report(scanner.results, "port_scan")

        if args.dirs:
            if args.framework:
                fw_map = {
                    "wordpress": "wordlists/framework/wordpress.txt",
                    "laravel": "wordlists/framework/laravel.txt",
                    "java-spring": "wordlists/framework/java-spring.txt",
                    "dotnet": "wordlists/framework/dotnet.txt",
                    "nextjs": "wordlists/framework/nextjs.txt",
                    "django": "wordlists/framework/django.txt",
                }
                wordlist = fw_map[args.framework]
            else:
                wordlist = args.wordlist or "wordlists/common_dirs.txt"
            scanner = DirScanner(args.url, wordlist, threads=args.threads)
            scanner.scan()
            save_report(scanner.results, "dir_scan")

        if args.subdomains:
            wordlist = args.wordlist or "wordlists/subdomains.txt"
            scanner = SubdomainScanner(args.url, wordlist, threads=args.threads)
            scanner.scan()
            save_report(scanner.results, "subdomain_scan")

    elif args.command == "exploit":
        banner()
        if args.sqli:
            scanner = SQLiScanner(args.url)
            scanner.scan()
            save_report(scanner.vulnerabilities, "sqli_scan")

        if args.xss:
            scanner = XSSScanner(args.url)
            scanner.scan()
            save_report(scanner.vulnerabilities, "xss_scan")

        if args.wp:
            scanner = WPScanner(args.url)
            scanner.scan()
            save_report(scanner.vulnerabilities, "wp_scan")

    elif args.command == "brute":
        banner()
        forcer = BruteForcer(
            args.url,
            users=args.users,
            passwords=args.passwords,  # FIXED: Changed from args.pass to args.passwords
            form=args.form,
            threads=args.threads
        )
        forcer.attack()
        save_report(forcer.results, "brute_force")

    elif args.command == "report":
        banner()
        if args.export:
            from core.report import export_report
            export_report(args.export, args.output)

    elif args.command == "targets":
        banner()
        if args.add:
            save_target(args.add, args.name)
        if args.list:
            targets = load_targets()
            for i, target in enumerate(targets["targets"], 1):
                print(f"{i}. {target['name'] or target['url']} ({target['url']})")

    elif args.command == "detect":
        cmd_detect(args)

if __name__ == "__main__":
    main()


def detect_frontend(url):
    """Detect frontend tech from a URL and return mapping.

    Returns a dict with:
    - framework: detected framework name
    - wordlist: path to wordlist to use
    - description: human-readable description
    - frontend_only: bool (True if frontend-only, no backend detected)
    - backend: backend framework (if known)
    """
    import requests
    try:
        r = requests.get(url, timeout=5, allow_redirects=False)
        content_type = r.headers.get('content-type', '')
        if 'html' not in content_type and 'text' not in content_type:
            return None, None

        import re
        html = r.text.lower()

        # Signature matching - separate frontend and backend frameworks
        # Backend frameworks (these have attack surfaces we target)
        backend_signatures = {
            'wordpress': ['/wp-admin/', '/wp-login.php', '/wp-includes/', 'wp-content', 'wp-generator'],
            'laravel': ['/.env', '/artisan', '/public/index.php', 'laravel'],
            'java-spring': ['/actuator/health', '/actuator/info', '/error/', '/.git/config'],
            'dotnet': ['/web.config', '/appsettings.json', '/bin/', '/.aspx', 'microsoft.aspnetcore'],
            'django': ['/static/admin/', '/admin/login/', '/media/', 'django-admin', 'django'],
        }

        # Frontend frameworks (these are client-side, but may imply a backend)
        frontend_signatures = {
            # Full-stack frameworks (have server-side routes)
            'nextjs': ['/_next/static/', '/_next/data/', '/_next/', 'next/link', 'next/image'],
            'nuxt': ['/nuxt/', '/_nuxt/', '/__nuxt_error', 'nuxt', '.nuxt/'],
            'sveltekit': ['/__svelte/', '/__svelte/env', 'sveltekit', 'src/routes/'],
            # Frontend-only frameworks
            'vue': ['/assets/vue/', 'vue-class-component', 'vuex', 'vue-router'],
            'react': ['/assets/react/', 'react-dom', 'react-router', 'createelement'],
            'angular': ['/assets/angular/', 'ng-', 'ng-app', 'angular/'],
        }

        # Find best backend match
        best_backend = None
        best_backend_score = 0
        for fw, patterns in backend_signatures.items():
            score = 0
            for p in patterns:
                if p in html:
                    score += 1
            if score > best_backend_score:
                best_backend_score = score
                best_backend = fw

        # Find best frontend match
        best_frontend = None
        best_frontend_score = 0
        for fw, patterns in frontend_signatures.items():
            score = 0
            for p in patterns:
                if p in html:
                    score += 1
            if score > best_frontend_score:
                best_frontend_score = score
                best_frontend = fw

        # Build result
        result = {
            'framework': None,
            'wordlist': None,
            'frontend_only': True,
            'backend': None,
            'description': '',
        }

        # Check for backend frameworks first
        if best_backend:
            result['wordlist'] = f'wordlists/framework/{best_backend}.txt'
            result['frontend_only'] = False
            result['backend'] = best_backend
            result['description'] = f"Backend: {best_backend}"
            return result

        # Check for frontend frameworks
        if best_frontend:
            if best_frontend == 'nextjs':
                result['wordlist'] = 'wordlists/framework/nextjs.txt'
                result['frontend_only'] = False
                result['backend'] = 'node.js'
                result['description'] = 'Next.js full-stack React framework (SSR/SSG)'
            elif best_frontend == 'nuxt':
                result['wordlist'] = 'wordlists/framework/nextjs.txt'
                result['frontend_only'] = False
                result['backend'] = 'node.js'
                result['description'] = 'Nuxt.js Vue-based full-stack framework'
            elif best_frontend == 'sveltekit':
                result['wordlist'] = 'wordlists/framework/nextjs.txt'
                result['frontend_only'] = False
                result['backend'] = 'node.js'
                result['description'] = 'SvelteKit full-stack Svelte framework'
            elif best_frontend == 'vue':
                result['frontend_only'] = True
                result['description'] = 'Vue.js frontend framework detected. No backend determined.'
            elif best_frontend == 'react':
                result['frontend_only'] = True
                result['description'] = 'React frontend framework detected. Determine backend separately.'
            elif best_frontend == 'angular':
                result['frontend_only'] = True
                result['description'] = 'Angular frontend framework detected. Determine backend separately.'
            result['framework'] = best_frontend
            return result

        # No match found
        result['description'] = 'No matching signatures found - check if target is a custom app'
        return result

    except Exception as e:
        return None, None, str(e)


def cmd_detect(args):
    """Detect frontend tech from a URL."""
    print(f"\n[fw] Analyzing {args.url}...\n")
    result = detect_frontend(args.url)

    if not result:
        print(f"[fw] Could not detect framework from URL")
        if args.auto_scan:
            print("[-] Skipping scan, no framework detected")
        return

    fw = result.get('framework', 'unknown')
    wordlist = result.get('wordlist', '')
    frontend_only = result.get('frontend_only', True)
    backend = result.get('backend', None)
    description = result.get('description', '')

    print(f"[fw] Frontend tech detected: {fw}")
    if wordlist:
        print(f"[fw] Wordlist: {wordlist}")
    print(f"[fw] Use: python3 blackwidow.py scan -u {args.url} --full -f {fw}")

    # Show backend info if separate API domain is suspected
    if frontend_only and backend:
        print(f"\n[fw] Note: Frontend-only framework ({fw}) detected.")
        print(f"[fw] No backend found on this domain. Check if the API is hosted on a separate domain, e.g., {args.url}/api")
        print(f"[fw] If backend is on a separate domain (e.g., api.example.com), run detect against that domain.")

    if args.auto_scan:
        import subprocess
        cmd = ['python3', 'blackwidow.py', 'scan', '-u', args.url, '--full', '-f', fw]
        print(f"\n[fw] Auto-scanning with {fw} wordlist...")
        print(f"[fw] Command: {' '.join(cmd)}")
        subprocess.run(cmd)


def setup_detect_parser(subparsers):
    parser = subparsers.add_parser("detect", help="Detect frontend tech and map to wordlist")
    parser.add_argument("-u", "--url", required=True, help="Target URL to analyze")
    parser.add_argument("--auto-scan", action="store_true", help="Auto-scan with mapped wordlist")
    return parser
