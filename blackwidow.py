#!/usr/bin/env python3
import argparse
import json
import os
import sys

from core.scanner import PortScanner, DirScanner, SubdomainScanner, FfufScanner, DirsearchScanner
from core.exploit import (
    SQLiScanner, XSSScanner, WPScanner,
    IDORScanner, AuthBypassScanner, SSRFScanner,
    SessionScanner, CredentialHarvester,
    HashIdentifier, DefacementDetector,
)
from core.brute import BruteForcer
from core.utils import banner, save_report, normalize_url
from core.detector import FrameworkDetector


# ─────────────────────────── Targets ──────────────────────────────────────

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



def cmd_detect(args):
    print(f"\n[fw] Deep-scanning {args.url} ...\n")
    detector = FrameworkDetector(args.url)
    result = detector.detect()

    if "error" in result:
        print(f"[fw] Error: {result['error']}")
        return

    print(f"[fw] URL         : {result['final_url']} [{result['status']}]")
    print(f"[fw] Server      : {result['server']}")
    if result['x_powered_by']:
        print(f"[fw] X-Powered-By: {result['x_powered_by']}")
    if result.get('api_base'):
        print(f"[fw] API Base    : {result['api_base']}")

    print(f"\n[fw] Raw headers:")
    for k, v in result['raw_headers'].items():
        print(f"     {k}: {v}")

    # Live backend endpoints
    live = result.get("live_api_endpoints", [])
    if live:
        print(f"\n[fw] Live backend endpoints ({len(live)} found):")
        for ep in live:
            xpb = f" X-Powered-By={ep['x_powered_by']}" if ep.get('x_powered_by') else ""
            print(f"  [{ep['status']}] {ep['path']}{xpb}")
            if ep.get('body') and ep['status'] != 200:
                print(f"       {ep['body'][:120]}")

    frameworks = result.get("frameworks", [])
    if not frameworks:
        print("\n[fw] No matching framework signatures found.")
        print("[fw] Try checking Wappalyzer/BuiltWith manually or run --creds to probe config files.")
        return

    print(f"\n[fw] Detected ({len(frameworks)} match{'es' if len(frameworks) != 1 else ''}):")
    for i, fw in enumerate(frameworks[:10], 1):
        bar = "█" * min(fw["score"], 20)
        print(f"  {i}. {fw['name']:<22} score={fw['score']:>3}  {bar}")
        print(f"       evidence: {', '.join(str(e) for e in fw['evidence'][:4])}")

    top = result["top"]
    if top:
        print(f"\n[fw] Best match  : {top['name']} (score={top['score']})")
        print(f"[fw] Wordlist    : {top['wordlist']}")
        print(f"[fw] Suggested   : python3 blackwidow.py scan -u {args.url} --dirs -w {top['wordlist']}")

    # Save result
    save_report(result, "detect")

    if args.auto_scan and top:
        import subprocess
        fw_flag_map = {
            "wordpress": "wordpress", "laravel": "laravel", "django": "django",
            "asp.net core": "dotnet", "java spring": "java-spring",
            "next.js": "nextjs", "nuxt.js": "nuxt", "sveltekit": "sveltekit",
            "vue.js": "vue", "react": "react", "angular": "angular",
        }
        fw_flag = fw_flag_map.get(top["name"].lower())
        cmd = ["python3", "blackwidow.py", "scan", "-u", args.url, "--dirs"]
        if fw_flag:
            cmd += ["-f", fw_flag]
        else:
            cmd += ["-w", top["wordlist"]]
        print(f"\n[fw] Auto-scanning: {' '.join(cmd)}")
        subprocess.run(cmd)


# ─────────────────────────── Hash Identify ────────────────────────────────

def cmd_hash(args):
    hashes = []
    if args.hash:
        hashes = [args.hash]
    elif args.file:
        with open(args.file) as f:
            hashes = [l.strip() for l in f if l.strip()]
    else:
        print("[-] Provide --hash or --file")
        return

    results = HashIdentifier.identify_many(hashes)
    for h, types in results.items():
        print(f"[hash] {h[:40]}... → {', '.join(types)}" if len(h) > 40 else f"[hash] {h} → {', '.join(types)}")
    save_report(results, "hash_identify")


# ─────────────────────────── Main ─────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="BlackWidow — All-in-One Web Hacking Toolkit",
        formatter_class=argparse.RawTextHelpFormatter,
        epilog="""Examples:
  python3 blackwidow.py scan -u http://target.com --full
  python3 blackwidow.py scan -u http://target.com --dirs --ffuf
  python3 blackwidow.py exploit -u http://target.com?id=1 --sqli --xss --ssrf --idor
  python3 blackwidow.py exploit -u http://target.com --auth-bypass --session --creds
  python3 blackwidow.py exploit -u http://target.com --defacement
  python3 blackwidow.py brute -u http://target.com/login --users users.txt --passwords wordlists/passwords.txt
  python3 blackwidow.py hash --hash '$2y$10$abc...'
  python3 blackwidow.py hash --file hashes.txt
  python3 blackwidow.py report --export html
  python3 blackwidow.py detect -u http://target.com --auto-scan
        """
    )

    subparsers = parser.add_subparsers(dest="command", required=True)

    # ── SCAN ──
    sp = subparsers.add_parser("scan", help="Scan targets (ports, dirs, subdomains)")
    sp.add_argument("-u", "--url", required=True, help="Target URL or IP")
    sp.add_argument("--ports", help="Port range (e.g. 1-1000 or 22,80,443)")
    sp.add_argument("--dirs", action="store_true", help="Directory brute force")
    sp.add_argument("--subdomains", action="store_true", help="Subdomain enumeration")
    sp.add_argument("--full", action="store_true", help="Full scan (ports + dirs + subdomains)")
    sp.add_argument("-t", "--threads", type=int, default=20, help="Threads (default: 20)")
    sp.add_argument("-w", "--wordlist", help="Custom wordlist path")
    sp.add_argument("-e", "--extensions", help="Extensions to append (e.g. .php,.bak,.html)")
    sp.add_argument("--ffuf", action="store_true", help="Use ffuf for dir fuzzing (if installed)")
    sp.add_argument("--dirsearch", action="store_true", help="Use dirsearch for dir fuzzing (if installed)")
    sp.add_argument("-f", "--framework", choices=[
        "wordpress", "laravel", "java-spring", "dotnet", "nextjs",
        "django", "nuxt", "sveltekit", "vue", "react", "angular",
    ], help="Use framework-specific wordlist")

    # ── EXPLOIT ──
    ep = subparsers.add_parser("exploit", help="Exploit/test vulnerabilities")
    ep.add_argument("-u", "--url", required=True, help="Target URL")
    ep.add_argument("--sqli", action="store_true", help="SQL Injection scan")
    ep.add_argument("--xss", action="store_true", help="XSS scan")
    ep.add_argument("--wp", action="store_true", help="WordPress deep scan")
    ep.add_argument("--cms", action="store_true", help="CMS detection")
    ep.add_argument("--idor", action="store_true", help="IDOR scan")
    ep.add_argument("--idor-range", type=int, default=50, help="IDOR ID range (default: 50)")
    ep.add_argument("--auth-bypass", action="store_true", help="Auth bypass scan")
    ep.add_argument("--ssrf", action="store_true", help="SSRF + path traversal scan")
    ep.add_argument("--session", action="store_true", help="Session/cookie management scan")
    ep.add_argument("--creds", action="store_true", help="Credential/config file harvesting")
    ep.add_argument("--defacement", action="store_true", help="Defacement detection")
    ep.add_argument("--all", action="store_true", help="Run all exploit modules")
    ep.add_argument("--cookie", help="Session cookie (e.g. session=abc123)")

    # ── BRUTE ──
    bp = subparsers.add_parser("brute", help="Brute force login")
    bp.add_argument("-u", "--url", required=True, help="Login URL")
    bp.add_argument("--users", help="Username wordlist")
    bp.add_argument("--passwords", help="Password wordlist")
    bp.add_argument("--form", help="Form template (e.g. 'username={}&password={}')")
    bp.add_argument("-t", "--threads", type=int, default=10, help="Threads (default: 10)")

    # ── HASH ──
    hp = subparsers.add_parser("hash", help="Hash identification")
    hp.add_argument("--hash", help="Single hash string to identify")
    hp.add_argument("--file", help="File with one hash per line")

    # ── REPORT ──
    rp = subparsers.add_parser("report", help="Generate/export reports")
    rp.add_argument("--export", choices=["txt", "json", "html"], help="Export format")
    rp.add_argument("--output", help="Output file path")

    # ── TARGETS ──
    tp = subparsers.add_parser("targets", help="Manage targets")
    tp.add_argument("--add", help="Add target URL")
    tp.add_argument("--list", action="store_true", help="List saved targets")
    tp.add_argument("--name", help="Target name label")

    # ── DETECT ──
    dp = subparsers.add_parser("detect", help="Detect framework and map wordlist")
    dp.add_argument("-u", "--url", required=True, help="Target URL")
    dp.add_argument("--auto-scan", action="store_true", help="Auto-scan with detected wordlist")

    args = parser.parse_args()

    # ── Cookies helper ──
    def parse_cookies(cookie_str):
        if not cookie_str:
            return {}
        cookies = {}
        for part in cookie_str.split(";"):
            part = part.strip()
            if "=" in part:
                k, v = part.split("=", 1)
                cookies[k.strip()] = v.strip()
        return cookies

    # ════════════════════════════════════════════════════════
    if args.command == "scan":
        banner()
        exts = [e.strip() for e in args.extensions.split(",")] if getattr(args, "extensions", None) else []

        if args.full:
            args.ports = "1-1000"
            args.dirs = True
            args.subdomains = True

        if args.ports:
            scanner = PortScanner(args.url, threads=args.threads)
            scanner.scan(port_range=args.ports)
            save_report(scanner.results, "port_scan")

        if args.dirs:
            fw_map = {
                "wordpress": "wordlists/framework/wordpress.txt",
                "laravel": "wordlists/framework/laravel.txt",
                "java-spring": "wordlists/framework/java-spring.txt",
                "dotnet": "wordlists/framework/dotnet.txt",
                "nextjs": "wordlists/framework/nextjs.txt",
                "django": "wordlists/framework/django.txt",
                "nuxt": "wordlists/framework/nuxt.txt",
                "sveltekit": "wordlists/framework/sveltekit.txt",
                "vue": "wordlists/framework/common.txt",
                "react": "wordlists/framework/common.txt",
                "angular": "wordlists/framework/common.txt",
            }
            wordlist = (fw_map[args.framework] if args.framework else None) or args.wordlist or "wordlists/common_dirs.txt"

            if args.ffuf:
                ffuf = FfufScanner(args.url, wordlist, extensions=exts, threads=args.threads)
                if not ffuf.run():
                    # fallback
                    scanner = DirScanner(args.url, wordlist, threads=args.threads, extensions=exts)
                    scanner.scan()
                    save_report(scanner.results, "dir_scan")
            elif args.dirsearch:
                ds = DirsearchScanner(args.url, wordlist=wordlist, extensions=exts, threads=args.threads)
                if not ds.run():
                    scanner = DirScanner(args.url, wordlist, threads=args.threads, extensions=exts)
                    scanner.scan()
                    save_report(scanner.results, "dir_scan")
            else:
                scanner = DirScanner(args.url, wordlist, threads=args.threads, extensions=exts)
                scanner.scan()
                save_report(scanner.results, "dir_scan")

        if args.subdomains:
            wordlist = args.wordlist or "wordlists/subdomains.txt"
            scanner = SubdomainScanner(args.url, wordlist, threads=args.threads)
            scanner.scan()
            save_report(scanner.results, "subdomain_scan")

    # ════════════════════════════════════════════════════════
    elif args.command == "exploit":
        banner()
        cookies = parse_cookies(getattr(args, "cookie", None))
        run_all = getattr(args, "all", False)

        if args.sqli or run_all:
            sc = SQLiScanner(args.url)
            sc.scan()
            save_report(sc.vulnerabilities, "sqli_scan")

        if args.xss or run_all:
            sc = XSSScanner(args.url)
            sc.scan()
            save_report(sc.vulnerabilities, "xss_scan")

        if args.idor or run_all:
            sc = IDORScanner(args.url, id_range=args.idor_range, cookies=cookies)
            sc.scan()
            save_report(sc.vulnerabilities, "idor_scan")

        if args.auth_bypass or run_all:
            sc = AuthBypassScanner(args.url, cookies=cookies)
            sc.scan()
            save_report(sc.vulnerabilities, "auth_bypass_scan")

        if args.ssrf or run_all:
            sc = SSRFScanner(args.url)
            sc.scan()
            save_report(sc.vulnerabilities, "ssrf_scan")

        if args.session or run_all:
            sc = SessionScanner(args.url)
            sc.scan()
            save_report(sc.vulnerabilities, "session_scan")

        if args.creds or run_all:
            sc = CredentialHarvester(args.url)
            sc.scan()
            save_report(sc.found, "cred_harvest")

        if args.defacement or run_all:
            sc = DefacementDetector(args.url)
            result = sc.check()
            save_report(result, "defacement_check")

        if args.wp or run_all:
            sc = WPScanner(args.url)
            sc.scan()
            save_report(sc.vulnerabilities, "wp_scan")

    # ════════════════════════════════════════════════════════
    elif args.command == "brute":
        banner()
        forcer = BruteForcer(
            args.url,
            users=args.users,
            passwords=args.passwords,
            form=args.form,
            threads=args.threads,
        )
        forcer.attack()
        save_report(forcer.results, "brute_force")

    # ════════════════════════════════════════════════════════
    elif args.command == "hash":
        banner()
        cmd_hash(args)

    # ════════════════════════════════════════════════════════
    elif args.command == "report":
        banner()
        if args.export:
            from core.report import export_report
            export_report(args.export, args.output)
        else:
            print("[-] Specify --export [txt|json|html]")

    # ════════════════════════════════════════════════════════
    elif args.command == "targets":
        banner()
        if args.add:
            save_target(args.add, args.name)
        if args.list:
            targets = load_targets()
            if not targets["targets"]:
                print("[-] No targets saved.")
            for i, t in enumerate(targets["targets"], 1):
                print(f"  {i}. {t.get('name', t['url'])} ({t['url']})")

    # ════════════════════════════════════════════════════════
    elif args.command == "detect":
        banner()
        cmd_detect(args)


if __name__ == "__main__":
    main()
