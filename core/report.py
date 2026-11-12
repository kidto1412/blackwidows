import json
import os
from datetime import datetime


def _load_all_reports():
    reports = {}
    if not os.path.isdir("reports"):
        return reports
    for file in sorted(os.listdir("reports")):
        if file.endswith(".json"):
            try:
                with open(f"reports/{file}") as f:
                    data = json.load(f)
                reports[file] = data
            except Exception:
                pass
    return reports


def export_report(fmt, output_path=None):
    reports = _load_all_reports()
    if not reports:
        print("[-] No reports to export (run scans first)")
        return

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    default_output = f"blackwidow_report_{timestamp}.{fmt}"
    output = output_path or default_output

    if fmt == "txt":
        with open(output, "w") as f:
            f.write(f"BlackWidow Report — {timestamp}\n")
            f.write("=" * 60 + "\n\n")
            for name, data in reports.items():
                f.write(f"\n=== {name} ===\n")
                if isinstance(data, list):
                    for item in data:
                        f.write(json.dumps(item, indent=2) + "\n")
                else:
                    f.write(json.dumps(data, indent=2) + "\n")
        print(f"[+] Exported: {output}")

    elif fmt == "json":
        with open(output, "w") as f:
            json.dump(reports, f, indent=2)
        print(f"[+] Exported: {output}")

    elif fmt == "html":
        html = f"""<!DOCTYPE html>
<html>
<head>
<meta charset="utf-8">
<title>BlackWidow Report</title>
<style>
  body {{ font-family: 'Courier New', monospace; background: #0d0d0d; color: #e0e0e0; padding: 20px; }}
  h1 {{ color: #cc0000; border-bottom: 2px solid #cc0000; padding-bottom: 8px; }}
  h2 {{ color: #ff4444; margin-top: 30px; }}
  pre {{ background: #1a1a1a; border: 1px solid #333; padding: 15px; border-radius: 4px;
         overflow-x: auto; white-space: pre-wrap; word-break: break-all; }}
  .vuln {{ border-left: 4px solid #cc0000; padding-left: 10px; margin: 10px 0; }}
  .found {{ border-left: 4px solid #00aa44; padding-left: 10px; margin: 10px 0; }}
  .meta {{ color: #888; font-size: 0.85em; }}
</style>
</head>
<body>
<h1>🕷 BlackWidow Report</h1>
<p class="meta">Generated: {timestamp}</p>
"""
        for name, data in reports.items():
            section = name.replace(".json", "").replace("_", " ").title()
            html += f"<h2>{section}</h2>\n"
            if isinstance(data, list):
                for item in data:
                    css_class = "vuln" if "vuln" in name.lower() or item.get("type") else "found"
                    html += f'<div class="{css_class}"><pre>{json.dumps(item, indent=2)}</pre></div>\n'
            else:
                html += f"<pre>{json.dumps(data, indent=2)}</pre>\n"
        html += "</body></html>"
        with open(output, "w") as f:
            f.write(html)
        print(f"[+] Exported: {output}")

    else:
        print(f"[-] Unknown format: {fmt}. Use txt, json, or html.")
