import json
import os
from datetime import datetime

def export_report(format, output_path=None):
    reports = []
    for file in os.listdir("reports"):
        if file.endswith(".json"):
            with open(f"reports/{file}") as f:
                reports.append(json.load(f))

    if not reports:
        print("[-] No reports to export")
        return

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    default_output = f"blackwidow_report_{timestamp}.{format}"

    if format == "txt":
        output = output_path or default_output
        with open(output, "w") as f:
            for report in reports:
                f.write(f"=== {report[0].get('type', 'Scan')} ===\n")
                for item in report:
                    f.write(f"{json.dumps(item, indent=2)}\n\n")
        print(f"[+] Exported to {output}")

    elif format == "json":
        output = output_path or default_output
        with open(output, "w") as f:
            json.dump(reports, f, indent=2)
        print(f"[+] Exported to {output}")

    elif format == "html":
        output = output_path or default_output
        html = "<html><body><h1>BlackWidow Report</h1>"
        for report in reports:
            html += f"<h2>{report[0].get('type', 'Scan')}</h2><pre>"
            html += json.dumps(report, indent=2)
            html += "</pre>"
        html += "</body></html>"
        with open(output, "w") as f:
            f.write(html)
        print(f"[+] Exported to {output}")
