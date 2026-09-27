import json
from datetime import datetime


def save_json_report(findings, target, path="report.json"):
    report = {
        "target": target,
        "generated_at": datetime.utcnow().isoformat() + "Z",
        "total_findings": len(findings),
        "findings": findings,
    }
    with open(path, "w") as f:
        json.dump(report, f, indent=2)
    return path


def save_text_report(findings, target, path="report.txt"):
    lines = []
    lines.append("Web Vulnerability Scanner - Reflected XSS Report")
    lines.append("=" * 50)
    lines.append(f"Target: {target}")
    lines.append(f"Generated: {datetime.utcnow().isoformat()}Z")
    lines.append(f"Total findings: {len(findings)}")
    lines.append("")

    if not findings:
        lines.append("No reflected XSS issues detected.")
    else:
        for i, f in enumerate(findings, 1):
            lines.append(f"[{i}] {f['type']} via {f['location']}")
            lines.append(f"    Endpoint : {f['endpoint']}")
            lines.append(f"    Parameter: {f['parameter']}")
            lines.append(f"    Payload  : {f['payload']}")
            lines.append(f"    Marker   : {f['evidence_marker']}")
            lines.append("")

    text = "\n".join(lines)
    with open(path, "w") as fh:
        fh.write(text)
    return path


def print_summary(findings):
    if not findings:
        print("\nNo reflected XSS vulnerabilities found.")
        return
    print(f"\n{len(findings)} potential vulnerability(ies) found:")
    for f in findings:
        print(f"  - [{f['location']}] {f['endpoint']}  param='{f['parameter']}'  ({f['payload_name']})")
