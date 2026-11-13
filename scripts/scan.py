"""Scan the insecure and secure Terraform with Checkov and write a before/after report.

Usage:  python scripts/scan.py            (needs `pip install checkov`)
Writes: reports/checkov-insecure.json, reports/checkov-secure.json, reports/summary.md
Exit code 1 if the secure configuration has any failed check.
"""
import json
import subprocess
import sys
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
REPORTS = ROOT / "reports"

# which misconfiguration (see README) each insecure resource belongs to
M_BY_RESOURCE = {
    "google_compute_network.vpc": "M1",
    "google_compute_firewall.allow_admin": "M2",
    "google_project_iam_member.app_editor": "M3",
    "google_service_account_key.app_key": "M4",
    "google_compute_instance.web": "M5",
    "google_storage_bucket.exports": "M6",
    "google_storage_bucket_iam_member.public_read": "M6",
    "google_sql_database_instance.db": "M7",
}


def checkov(directory):
    cmd = ["checkov", "-d", str(ROOT / directory), "--framework", "terraform",
           "--external-checks-dir", str(ROOT / "policies"), "-o", "json"]
    out = subprocess.run(cmd, capture_output=True, text=True).stdout
    data = json.loads(out)
    data = data[0] if isinstance(data, list) else data
    # keep the report small and free of local paths: summary, failed and skipped checks only
    keep = ("check_id", "check_name", "resource", "repo_file_path", "file_line_range", "check_result", "guideline")
    slim = {
        "summary": data["summary"],
        "failed_checks": [{k: c.get(k) for k in keep} for c in data["results"].get("failed_checks", [])],
        "skipped_checks": [{k: c.get(k) for k in keep} for c in data["results"].get("skipped_checks", [])],
    }
    (REPORTS / f"checkov-{directory}.json").write_text(json.dumps(slim, indent=2))
    return data


def main():
    REPORTS.mkdir(exist_ok=True)
    before, after = checkov("insecure"), checkov("secure")
    b, a = before["summary"], after["summary"]
    failed = before["results"]["failed_checks"]

    lines = [
        "# Checkov scan: before and after hardening", "",
        "| | Insecure | Secure |", "|---|---:|---:|",
        f"| Passed checks | {b['passed']} | {a['passed']} |",
        f"| **Failed checks** | **{b['failed']}** | **{a['failed']}** |",
        f"| Skipped (with justification) | {b['skipped']} | {a['skipped']} |", "",
        "## Findings in the insecure configuration", "",
        "| # | Check | Resource | Finding | Fixed? |", "|---|---|---|---|---|",
    ]
    still_failing = {(f["check_id"], f["resource"]) for f in after["results"]["failed_checks"]}
    for f in sorted(failed, key=lambda f: (M_BY_RESOURCE.get(f["resource"], "M9"), f["check_id"])):
        m = M_BY_RESOURCE.get(f["resource"], "-")
        fixed = "No" if (f["check_id"], f["resource"]) in still_failing else "Yes"
        custom = " *(custom)*" if "PORTFOLIO" in f["check_id"] else ""
        lines.append(f"| {m} | `{f['check_id']}`{custom} | `{f['resource']}` | {f['check_name']} | {fixed} |")

    by_m = Counter(M_BY_RESOURCE.get(f["resource"], "-") for f in failed)
    lines += ["", "## Failed checks per misconfiguration", "", "| Misconfiguration | Failed checks |", "|---|---:|"]
    lines += [f"| {m} | {n} |" for m, n in sorted(by_m.items())]
    skipped = after["results"].get("skipped_checks", [])
    if skipped:
        lines += ["", "## Accepted exceptions in the secure configuration", ""]
        lines += [f"- `{s['check_id']}` on `{s['resource']}`: {s['check_result'].get('suppress_comment', '')}" for s in skipped]
    lines += ["", "*M8 (no Data Access audit logs) is not detected by any check, because scanners struggle to "
              "flag something that is missing. It was found by manual review; see the README.*", ""]
    (REPORTS / "summary.md").write_text("\n".join(lines))
    print(f"insecure: {b['failed']} failed / secure: {a['failed']} failed -> reports/summary.md")
    return 1 if a["failed"] else 0


if __name__ == "__main__":
    sys.exit(main())
