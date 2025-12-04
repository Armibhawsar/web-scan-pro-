import os
import json
from datetime import datetime

from config import BASE_URL, OUTPUT_DIR
from scanner.crawler import crawl
from scanner.sql_injection import test_sql_injection
from scanner.xss import test_xss
from scanner.auth_test import test_authentication
from scanner.idor_test import test_idor
from report.html_report import generate_html_report

os.makedirs(OUTPUT_DIR, exist_ok=True)

def main():
    start = datetime.utcnow().isoformat()
    print(f"[+] Starting WebScanPro on {BASE_URL}")

    # Week 1-2
    print("[*] Running crawler...")
    targets = crawl(BASE_URL)
    print(f"[+] Found {len(targets['forms'])} forms and {len(targets['links'])} links.")

    # Week 3-6
    print("[*] Running SQLi tests...")
    sqli_results = test_sql_injection(BASE_URL,targets)

    print("[*] Running XSS tests...")
    xss_results = test_xss(BASE_URL, targets)

    print("[*] Running authentication tests...")
    auth_results = test_authentication(BASE_URL)

    print("[*] Running IDOR tests...")
    idor_results = test_idor(BASE_URL, targets)

    # Prepare report object
    report = {
        "meta": {"base_url": BASE_URL, "start": start},
        "targets": targets,
        "sqli": sqli_results,
        "xss": xss_results,
        "auth": auth_results,
        "idor": idor_results
    }

    # Week 7 – HTML only
    html_path = os.path.join(OUTPUT_DIR, "report.html")
    print(f"[*] Generating HTML report at {html_path} ...")
    generate_html_report(report, html_path)

    # Save JSON
    json_path = os.path.join(OUTPUT_DIR, "report.json")
    with open(json_path, "w", encoding="utf-8") as fh:
        json.dump(report, fh, indent=2)
    print("[+] Raw JSON saved to", json_path)

    print("\n✔ HTML report successfully generated.")
    print("✔ No PDF created (you selected HTML-only mode).")

if __name__ == "__main__":
    main()
