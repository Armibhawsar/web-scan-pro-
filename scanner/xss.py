# scanner/xss.py
import requests
from bs4 import BeautifulSoup

HEADERS = {"User-Agent": "WebScanPro/1.0"}
XSS_PAYLOADS = [
    "<script>alert(1)</script>",
    "\"><svg/onload=alert(1)>",
    "<img src=x onerror=alert(1)>",
]

def test_xss(base_url, targets):
    results = []
    # check each form by submitting payload and searching response for the payload (reflected)
    for form in targets.get("forms", []):
        action = form["action"]
        method = form["method"].lower()
        input_names = [i["name"] for i in form["inputs"]]
        if not input_names:
            continue
        for payload in XSS_PAYLOADS:
            data = {name: payload for name in input_names}
            try:
                if method == "post":
                    r = requests.post(action, data=data, headers=HEADERS, timeout=10)
                else:
                    r = requests.get(action, params=data, headers=HEADERS, timeout=10)
            except Exception:
                continue
            # naive detection: payload appears in response body
            if payload in r.text:
                evidence = {"payload": payload, "status_code": r.status_code, "body_snippet": r.text[:400]}
                results.append({
                    "vulnerability": "Reflected XSS",
                    "endpoint": action,
                    "severity": "HIGH",
                    "payload": payload,
                    "evidence": evidence
                })
    return results