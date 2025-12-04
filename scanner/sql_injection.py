import requests
from urllib.parse import urlparse, parse_qs, urljoin
from bs4 import BeautifulSoup

HEADERS = {"User-Agent": "WebScanPro/1.0"}

SQL_PAYLOADS = [
    "' OR '1'='1",
    "' OR 1=1 -- ",
    "\" OR \"\" = \"",
    "' UNION SELECT NULL--",
]

ERROR_SIGNS = [
    "sql syntax", "mysql", "warning", "mysqli", "sqlstate",
    "you have an error in your sql syntax",
    "unterminated", "unclosed quotation"
]


# ---------------------------
#  HELPER – Only test real SQL parameters
# ---------------------------
def is_valid_sql_target(url):
    parsed = urlparse(url)
    params = parse_qs(parsed.query)

    if not params:
        return False  # No key-value params → skip

    # skip Apache auto-index garbage URLs
    bad_params = {"C", "O", "D"}
    if set(params.keys()).intersection(bad_params):
        return False

    # skip static folders
    skip_dirs = ["includes", "css", "js", "images", "fonts"]
    for s in skip_dirs:
        if f"/{s}/" in parsed.path:
            return False

    return True


def is_error(text):
    if not text:
        return False
    t = text.lower()
    return any(sig in t for sig in ERROR_SIGNS)


# ---------------------------
#  MAIN SQL INJECTION TESTER
# ---------------------------
def test_sql_injection(base_url, targets):
    results = []

    # ---------------------------
    #  TEST URL PARAMETERS
    # ---------------------------
    for link in targets.get("links", []):
        if not is_valid_sql_target(link):
            continue  # SKIP false positives

        for payload in SQL_PAYLOADS:
            try:
                test_url = link + payload
                r = requests.get(test_url, headers=HEADERS, timeout=8)
            except:
                continue

            if is_error(r.text):
                results.append({
                    "vulnerability": "SQL Injection",
                    "endpoint": test_url,
                    "severity": "HIGH",
                    "payload": payload,
                    "evidence": {
                        "payload": payload,
                        "status_code": r.status_code,
                        "body_snippet": r.text[:400]
                    }
                })

    # ---------------------------
    #  TEST FORMS
    # ---------------------------
    for form in targets.get("forms", []):
        action = form["action"]
        method = form["method"].lower()
        inputs = [i["name"] for i in form["inputs"] if i["name"]]

        if not inputs:
            continue

        for payload in SQL_PAYLOADS:
            data = {field: payload for field in inputs}

            try:
                if method == "post":
                    r = requests.post(action, data=data, headers=HEADERS, timeout=10)
                else:
                    r = requests.get(action, params=data, headers=HEADERS, timeout=10)
            except:
                continue

            if is_error(r.text):
                results.append({
                    "vulnerability": "SQL Injection",
                    "endpoint": action,
                    "severity": "HIGH",
                    "payload": payload,
                    "evidence": {
                        "payload": payload,
                        "status_code": r.status_code,
                        "body_snippet": r.text[:400]
                    }
                })

    return results
