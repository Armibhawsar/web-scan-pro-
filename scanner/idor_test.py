# scanner/idor_test.py
import requests
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse, ParseResult

HEADERS = {"User-Agent": "WebScanPro/1.0"}

def replace_query_param(url, key, value):
    p = urlparse(url)
    q = parse_qs(p.query)
    q[key] = [value]
    new_query = urlencode(q, doseq=True)
    return urlunparse(ParseResult(p.scheme, p.netloc, p.path, p.params, new_query, p.fragment))

def test_idor(base_url, targets, id_values=[1,2,3,4,5]):
    results = []
    # look for links with numeric query params and attempt different IDs
    for link in targets.get("links", []):
        if "=" not in link:
            continue
        parsed = urlparse(link)
        params = parse_qs(parsed.query)
        # find numeric-looking params
        for k, v in params.items():
            try:
                int(v[0])
            except Exception:
                continue
            # try different ids
            for new_id in id_values:
                new_url = replace_query_param(link, k, new_id)
                try:
                    r = requests.get(new_url, headers=HEADERS, timeout=10)
                except Exception:
                    continue
                # naive: if response contains "user" or "id" or doesn't require login
                body = r.text.lower()
                if "unauthorized" not in body and len(body) > 100:
                    results.append({
                        "vulnerability": "Possible IDOR",
                        "endpoint": new_url,
                        "severity": "MEDIUM",
                        "param": k,
                        "tested_value": new_id,
                        "evidence_snippet": body[:300]
                    })
    if not results:
        results.append({"note":"No obvious IDOR found with naive checks."})
    return results
