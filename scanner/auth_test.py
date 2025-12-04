# scanner/auth_test.py
import requests
from bs4 import BeautifulSoup

HEADERS = {"User-Agent": "WebScanPro/1.0"}

DEFAULT_CREDENTIALS = [
    ("admin","admin"),
    ("admin","password"),
    ("admin","1234"),
    ("test","test")
]

def test_authentication(base_url):
    results = []
    # Attempt login to DVWA login page: /login.php
    login_url = base_url.rstrip("/") + "/login.php"
    try:
        r = requests.get(login_url, headers=HEADERS, timeout=10)
    except Exception:
        return [{"note": "Could not access login page", "login_url": login_url}]

    # DVWA uses form fields 'username' and 'password' often along with 'Login'
    for user, pw in DEFAULT_CREDENTIALS:
        try:
            data = {"username": user, "password": pw, "Login": "Login"}
            rr = requests.post(login_url, data=data, headers=HEADERS, timeout=10, allow_redirects=True)
            body = rr.text.lower()
            # a naive check: DVWA shows "welcome to dvwa" or "failed to login" - adjust as needed
            if "login failed" not in body and rr.status_code == 200 and "logout" in body:
                results.append({
                    "vulnerability": "Weak Credentials",
                    "endpoint": login_url,
                    "severity": "HIGH",
                    "credential": {"username": user, "password": pw}
                })
        except Exception:
            continue
    if not results:
        results.append({"note": "No weak/default creds found (basic check)","login_url": login_url})
    return results
