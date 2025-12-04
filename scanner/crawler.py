# scanner/crawler.py
import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse

HEADERS = {"User-Agent": "WebScanPro/1.0"}

def get_soup(url):
    r = requests.get(url, headers=HEADERS, timeout=10)
    r.raise_for_status()
    return BeautifulSoup(r.text, "html.parser")

def crawl(base_url, max_pages=30):
    """
    Very simple crawler focused on collecting forms and links on the base_url domain.
    Returns dict with 'links' and 'forms'.
    """
    to_visit = {base_url}
    visited = set()
    links = set()
    forms = []

    while to_visit and len(visited) < max_pages:
        url = to_visit.pop()
        visited.add(url)
        try:
            soup = get_soup(url)
        except Exception:
            continue

        # collect links
        for a in soup.find_all("a", href=True):
            href = urljoin(url, a["href"])
            p = urlparse(href)
            if p.netloc == urlparse(base_url).netloc:
                if href not in visited:
                    to_visit.add(href)
                links.add(href)

        # collect forms
        for form in soup.find_all("form"):
            action = form.get("action") or url
            method = (form.get("method") or "get").lower()
            inputs = []
            for inp in form.find_all(["input","textarea","select"]):
                name = inp.get("name")
                typ = inp.get("type","text")
                if name:
                    inputs.append({"name": name, "type": typ})
            forms.append({
                "page": url,
                "action": urljoin(url, action),
                "method": method,
                "inputs": inputs
            })

    return {"links": list(links), "forms": forms}
