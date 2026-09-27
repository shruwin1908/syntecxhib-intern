"""
Simple same-domain crawler.

Collects:
  - "forms": pages containing <form> elements, with their inputs/method/action
  - "links_with_params": URLs that already carry GET query parameters

Designed to be polite and bounded (max_pages) so it doesn't hammer a target.
"""

from collections import deque
from urllib.parse import urljoin, urlparse, parse_qs

import requests
from bs4 import BeautifulSoup


class CrawlResult:
    def __init__(self):
        self.visited = set()
        self.forms = []            # list of dicts: {page, action, method, inputs}
        self.links_with_params = []  # list of dicts: {page, url, params}


def _same_domain(base_netloc, url):
    return urlparse(url).netloc in ("", base_netloc)


def _extract_forms(page_url, soup):
    forms = []
    for form in soup.find_all("form"):
        action = form.get("action") or page_url
        method = (form.get("method") or "get").lower()
        inputs = []
        for tag in form.find_all(["input", "textarea", "select"]):
            name = tag.get("name")
            if not name:
                continue
            inputs.append({
                "name": name,
                "type": tag.get("type", "text"),
                "value": tag.get("value", ""),
            })
        if inputs:
            forms.append({
                "page": page_url,
                "action": urljoin(page_url, action),
                "method": method,
                "inputs": inputs,
            })
    return forms


def crawl(start_url, max_pages=20, timeout=8, session=None):
    """
    Breadth-first crawl of start_url restricted to its own domain.
    Returns a CrawlResult.
    """
    session = session or requests.Session()
    base_netloc = urlparse(start_url).netloc

    result = CrawlResult()
    queue = deque([start_url])

    while queue and len(result.visited) < max_pages:
        url = queue.popleft()
        if url in result.visited:
            continue
        result.visited.add(url)

        try:
            resp = session.get(url, timeout=timeout)
        except requests.RequestException:
            continue

        content_type = resp.headers.get("Content-Type", "")
        if "text/html" not in content_type:
            continue

        soup = BeautifulSoup(resp.text, "html.parser")

        # Forms on this page
        result.forms.extend(_extract_forms(url, soup))

        # Links: queue same-domain ones, record ones with query params
        for a in soup.find_all("a", href=True):
            link = urljoin(url, a["href"])
            parsed = urlparse(link)

            if parsed.scheme not in ("http", "https"):
                continue
            if not _same_domain(base_netloc, link):
                continue

            if parsed.query:
                result.links_with_params.append({
                    "page": url,
                    "url": link,
                    "params": {k: v[0] for k, v in parse_qs(parsed.query).items()},
                })

            clean_link = link.split("#")[0]
            if clean_link not in result.visited:
                queue.append(clean_link)

    return result
