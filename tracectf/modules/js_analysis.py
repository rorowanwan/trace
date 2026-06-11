import httpx
import re
from urllib.parse import urljoin


# patterns to look for in JS files
PATTERNS = {
    "api_endpoints": [
        r'["\'`](/api/[^\s"\'`]+)',
        r'["\'`](/v\d+/[^\s"\'`]+)',
        r'fetch\(["\']([^"\']+)["\']',
        r'axios\.[a-z]+\(["\']([^"\']+)["\']',
        r'url:\s*["\']([^"\']+)["\']',
    ],
    "secrets": [
        r'(?i)(api[_-]?key|apikey|secret|token|password|passwd|auth)["\s]*[:=]["\s]*["\']([A-Za-z0-9+/=_\-]{8,})["\']',
        r'(?i)bearer\s+([A-Za-z0-9\-_.]+)',
        r'(?i)(aws_access_key|aws_secret)["\s]*[:=]["\s]*["\']([^"\']+)["\']',
    ],
    "interesting_comments": [
        r'//\s*(TODO|FIXME|HACK|XXX|BUG|NOTE|password|secret|flag|admin|debug)[^\n]*',
        r'/\*[\s\S]*?(TODO|FIXME|password|secret|flag)[\s\S]*?\*/',
    ],
    "internal_urls": [
        r'https?://(?:localhost|127\.0\.0\.1|10\.\d+\.\d+\.\d+|192\.168\.\d+\.\d+)[^\s"\'`]*',
        r'https?://[^\s"\'`]*\.(?:internal|local|corp|dev|staging)[^\s"\'`]*',
    ],
    "graphql": [
        r'(?i)(graphql|__schema|introspection)',
    ],
}


def analyze_js(base_url: str, script_urls: list[str]) -> list[dict]:
    findings = []

    # also check inline scripts on the page
    try:
        resp = httpx.get(base_url, follow_redirects=True, timeout=10, verify=False)
        from bs4 import BeautifulSoup
        soup = BeautifulSoup(resp.text, "html.parser")
        inline_scripts = [tag.string for tag in soup.find_all("script") if not tag.get("src") and tag.string]
    except Exception:
        inline_scripts = []

    sources = []
    for url in script_urls[:10]:  # cap at 10 external scripts
        try:
            r = httpx.get(url, follow_redirects=True, timeout=8, verify=False)
            if r.status_code == 200:
                sources.append({"url": url, "content": r.text})
        except Exception:
            continue

    for i, inline in enumerate(inline_scripts):
        if inline and len(inline.strip()) > 20:
            sources.append({"url": f"inline-script-{i}", "content": inline})

    for source in sources:
        content = source["content"]
        source_findings: dict = {"source": source["url"], "hits": {}}

        for category, patterns in PATTERNS.items():
            hits = set()
            for pattern in patterns:
                for match in re.finditer(pattern, content):
                    hit = match.group(0).strip()[:200]
                    hits.add(hit)
            if hits:
                source_findings["hits"][category] = list(hits)

        if source_findings["hits"]:
            findings.append(source_findings)

    return findings
