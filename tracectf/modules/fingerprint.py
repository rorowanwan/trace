import httpx
from bs4 import BeautifulSoup
from urllib.parse import urljoin
from typing import Any


TECH_SIGNATURES = {
    "WordPress": ["wp-content", "wp-includes", "wp-json"],
    "Laravel": ["laravel_session", "XSRF-TOKEN"],
    "Django": ["csrftoken", "django"],
    "Rails": ["_rails-", "X-Runtime"],
    "Express": ["X-Powered-By: Express"],
    "PHP": ["X-Powered-By: PHP", ".php"],
    "ASP.NET": ["X-AspNet-Version", "ASP.NET_SessionId"],
    "Next.js": ["__NEXT_DATA__", "_next/static"],
    "React": ["__react", "react-root", "_reactRootContainer"],
    "Vue": ["__vue__", "data-v-"],
}


def fingerprint(url: str, cookies: dict = {}, headers: dict = {}, delay: float = 0.0) -> dict[str, Any]:
    findings: dict[str, Any] = {
        "status_code": None,
        "server": None,
        "powered_by": None,
        "content_type": None,
        "interesting_headers": {},
        "cookies": [],
        "detected_tech": [],
        "scripts": [],
        "forms": [],
        "comments": [],
    }

    try:
        if delay > 0:
            import time; time.sleep(delay)
        resp = httpx.get(url, follow_redirects=True, timeout=10, verify=False, cookies=cookies, headers=headers)
    except httpx.RequestError as e:
        findings["error"] = str(e)
        return findings

    findings["status_code"] = resp.status_code
    resp_headers = dict(resp.headers)

    # basic headers
    findings["server"] = resp_headers.get("server")
    findings["powered_by"] = resp_headers.get("x-powered-by")
    findings["content_type"] = resp_headers.get("content-type")

    # interesting security headers (or lack thereof)
    interesting = [
        "x-frame-options", "x-xss-protection", "content-security-policy",
        "strict-transport-security", "x-content-type-options",
        "access-control-allow-origin", "x-runtime", "x-aspnet-version",
        "cf-ray", "x-cache", "via",
    ]
    for h in interesting:
        if h in resp_headers:
            findings["interesting_headers"][h] = resp_headers[h]

    # cookies
    for name, val in resp.cookies.items():
        findings["cookies"].append({"name": name, "value": val[:40] + "..." if len(val) > 40 else val})

    # parse html
    soup = BeautifulSoup(resp.text, "html.parser")

    # script srcs
    for tag in soup.find_all("script", src=True):
        src = tag["src"]
        if src.startswith("http"):
            findings["scripts"].append(src)
        else:
            findings["scripts"].append(urljoin(url, src))

    # forms
    for form in soup.find_all("form"):
        form_info = {
            "action": form.get("action", ""),
            "method": form.get("method", "get").upper(),
            "inputs": [{"name": i.get("name"), "type": i.get("type", "text")} for i in form.find_all("input")],
        }
        findings["forms"].append(form_info)

    # html comments
    from bs4 import Comment
    for comment in soup.find_all(string=lambda t: isinstance(t, Comment)):
        c = comment.strip()
        if c and len(c) > 3:
            findings["comments"].append(c[:200])

    # tech detection
    body = resp.text
    all_headers_str = str(resp_headers)
    for tech, sigs in TECH_SIGNATURES.items():
        for sig in sigs:
            if sig.lower() in body.lower() or sig.lower() in all_headers_str.lower():
                if tech not in findings["detected_tech"]:
                    findings["detected_tech"].append(tech)
                break

    return findings
