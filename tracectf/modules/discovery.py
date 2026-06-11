import subprocess
import json
import tempfile
import os
import shutil
from typing import Optional


DEFAULT_WORDLIST_CANDIDATES = [
    "/usr/share/seclists/Discovery/Web-Content/common.txt",
    "/usr/share/wordlists/dirb/common.txt",
    "/usr/share/wordlists/dirbuster/directory-list-2.3-small.txt",
    "/usr/share/seclists/Discovery/Web-Content/raft-small-words.txt",
]

FALLBACK_WORDLIST = [
    "admin", "login", "api", "v1", "v2", "upload", "uploads", "static",
    "assets", "js", "css", "img", "images", "backup", "config", "flag",
    "secret", "test", "dev", "debug", "robots.txt", "sitemap.xml",
    ".git", ".env", "phpinfo.php", "info.php", "dashboard", "panel",
    "user", "users", "account", "accounts", "auth", "token", "reset",
    "register", "signup", "logout", "profile", "settings", "download",
]


def _get_wordlist(custom: Optional[str] = None) -> Optional[str]:
    if custom and os.path.exists(custom):
        return custom
    for candidate in DEFAULT_WORDLIST_CANDIDATES:
        if os.path.exists(candidate):
            return candidate
    return None


def discover(url: str, wordlist: Optional[str] = None) -> list[dict]:
    url = url.rstrip("/")

    if shutil.which("ffuf"):
        return _run_ffuf(url, wordlist)
    return _run_fallback(url)


def _run_ffuf(url: str, wordlist: Optional[str] = None) -> list[dict]:
    wl = _get_wordlist(wordlist)
    results = []

    with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as tmp:
        tmp_path = tmp.name

    try:
        if wl:
            cmd = [
                "ffuf", "-u", f"{url}/FUZZ",
                "-w", wl,
                "-o", tmp_path,
                "-of", "json",
                "-mc", "200,201,204,301,302,307,401,403,405",
                "-t", "50",
                "-timeout", "5",
                "-s",  # silent
            ]
        else:
            # write fallback wordlist to temp file
            with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as wf:
                wf.write("\n".join(FALLBACK_WORDLIST))
                wl_tmp = wf.name
            cmd = [
                "ffuf", "-u", f"{url}/FUZZ",
                "-w", wl_tmp,
                "-o", tmp_path,
                "-of", "json",
                "-mc", "200,201,204,301,302,307,401,403,405",
                "-t", "20",
                "-timeout", "5",
                "-s",
            ]

        subprocess.run(cmd, capture_output=True, timeout=60)

        if os.path.exists(tmp_path) and os.path.getsize(tmp_path) > 0:
            with open(tmp_path) as f:
                data = json.load(f)
            for r in data.get("results", []):
                results.append({
                    "url": r.get("url"),
                    "status": r.get("status"),
                    "length": r.get("length"),
                    "words": r.get("words"),
                })
    except (subprocess.TimeoutExpired, Exception):
        pass
    finally:
        if os.path.exists(tmp_path):
            os.unlink(tmp_path)
        if "wl_tmp" in locals() and os.path.exists(wl_tmp):
            os.unlink(wl_tmp)

    return results


def _run_fallback(url: str) -> list[dict]:
    """Pure httpx fallback when ffuf isn't available."""
    import httpx
    results = []
    with httpx.Client(follow_redirects=False, timeout=5, verify=False) as client:
        for word in FALLBACK_WORDLIST:
            target = f"{url}/{word}"
            try:
                r = client.get(target)
                if r.status_code not in (404, 400):
                    results.append({
                        "url": target,
                        "status": r.status_code,
                        "length": len(r.content),
                    })
            except Exception:
                continue
    return results
