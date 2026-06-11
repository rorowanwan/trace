# Trace

CTF-scoped web recon pipeline. Fingerprint, discover, analyze, summarize.

## Install

```bash
git clone https://github.com/rorowanwan/trace
cd trace
pip install -e . --break-system-packages
```

## Usage

```bash
# full scan
trace scan http://target.ctf

# skip slow discovery step
trace scan http://target.ctf --no-discovery

# custom wordlist
trace scan http://target.ctf -w /usr/share/seclists/Discovery/Web-Content/big.txt

# json output (pipe to jq etc)
trace scan http://target.ctf --json | jq .fingerprint

# no llm (offline mode)
trace scan http://target.ctf --no-llm
```

## Setup

Set your Gemini API key for LLM summarization:

```bash
export GEMINI_API_KEY=your-key-here...
```

Add to your `~/.config/fish/config.fish` or equivalent to persist.

## Pipeline

1. **Fingerprint** — headers, server, cookies, tech stack detection, forms, HTML comments
2. **Discovery** — ffuf-based dir/endpoint bruteforce (falls back to pure httpx if no wordlist)
3. **JS Analysis** — fetches scripts, scans for API endpoints, secrets, interesting comments
4. **LLM Summary** — feeds all findings to Claude, outputs prioritized attack vector list

## Sample Output

```
$ trace http://target.ctf

┌─────────────────────────┐
│ Trace — http://target.ctf │
└─────────────────────────┘

▸ Fingerprint
  status_code: 200
  server: Apache/2.4.41
  powered_by: PHP/7.4.3
  detected_tech: ['PHP', 'WordPress']
  cookies: [{'name': 'PHPSESSID', 'value': 'abc123'}]
  forms: [{'action': '/login.php', 'method': 'POST', 'inputs': [...]}]
  comments: ['<!-- TODO: remove debug mode before prod -->']

▸ Discovered Endpoints
  • url: http://target.ctf/admin  status: 403
  • url: http://target.ctf/.git  status: 200
  • url: http://target.ctf/backup.zip  status: 200

▸ JS Analysis
  • source: /static/app.js
    api_endpoints: ['/api/v1/users', '/api/v1/flag']
    secrets: ['Authorization: Bearer eyJhbG...']

╔══════════════════ LLM Summary ══════════════════╗
  • .git directory exposed — run git-dumper to recover source
  • backup.zip accessible — likely contains source or credentials  
  • Bearer token found in JS — try authenticated requests to /api/v1/flag
  • PHP/7.4.3 is EOL — check for known CVEs
  • Login form at /login.php — try SQLi and default credentials
╚═════════════════════════════════════════════════╝
```

## Requirements

- Python 3.11+
- ffuf (optional but recommended)
- `ANTHROPIC_API_KEY` env var (optional, skipped if not set)
