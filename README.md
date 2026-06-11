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

## Requirements

- Python 3.11+
- ffuf (optional but recommended)
- `ANTHROPIC_API_KEY` env var (optional, skipped if not set)
