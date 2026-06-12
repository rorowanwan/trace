import typer
import json
from enum import Enum
from rich.console import Console
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn
from typing import Optional, List
from tracectf.modules.fingerprint import fingerprint
from tracectf.modules.discovery import discover
from tracectf.modules.js_analysis import analyze_js
from tracectf.modules.summarize import summarize
from tracectf.utils.output import print_section, print_finding

app = typer.Typer(help="Trace — CTF web recon pipeline")
console = Console()


class Profile(str, Enum):
    quick = "quick"   # fingerprint + js only, no discovery, no llm
    normal = "normal" # fingerprint + discovery + js + llm
    full = "full"     # normal + bigger wordlist hint + llm


@app.command()
def scan(
    url: str = typer.Argument(..., help="Target URL to scan"),
    output_json: bool = typer.Option(False, "--json", help="Output results as JSON"),
    skip_discovery: bool = typer.Option(False, "--no-discovery", help="Skip dir/endpoint discovery"),
    wordlist: Optional[str] = typer.Option(None, "--wordlist", "-w", help="Custom wordlist for discovery"),
    no_llm: bool = typer.Option(False, "--no-llm", help="Skip LLM summarization"),
    delay: float = typer.Option(0.0, "--delay", "-D", help="Delay in seconds between requests (polite mode for shared CTF infra)"),
    cookie: Optional[List[str]] = typer.Option(None, "--cookie", "-c", help="Cookie(s) to inject, e.g. -c 'session=abc123'"),
    header: Optional[List[str]] = typer.Option(None, "--header", "-H", help="Header(s) to inject, e.g. -H 'Authorization: Bearer token'"),
    profile: Profile = typer.Option(Profile.normal, "--profile", "-p", help="Scan profile: quick | normal | full"),
):
    """Run the full recon pipeline against a target URL."""

    # normalize url
    if not url.startswith("http"):
        url = "http://" + url

    # parse cookies into dict
    cookies: dict = {}
    for c in (cookie or []):
        if "=" in c:
            k, v = c.split("=", 1)
            cookies[k.strip()] = v.strip()

    # parse headers into dict
    headers: dict = {}
    for h in (header or []):
        if ":" in h:
            k, v = h.split(":", 1)
            headers[k.strip()] = v.strip()

    # apply profile overrides
    if profile == Profile.quick:
        skip_discovery = True
        no_llm = True
    elif profile == Profile.full:
        skip_discovery = False
        no_llm = False
        if wordlist is None:
            # pick largest available wordlist for full profile
            from tracectf.modules.discovery import DEFAULT_WORDLIST_CANDIDATES
            full_candidates = [
                "/usr/share/seclists/Discovery/Web-Content/raft-large-words.txt",
                "/usr/share/seclists/Discovery/Web-Content/directory-list-2.3-big.txt",
            ] + DEFAULT_WORDLIST_CANDIDATES
            for candidate in full_candidates:
                import os
                if os.path.exists(candidate):
                    wordlist = candidate
                    break

    results = {"url": url, "fingerprint": {}, "discovery": [], "js_analysis": [], "summary": ""}

    with Progress(SpinnerColumn(), TextColumn("[progress.description]{task.description}"), transient=True) as progress:

        # stage 1: fingerprint
        task = progress.add_task("Fingerprinting target...", total=None)
        fp = fingerprint(url, cookies=cookies, headers=headers, delay=delay)
        results["fingerprint"] = fp
        progress.remove_task(task)

        # stage 2: discovery
        if not skip_discovery:
            task = progress.add_task("Running endpoint discovery...", total=None)
            discovered = discover(url, wordlist=wordlist, delay=delay, cookies=cookies, headers=headers)
            results["discovery"] = discovered
            progress.remove_task(task)

        # stage 3: js analysis
        task = progress.add_task("Analyzing JavaScript...", total=None)
        js_findings = analyze_js(url, fp.get("scripts", []), cookies=cookies, headers=headers, delay=delay)
        results["js_analysis"] = js_findings
        progress.remove_task(task)

        # stage 4: llm summary
        if not no_llm:
            task = progress.add_task("Summarizing with LLM...", total=None)
            summary = summarize(results)
            results["summary"] = summary
            progress.remove_task(task)

    if output_json:
        print(json.dumps(results, indent=2))
        return

    # pretty print
    console.print(Panel(f"[bold cyan]Trace[/bold cyan] — [white]{url}[/white]", expand=False))

    print_section(console, "Fingerprint", results["fingerprint"])

    if results["discovery"]:
        print_section(console, "Discovered Endpoints", results["discovery"])

    if results["js_analysis"]:
        print_section(console, "JS Analysis", results["js_analysis"])

    if results["summary"]:
        console.print(Panel(results["summary"], title="[bold yellow]LLM Summary[/bold yellow]", border_style="yellow"))


if __name__ == "__main__":
    app()
