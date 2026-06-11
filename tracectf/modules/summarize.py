import os
import json
import anthropic


SYSTEM_PROMPT = """You are an expert CTF player analyzing web recon results. 
Your job is to look at recon data and identify the most promising attack vectors for a CTF challenge.
Be specific, concise, and prioritize findings by likelihood of leading to the flag.
Focus on what's unusual, misconfigured, or exploitable — not just what's present.
Format your response as a short bulleted list of actionable leads, max 8 bullets."""


def summarize(results: dict) -> str:
    api_key = os.environ.get("ANTHROPIC_API_KEY")
    if not api_key:
        return "[no ANTHROPIC_API_KEY set — skipping LLM summary]"

    client = anthropic.Anthropic(api_key=api_key)

    # build a condensed version of results for the prompt
    condensed = {
        "url": results.get("url"),
        "fingerprint": {
            "status": results["fingerprint"].get("status_code"),
            "server": results["fingerprint"].get("server"),
            "powered_by": results["fingerprint"].get("powered_by"),
            "detected_tech": results["fingerprint"].get("detected_tech", []),
            "cookies": results["fingerprint"].get("cookies", []),
            "forms": results["fingerprint"].get("forms", []),
            "comments": results["fingerprint"].get("comments", []),
            "interesting_headers": results["fingerprint"].get("interesting_headers", {}),
        },
        "discovered_endpoints": [
            {"url": d.get("url"), "status": d.get("status")}
            for d in results.get("discovery", [])[:30]  # cap to avoid token overflow
        ],
        "js_findings": results.get("js_analysis", []),
    }

    prompt = f"Here are the recon results for a CTF web challenge:\n\n{json.dumps(condensed, indent=2)}\n\nWhat are the most promising attack vectors and leads?"

    try:
        message = client.messages.create(
            model="claude-sonnet-4-20250514",
            max_tokens=600,
            system=SYSTEM_PROMPT,
            messages=[{"role": "user", "content": prompt}],
        )
        return message.content[0].text
    except Exception as e:
        return f"[LLM error: {e}]"
