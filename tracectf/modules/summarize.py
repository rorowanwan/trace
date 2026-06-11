import os
import json


SYSTEM_PROMPT = """You are an expert CTF player analyzing web recon results. 
Your job is to look at recon data and identify the most promising attack vectors for a CTF challenge.
Be specific, concise, and prioritize findings by likelihood of leading to the flag.
Focus on what's unusual, misconfigured, or exploitable — not just what's present.
Format your response as a short bulleted list of actionable leads, max 8 bullets."""


def _build_condensed(results: dict) -> dict:
    return {
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
            for d in results.get("discovery", [])[:30]
        ],
        "js_findings": results.get("js_analysis", []),
    }


def _summarize_gemini(condensed: dict, api_key: str) -> str:
    from google import genai
    client = genai.Client(api_key=api_key)
    prompt = f"{SYSTEM_PROMPT}\n\nHere are the recon results for a CTF web challenge:\n\n{json.dumps(condensed, indent=2)}\n\nWhat are the most promising attack vectors and leads?"
    response = client.models.generate_content(
        model="gemini-2.5-flash",
        contents=prompt,
    )
    return response.text


def _summarize_anthropic(condensed: dict, api_key: str) -> str:
    import anthropic
    client = anthropic.Anthropic(api_key=api_key)
    prompt = f"Here are the recon results for a CTF web challenge:\n\n{json.dumps(condensed, indent=2)}\n\nWhat are the most promising attack vectors and leads?"
    message = client.messages.create(
        model="claude-haiku-4-5",
        max_tokens=600,
        system=SYSTEM_PROMPT,
        messages=[{"role": "user", "content": prompt}],
    )
    return message.content[0].text


def summarize(results: dict) -> str:
    condensed = _build_condensed(results)

    gemini_key = os.environ.get("GEMINI_API_KEY")
    anthropic_key = os.environ.get("ANTHROPIC_API_KEY")

    try:
        if gemini_key:
            return _summarize_gemini(condensed, gemini_key)
        elif anthropic_key:
            return _summarize_anthropic(condensed, anthropic_key)
        else:
            return "[no LLM API key set — export GEMINI_API_KEY or ANTHROPIC_API_KEY]"
    except Exception as e:
        return f"[LLM error: {e}]"
