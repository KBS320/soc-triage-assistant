# triage.py — AI-Assisted SOC Alert Triage Assistant
# Reads Sysmon-style events, enriches indicators against VirusTotal, and uses
# Claude to produce a Tier 1 triage summary for each event.

import json
import os
import requests
from dotenv import load_dotenv

load_dotenv()  # read the .env file

VT_KEY = os.getenv("VIRUSTOTAL_API_KEY")
ANTHROPIC_KEY = os.getenv("ANTHROPIC_API_KEY")


def load_events(filename):
    """Open the JSON file and return the list of events inside it."""
    with open(filename, "r") as f:
        return json.load(f)


def check_virustotal(indicator, indicator_type):
    """Ask VirusTotal about an IP or file hash. Return a short verdict string."""
    if not indicator:
        return "No indicator to check"

    if indicator_type == "ip":
        url = f"https://www.virustotal.com/api/v3/ip_addresses/{indicator}"
    else:
        url = f"https://www.virustotal.com/api/v3/files/{indicator}"

    headers = {"x-apikey": VT_KEY}

    try:
        response = requests.get(url, headers=headers, timeout=15)
        if response.status_code == 200:
            data = response.json()
            stats = data["data"]["attributes"]["last_analysis_stats"]
            malicious = stats.get("malicious", 0)
            return f"{malicious} security vendors flagged this as malicious"
        elif response.status_code == 404:
            return "Not found in VirusTotal (no reputation data)"
        else:
            return f"VirusTotal error (status {response.status_code})"
    except Exception as e:
        return f"Could not reach VirusTotal: {e}"


def ai_triage(event, vt_result):
    """Ask Claude to triage one event. Requires ANTHROPIC_API_KEY in .env."""
    if not ANTHROPIC_KEY:
        return "[AI triage skipped — no ANTHROPIC_API_KEY found in .env]"

    import anthropic
    client = anthropic.Anthropic(api_key=ANTHROPIC_KEY)

    prompt = f"""You are a Tier 1 SOC analyst. Triage this Windows security event.

Event details:
- MITRE technique: {event['technique']}
- User: {event['user']}
- Process: {event['image']}
- Command line: {event['command_line']}
- Parent process: {event['parent_image']}
- Threat intel result: {vt_result}

In 3 short sections give:
1. WHAT HAPPENED — one plain sentence.
2. SEVERITY — Low, Medium, or High, with a one-line reason.
3. RECOMMENDED ACTION — what a Tier 1 analyst should do next.
Keep it concise and practical."""

    message = client.messages.create(
        model="claude-sonnet-4-6",
        max_tokens=400,
        messages=[{"role": "user", "content": prompt}],
    )
    return message.content[0].text


def main():
    events = load_events("sample_events.json")
    print(f"Loaded {len(events)} events. Triaging...\n")

    report_lines = []

    for i, event in enumerate(events, start=1):
        print(f"--- Triaging event {i} ({event['technique']}) ---")

        vt = check_virustotal(event.get("src_ip"), "ip")
        if event.get("file_hash"):
            vt_hash = check_virustotal(event["file_hash"], "hash")
            vt = f"IP: {vt} | Hash: {vt_hash}"

        summary = ai_triage(event, vt)

        section = (
            f"\n{'='*60}\n"
            f"EVENT {i} — {event['technique']}\n"
            f"Command: {event['command_line']}\n"
            f"Threat Intel: {vt}\n"
            f"{'-'*60}\n"
            f"{summary}\n"
        )
        report_lines.append(section)
        print(f"Threat Intel: {vt}")
        print(summary + "\n")

    with open("triage_report.txt", "w") as f:
        f.write("".join(report_lines))
    print("Done. Full report saved to triage_report.txt")


if __name__ == "__main__":
    main()
