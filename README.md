# 🩺 SOUP Agent — Google Sheets Edition

A lightweight tool for QARA professionals to track **Software of Unknown Provenance (SOUP)** in SaMD/SiMD development per **IEC 62304**.

## What it does
- You enter a package name and version → agent auto-fills 20+ technical fields
- Stores everything in **your own Google Sheet** (full control, easy sharing, built-in audit trail)
- Auto-refreshes daily at **9:00 AM IST** to catch new vulnerabilities
- Runs free on Streamlit Cloud — no installation on your laptop

## Built for non-technical QARA users
- All technical decisions made by default
- Click-by-click setup guide included
- Familiar tools: a website + a Google Sheet

## Setup

👉 **See `SETUP_GUIDE.md` for the full step-by-step instructions.**

Quick overview:
1. Create a Google Sheet with the right columns (3 min)
2. Create a free Google Cloud project + service account (10 min)
3. Upload code to GitHub (5 min)
4. Deploy free on Streamlit Cloud (5 min)

Total time: ~30 minutes the first time. After that, you just open the app URL in your browser.

## Files in this package

| File | Purpose |
|---|---|
| `SETUP_GUIDE.md` | Complete click-by-click guide for non-technical users |
| `app.py` | The agent code (upload to GitHub) |
| `requirements.txt` | Python dependencies (upload to GitHub) |
| `secrets_template.toml` | Template for Streamlit Cloud secrets configuration |
| `sheet_template_inventory.csv` | Column headers for the main sheet tab |
| `sheet_template_log.csv` | Column headers for the refresh log tab |

## Compliance reference
- IEC 62304 §5.3.3, §5.3.4, §7, §8.1.2 (SOUP requirements)
- IEC 62304 §5.1.4 / FDA CSA (tool validation — applies to this agent itself if used for formal submissions)
- Google Workspace certifications (ISO 27001, SOC 2, HIPAA-eligible) — useful for your validation documentation

## Data sources
- [deps.dev](https://deps.dev) — Google's open package index
- [OSV.dev](https://osv.dev) — Google's open vulnerability database
- [NVD](https://nvd.nist.gov) — NIST's National Vulnerability Database

All free, all reputable, all used by real-world security teams.
