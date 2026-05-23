"""
SOUP & Tool Agent v5 — AI-Powered with Gemini Integration
==========================================================
For QARA professionals managing SOUP (IEC 62304 §5.3.3) and Tools (§5.1.4 + FDA CSA).

v5 additions:
  - Google Gemini API integration for AI auto-fill (free tier)
  - 5 high-value AI features: Intended Use, Functional Requirements,
    Tool Risk Justification, Impact-if-Tool-Fails, CVE plain-English
  - Bulk import from requirements.txt / package.json with AI classification
  - Help moved to sidebar (accessible from every tab)
  - Logo removed
  - AI audit trail: every AI suggestion marked, requires human review
"""

import streamlit as st
import requests
import time
import json
import pandas as pd
import pytz
from datetime import datetime
from apscheduler.schedulers.background import BackgroundScheduler
from apscheduler.triggers.cron import CronTrigger
import gspread
from google.oauth2.service_account import Credentials

# ============================================================
# CONFIGURATION
# ============================================================

IST = pytz.timezone("Asia/Kolkata")
SOUP_SHEET = "SOUP Inventory"
TOOL_SHEET = "Tool Inventory"
LOG_SHEET = "Refresh Log"

GEMINI_API_BASE = "https://generativelanguage.googleapis.com/v1beta/models"
# Primary model + fallback chain in case Google retires a model in the future.
# Order: try first, then fall back. All are stable free-tier models as of 2026.
GEMINI_MODELS_FALLBACK = [
    "gemini-2.5-flash-lite",   # Free tier: 15 req/min, 1000/day — fastest
    "gemini-2.5-flash",         # Free tier: 10 req/min, 250/day — better quality
    "gemini-flash-latest",      # Generic alias — auto-resolves to current stable
]

ECOSYSTEMS = {
    "npm": "npm — JavaScript / Node.js",
    "PyPI": "PyPI — Python",
    "Maven": "Maven — Java",
    "NuGet": "NuGet — .NET / C#",
    "Go": "Go modules",
    "Cargo": "Cargo — Rust",
    "RubyGems": "RubyGems — Ruby",
}

USAGE_CONTEXT_OPTIONS = [
    "Production (runtime)",
    "Development tooling only",
    "Testing only",
    "Build pipeline only",
    "Documentation generation",
]

TOOL_CATEGORIES = [
    "Build tool / Bundler", "Package manager", "Test framework",
    "Test data / Mocking", "Coverage tool", "Static analysis / Linter",
    "Code formatter", "CI/CD platform / plugin", "Documentation generator",
    "Diagram tool", "Code generator / Transpiler", "Container builder",
    "Debugger / Profiler", "IDE plugin", "Other",
]

TOOL_RISK_LEVELS = ["High", "Medium", "Low"]

VALIDATION_APPROACHES = [
    "Vendor reliance (mature widely-used tool, lightweight evidence)",
    "Unscripted testing (ad-hoc functional checks)",
    "Scripted testing (documented test cases executed)",
    "Scripted with edge cases (formal IQ/OQ + edge case testing)",
]

VALIDATION_STATUSES = ["Pending", "In Validation", "Validated", "Retired"]
ITEM_TYPE_OPTIONS = ["SOUP", "Tool", "Not yet classified"]

SOUP_COLUMNS = [
    "Name", "Version", "Ecosystem", "Item Type",
    "Tool vs SOUP Justification",
    "Publisher", "License", "Description", "Repository URL",
    "Homepage", "Release Date", "Latest Version", "Outdated",
    "CVE Count", "Highest CVSS", "CVE List", "CVE Plain English",
    "Anomaly List",
    "Suggested Safety Class", "Confirmed Safety Class",
    "Intended Use", "Usage Context", "Usage Context Justification",
    "Functional Requirements", "Verification Notes",
    "AI Review Status",  # New: tracks human review of AI suggestions
    "Approval Status", "Owner", "Date Added", "Last Refreshed",
]

TOOL_COLUMNS = [
    "Name", "Version", "Ecosystem", "Item Type",
    "Tool vs SOUP Justification",
    "Publisher", "License", "Description", "Repository URL",
    "Homepage", "Release Date", "Latest Version", "Outdated",
    "CVE Count", "Highest CVSS", "CVE List", "CVE Plain English",
    "Tool Category", "Tool Function in Process",
    "Usage Context", "Usage Context Justification",
    "Tool Risk Level", "Tool Risk Justification",
    "Impact if Tool Fails",
    "Validation Approach", "Validation Approach Justification",
    "Validation Evidence", "Tool Output Verification",
    "Configuration Management",
    "Validation Status", "Last Validation Date",
    "AI Review Status",
    "Approval Status", "Owner", "Date Added", "Last Refreshed",
]

st.set_page_config(
    page_title="SOUP & Tool Agent",
    page_icon="📋",
    layout="wide",
)

# ============================================================
# GOOGLE SHEETS CONNECTION
# ============================================================

@st.cache_resource
def get_gsheet():
    try:
        scopes = ["https://www.googleapis.com/auth/spreadsheets",
                  "https://www.googleapis.com/auth/drive"]
        creds_dict = dict(st.secrets["gcp_service_account"])
        creds = Credentials.from_service_account_info(creds_dict, scopes=scopes)
        client = gspread.authorize(creds)
        return client.open_by_url(st.secrets["sheet_url"])
    except Exception as e:
        st.error(f"❌ Could not connect to Google Sheet. Error: {e}")
        st.stop()

def get_soup_ws(): return get_gsheet().worksheet(SOUP_SHEET)
def get_tool_ws(): return get_gsheet().worksheet(TOOL_SHEET)
def get_log_ws(): return get_gsheet().worksheet(LOG_SHEET)

# Cache sheet reads for 30 seconds to avoid Google Sheets API rate limits
# (60 reads/min/user). Saves/edits invalidate the cache via clear_cache().
@st.cache_data(ttl=30, show_spinner=False)
def _read_sheet_cached(sheet_name):
    """Cached version of sheet read. TTL=30s prevents hitting API rate limits."""
    ws = get_soup_ws() if sheet_name == SOUP_SHEET else get_tool_ws()
    cols = SOUP_COLUMNS if sheet_name == SOUP_SHEET else TOOL_COLUMNS
    records = ws.get_all_records()
    if not records:
        return pd.DataFrame(columns=cols)
    df = pd.DataFrame(records)
    for c in cols:
        if c not in df.columns:
            df[c] = ""
    return df

def read_sheet(sheet_name):
    """Public wrapper. Reads from cache (30s TTL) to respect rate limits."""
    return _read_sheet_cached(sheet_name)

def clear_cache():
    """Clear the sheet cache after any write operation so subsequent reads are fresh."""
    _read_sheet_cached.clear()

def read_all_items():
    soup = read_sheet(SOUP_SHEET).copy()
    tool = read_sheet(TOOL_SHEET).copy()
    soup["_sheet"] = "SOUP"
    tool["_sheet"] = "Tool"
    all_cols = set(soup.columns) | set(tool.columns)
    for c in all_cols:
        if c not in soup.columns: soup[c] = ""
        if c not in tool.columns: tool[c] = ""
    return pd.concat([soup, tool], ignore_index=True, sort=False)

def find_row(sheet_name, name, version, ecosystem):
    df = read_sheet(sheet_name)
    if df.empty: return 0
    mask = ((df["Name"].astype(str).str.lower() == name.lower()) &
            (df["Version"].astype(str) == version) &
            (df["Ecosystem"].astype(str) == ecosystem))
    matches = df.index[mask].tolist()
    return matches[0] + 2 if matches else 0

def upsert_record(record, target_sheet):
    cols = SOUP_COLUMNS if target_sheet == SOUP_SHEET else TOOL_COLUMNS
    ws = get_soup_ws() if target_sheet == SOUP_SHEET else get_tool_ws()
    row_data = [record.get(col, "") for col in cols]
    existing = find_row(target_sheet, record["Name"], record["Version"], record["Ecosystem"])
    
    if existing > 0:
        user_cols = {
            "Item Type", "Tool vs SOUP Justification",
            "Confirmed Safety Class", "Intended Use", "Usage Context",
            "Usage Context Justification", "Functional Requirements",
            "Verification Notes", "Approval Status", "Owner", "Date Added",
            "AI Review Status",
            "Tool Category", "Tool Function in Process",
            "Tool Risk Level", "Tool Risk Justification",
            "Impact if Tool Fails", "Validation Approach",
            "Validation Approach Justification", "Validation Evidence",
            "Tool Output Verification", "Configuration Management",
            "Validation Status", "Last Validation Date",
        }
        for i, col in enumerate(cols):
            if col not in user_cols:
                ws.update_cell(existing, i + 1, row_data[i])
                time.sleep(0.1)
    else:
        ws.append_row(row_data, value_input_option="USER_ENTERED")
    clear_cache()  # invalidate cache after write

def move_item_between_sheets(name, version, ecosystem, from_sheet, to_sheet):
    src_df = read_sheet(from_sheet)
    mask = ((src_df["Name"].astype(str).str.lower() == name.lower()) &
            (src_df["Version"].astype(str) == version) &
            (src_df["Ecosystem"].astype(str) == ecosystem))
    if not mask.any(): return False
    row = src_df[mask].iloc[0].to_dict()
    target_cols = SOUP_COLUMNS if to_sheet == SOUP_SHEET else TOOL_COLUMNS
    target_ws = get_soup_ws() if to_sheet == SOUP_SHEET else get_tool_ws()
    new_row = [row.get(col, "") for col in target_cols]
    target_ws.append_row(new_row, value_input_option="USER_ENTERED")
    src_row_idx = find_row(from_sheet, name, version, ecosystem)
    if src_row_idx > 0:
        src_ws = get_soup_ws() if from_sheet == SOUP_SHEET else get_tool_ws()
        src_ws.delete_rows(src_row_idx)
    clear_cache()
    return True

def update_user_fields(sheet_name, name, version, ecosystem, updates):
    ws = get_soup_ws() if sheet_name == SOUP_SHEET else get_tool_ws()
    cols = SOUP_COLUMNS if sheet_name == SOUP_SHEET else TOOL_COLUMNS
    row = find_row(sheet_name, name, version, ecosystem)
    if row == 0: return False
    for field, value in updates.items():
        if field in cols:
            ws.update_cell(row, cols.index(field) + 1, value)
            time.sleep(0.1)
    clear_cache()
    return True

def delete_row(sheet_name, name, version, ecosystem):
    ws = get_soup_ws() if sheet_name == SOUP_SHEET else get_tool_ws()
    row = find_row(sheet_name, name, version, ecosystem)
    if row > 0:
        ws.delete_rows(row)
        clear_cache()

def log_refresh(trigger, items, new_cves, notes=""):
    try:
        get_log_ws().append_row([
            datetime.now(IST).isoformat(), trigger, items, new_cves, notes
        ], value_input_option="USER_ENTERED")
    except Exception:
        pass

# ============================================================
# GEMINI AI INTEGRATION
# ============================================================

def gemini_available():
    """Check if Gemini API key is configured."""
    try:
        return bool(st.secrets.get("gemini_api_key"))
    except Exception:
        return False

def call_gemini(prompt: str, max_tokens: int = 500) -> str:
    """Call Gemini API. Returns text response or error string starting with 'ERROR:'.
    
    Tries each model in GEMINI_MODELS_FALLBACK until one works. Handles:
    - Missing API key
    - Rate limits
    - Model retired (404)
    - Safety filter blocks
    - Empty responses
    - Network errors
    """
    api_key = st.secrets.get("gemini_api_key", "")
    if not api_key:
        return "ERROR: Gemini API key not configured. Add 'gemini_api_key' to Streamlit secrets."
    
    payload = {
        "contents": [{"parts": [{"text": prompt}]}],
        "generationConfig": {
            "temperature": 0.3,
            "maxOutputTokens": max_tokens,
        },
        # Loosen safety settings — we're discussing software libraries, not actual medical content
        "safetySettings": [
            {"category": "HARM_CATEGORY_HARASSMENT", "threshold": "BLOCK_NONE"},
            {"category": "HARM_CATEGORY_HATE_SPEECH", "threshold": "BLOCK_NONE"},
            {"category": "HARM_CATEGORY_SEXUALLY_EXPLICIT", "threshold": "BLOCK_NONE"},
            {"category": "HARM_CATEGORY_DANGEROUS_CONTENT", "threshold": "BLOCK_NONE"},
        ],
    }
    
    last_error = "ERROR: No models could process this request"
    
    for model_name in GEMINI_MODELS_FALLBACK:
        url = f"{GEMINI_API_BASE}/{model_name}:generateContent?key={api_key}"
        try:
            r = requests.post(url, json=payload, timeout=30)
            
            # HTTP-level errors
            if r.status_code == 429:
                return "ERROR: Rate limit exceeded (15 req/min, 1000/day on free tier). Wait 60 seconds and try again."
            
            if r.status_code == 400:
                # Bad request — show what API said
                err_text = r.text[:300]
                return f"ERROR: Bad request to Gemini (400). API said: {err_text}"
            
            if r.status_code == 403:
                return f"ERROR: API key invalid or quota exhausted (403). Regenerate key at aistudio.google.com/apikey"
            
            if r.status_code == 404:
                last_error = f"ERROR: Model '{model_name}' not found (404), trying fallback..."
                continue
            
            if r.status_code != 200:
                last_error = f"ERROR: Gemini returned HTTP {r.status_code}. {r.text[:200]}"
                continue
            
            # HTTP 200 — parse response
            try:
                data = r.json()
            except Exception as e:
                last_error = f"ERROR: Could not parse JSON from Gemini. {str(e)[:100]}"
                continue
            
            # Check for prompt-level blocking
            if "promptFeedback" in data:
                block_reason = data["promptFeedback"].get("blockReason", "")
                if block_reason:
                    return f"ERROR: Prompt blocked by Gemini safety filter ({block_reason}). Try rephrasing the package description."
            
            # Check candidates
            candidates = data.get("candidates", [])
            if not candidates:
                last_error = f"ERROR: Gemini returned no candidates. Raw response: {str(data)[:200]}"
                continue
            
            cand = candidates[0]
            
            # Check finish reason
            finish_reason = cand.get("finishReason", "")
            if finish_reason == "SAFETY":
                return "ERROR: Response blocked by Gemini safety filter. Try rephrasing the input."
            if finish_reason == "RECITATION":
                return "ERROR: Response blocked due to recitation concerns. Try rephrasing."
            
            # Extract text
            content = cand.get("content", {})
            parts = content.get("parts", [])
            if not parts:
                last_error = (f"ERROR: Gemini returned empty content (finish_reason: {finish_reason}). "
                              f"Raw candidate: {str(cand)[:200]}")
                continue
            
            text = parts[0].get("text", "").strip()
            if not text:
                last_error = f"ERROR: Gemini returned blank text. Finish reason: {finish_reason}"
                continue
            
            # SUCCESS
            return text
            
        except requests.exceptions.Timeout:
            last_error = f"ERROR: Gemini timed out after 30s on model {model_name}"
            continue
        except requests.exceptions.ConnectionError:
            return "ERROR: Could not connect to Gemini. Check your internet."
        except Exception as e:
            last_error = f"ERROR: Unexpected error calling {model_name}: {str(e)[:150]}"
            continue
    
    return last_error

# AI prompt templates ---

def ai_intended_use(name, version, ecosystem, description, usage_context=""):
    prompt = f"""You are a QARA expert helping document SOUP for a medical device per IEC 62304 §5.3.3.

Package: {name} {version} ({ecosystem})
Package description: {description}
Usage context: {usage_context or "Not specified"}

Write a single 1-2 sentence "Intended Use" statement describing how this package is typically used in a SaMD (Software as a Medical Device) application. Be specific about the function it serves. Do NOT mention the company name or specific product. Format: "Used for [specific purpose] in the [module/component type]."

Output ONLY the statement, no preamble, no explanation, no quotes."""
    return call_gemini(prompt, max_tokens=200)

def ai_functional_requirements(name, version, description, intended_use=""):
    prompt = f"""You are a QARA expert documenting SOUP for a medical device per IEC 62304 §5.3.3.

Package: {name} {version}
Description: {description}
Intended use: {intended_use or "General use"}

Draft 3-5 specific functional and performance requirements this SOUP must satisfy. Focus on:
- What the package must do correctly
- Performance characteristics (accuracy, speed, throughput where applicable)
- Error handling expectations
- Input/output behavior

Format as bullet points starting with "•". Each bullet on a new line. Be specific and testable. Do NOT include generic requirements like "must be reliable."

Output ONLY the bullet list, no preamble."""
    return call_gemini(prompt, max_tokens=400)

def ai_tool_risk_justification(name, description, risk_level, tool_function=""):
    prompt = f"""You are a QARA expert assessing a development tool per FDA CSA (Computer Software Assurance) guidance.

Tool: {name}
Description: {description}
Tool function in process: {tool_function or "Not specified"}
Assigned risk level: {risk_level}

Write a 2-3 sentence justification for why this tool is classified as {risk_level} risk per FDA CSA. Reference the CSA risk-based approach. Mention what defects could occur and their potential impact on product quality or V&V evidence.

Output ONLY the justification paragraph, no preamble."""
    return call_gemini(prompt, max_tokens=300)

def ai_impact_if_fails(name, description, tool_function=""):
    prompt = f"""You are a QARA expert assessing development tool risks for a medical device.

Tool: {name}
Description: {description}
Tool function: {tool_function or "Not specified"}

Describe 2-3 specific failure scenarios for this tool and their concrete impact on the medical device development process. Be specific — name actual failure modes (e.g., "false-pass test results", "corrupted bundled output", "missed CVE in dependency tree"). Do not be generic.

Format as a single paragraph (3-4 sentences). Output ONLY the paragraph."""
    return call_gemini(prompt, max_tokens=300)

def ai_cve_plain_english(cve_id, cve_summary, cvss_score):
    prompt = f"""You are explaining a security vulnerability to a non-technical QARA professional.

CVE ID: {cve_id}
Technical summary: {cve_summary}
CVSS score: {cvss_score}

Explain in 2 short sentences:
1. What the vulnerability actually does (in plain English, no jargon)
2. When it matters for a typical medical software application

Avoid: technical acronyms, code snippets, hypothetical attacks. Focus on practical impact.

Output ONLY the explanation, no preamble."""
    return call_gemini(prompt, max_tokens=200)

def ai_classify_bulk_item(name, ecosystem, description=""):
    """For bulk import: classify a single item as SOUP or Tool."""
    prompt = f"""You are a QARA expert classifying software per IEC 62304.

Package: {name} ({ecosystem})
Description: {description}

Classify this as either "SOUP" (incorporated into medical device, ships with product) or "Tool" (used in development/build/test, NOT shipped).

Respond with a JSON object only (no markdown, no preamble):
{{"classification": "SOUP" or "Tool", "confidence": "High" or "Medium" or "Low", "reasoning": "one sentence why"}}"""
    response = call_gemini(prompt, max_tokens=200)
    if response.startswith("ERROR"):
        return None
    # Try to parse JSON
    try:
        # Strip markdown code fences if present
        cleaned = response.strip()
        if cleaned.startswith("```"):
            cleaned = cleaned.split("```")[1]
            if cleaned.startswith("json"):
                cleaned = cleaned[4:]
            cleaned = cleaned.strip()
        return json.loads(cleaned)
    except Exception:
        return None

# ============================================================
# EXTERNAL APIs (deps.dev, OSV, NVD)
# ============================================================

def fetch_depsdev(eco, name, version):
    try:
        r = requests.get(f"https://api.deps.dev/v3/systems/{eco}/packages/{name}/versions/{version}", timeout=15)
        if r.status_code == 200: return r.json()
    except Exception: pass
    return {}

def fetch_depsdev_latest(eco, name):
    try:
        r = requests.get(f"https://api.deps.dev/v3/systems/{eco}/packages/{name}", timeout=15)
        if r.status_code == 200:
            data = r.json()
            versions = data.get("versions", [])
            for v in versions:
                if v.get("isDefault"):
                    return v.get("versionKey", {}).get("version", "")
            if versions:
                return versions[-1].get("versionKey", {}).get("version", "")
    except Exception: pass
    return ""

def fetch_osv_vulns(eco, name, version):
    try:
        r = requests.post("https://api.osv.dev/v1/query",
                          json={"package": {"name": name, "ecosystem": eco}, "version": version}, timeout=15)
        if r.status_code == 200: return r.json().get("vulns", [])
    except Exception: pass
    return []

def fetch_nvd_cvss(cve_id):
    try:
        r = requests.get(f"https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={cve_id}", timeout=15)
        if r.status_code == 200:
            data = r.json()
            for item in data.get("vulnerabilities", []):
                metrics = item.get("cve", {}).get("metrics", {})
                for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
                    if key in metrics and metrics[key]:
                        return metrics[key][0].get("cvssData", {}).get("baseScore", 0.0)
    except Exception: pass
    return 0.0

def severity_label(s):
    if s == 0: return "—"
    if s < 4: return "Low"
    if s < 7: return "Medium"
    if s < 9: return "High"
    return "Critical"

def suggest_safety_class(cve_count, highest_cvss, is_outdated, item_type):
    if item_type == "Tool":
        return "N/A — Tool (use §5.1.4 + FDA CSA, not SOUP safety class)"
    if highest_cvss >= 7.0 or cve_count >= 3:
        return "Class B/C — HUMAN REVIEW REQUIRED (significant vulns)"
    if is_outdated and cve_count > 0:
        return "Class B — HUMAN REVIEW REQUIRED (outdated with vulns)"
    return "Class A (suggested — confirm based on usage)"

# ============================================================
# ENRICHMENT
# ============================================================

def enrich(eco, name, version, item_type="SOUP"):
    meta = fetch_depsdev(eco, name, version)
    latest = fetch_depsdev_latest(eco, name)
    is_outdated = bool(latest and latest != version)
    vulns = fetch_osv_vulns(eco, name, version)
    
    cves = []
    highest_cvss = 0.0
    for v in vulns:
        cve_ids = [a for a in v.get("aliases", []) if a.startswith("CVE-")]
        primary = cve_ids[0] if cve_ids else v.get("id", "Unknown")
        score = 0.0
        if cve_ids:
            score = fetch_nvd_cvss(cve_ids[0])
            time.sleep(0.6)
        cves.append({
            "id": primary, "summary": v.get("summary", "")[:200],
            "cvss": score, "severity": severity_label(score),
        })
        if score > highest_cvss: highest_cvss = score
    
    licenses = meta.get("licenses", [])
    license_str = ", ".join(licenses) if licenses else "Unknown"
    links = meta.get("links", [])
    repo_url = next((l["url"] for l in links if l.get("label") == "SOURCE_REPO"), "")
    homepage = next((l["url"] for l in links if l.get("label") == "HOMEPAGE"), "")
    
    cve_text = "\n".join([
        f"• {c['id']} [{c['severity']}, CVSS {c['cvss']}]: {c['summary']}"
        for c in cves
    ]) or "No known vulnerabilities"
    
    anomaly_text = "\n".join([f"• {c['id']}: {c['summary']}" for c in cves]) \
        or "None identified from public sources"
    
    base = {
        "Name": name, "Version": version, "Ecosystem": eco,
        "Item Type": item_type, "Tool vs SOUP Justification": "",
        "Publisher": meta.get("registries", [eco])[0] if meta.get("registries") else eco,
        "License": license_str,
        "Description": meta.get("description", "")[:500] or f"{name} {version}",
        "Repository URL": repo_url, "Homepage": homepage,
        "Release Date": meta.get("publishedAt", ""),
        "Latest Version": latest,
        "Outdated": "Yes" if is_outdated else "No",
        "CVE Count": len(cves), "Highest CVSS": highest_cvss,
        "CVE List": cve_text, "CVE Plain English": "",
        "Approval Status": "Draft", "Owner": "",
        "AI Review Status": "No AI suggestions yet",
        "Date Added": datetime.now(IST).strftime("%Y-%m-%d %H:%M IST"),
        "Last Refreshed": datetime.now(IST).strftime("%Y-%m-%d %H:%M IST"),
        "Usage Context": "", "Usage Context Justification": "",
    }
    
    if item_type == "Tool":
        base.update({
            "Tool Category": "", "Tool Function in Process": "",
            "Tool Risk Level": "", "Tool Risk Justification": "",
            "Impact if Tool Fails": "", "Validation Approach": "",
            "Validation Approach Justification": "", "Validation Evidence": "",
            "Tool Output Verification": "", "Configuration Management": "",
            "Validation Status": "Pending", "Last Validation Date": "",
        })
    else:
        base.update({
            "Anomaly List": anomaly_text,
            "Suggested Safety Class": suggest_safety_class(len(cves), highest_cvss, is_outdated, item_type),
            "Confirmed Safety Class": "", "Intended Use": "",
            "Functional Requirements": "", "Verification Notes": "",
        })
    
    return base

# ============================================================
# REFRESH
# ============================================================

def refresh_all(trigger="manual"):
    soup_df = read_sheet(SOUP_SHEET)
    tool_df = read_sheet(TOOL_SHEET)
    if soup_df.empty and tool_df.empty:
        log_refresh(trigger, 0, 0, "Nothing to refresh")
        return 0, 0
    total = 0
    new_cves_total = 0
    for sheet_name, df, item_type in [(SOUP_SHEET, soup_df, "SOUP"), (TOOL_SHEET, tool_df, "Tool")]:
        for _, row in df.iterrows():
            try:
                old = int(row.get("CVE Count", 0) or 0)
                rec = enrich(row["Ecosystem"], row["Name"], str(row["Version"]), item_type)
                diff = rec["CVE Count"] - old
                if diff > 0: new_cves_total += diff
                upsert_record(rec, sheet_name)
                total += 1
            except Exception as e:
                print(f"Refresh failed for {row.get('Name','?')}: {e}")
    log_refresh(trigger, total, new_cves_total)
    return total, new_cves_total

# ============================================================
# SCHEDULER
# ============================================================

@st.cache_resource
def get_scheduler():
    s = BackgroundScheduler(timezone=IST)
    s.add_job(lambda: refresh_all("scheduled_9am_IST"),
              CronTrigger(hour=9, minute=0, timezone=IST),
              id="daily_refresh", replace_existing=True)
    s.start()
    return s

scheduler = get_scheduler()

# ============================================================
# CLASSIFIERS
# ============================================================

def classify_tool_vs_soup(answers):
    q1 = answers.get("ships_in_device")
    q2 = answers.get("output_in_device")
    q3 = answers.get("affects_quality")
    if q1 == "Yes":
        return ("SOUP",
                "This item is incorporated into the released medical device — its code runs on the device "
                "or as part of the released software. Therefore classified as SOUP per IEC 62304 §3.31. "
                "Apply §5.3.3, §5.3.4, and §7 requirements.")
    if q1 == "No":
        base = "This item does NOT ship inside the medical device — its code does not execute on the customer's device or as part of the released product. "
        if q2 == "Yes":
            return ("Tool", base + "However, it transforms code or generates content that DOES ship. "
                    "Therefore classified as a Tool per IEC 62304 §5.1.4. Apply tool validation proportional to risk (FDA CSA approach).")
        if q3 == "Yes":
            return ("Tool", base + "It produces evidence used in V&V or quality decisions. "
                    "Therefore classified as a Tool per IEC 62304 §5.1.4. Validate to ensure reliable verification evidence (FDA CSA risk-based approach).")
        return ("Tool", base + "It is used only for developer convenience and does not affect product code, output, or V&V evidence. "
                "Classified as low-risk Tool per IEC 62304 §5.1.4. Minimal validation required.")
    return ("Not yet classified", "Insufficient information to classify.")

def determine_usage_context(answers):
    if answers.get("runs_in_device") == "Yes":
        return ("Production (runtime)",
                "Executes within the medical device during normal operation. In scope for full IEC 62304 §5.3.3 / §5.3.4 SOUP treatment.")
    if answers.get("produces_test_evidence") == "Yes":
        return ("Testing only",
                "Used to produce V&V evidence. Validate per IEC 62304 §5.1.4 with rigor proportional to evidence importance (FDA CSA approach).")
    if answers.get("transforms_shipped_code") == "Yes":
        return ("Build pipeline only",
                "Compiles, packages, or transforms code that ships in the device. Address under supply-chain integrity and tool validation.")
    if answers.get("generates_customer_content") == "Yes":
        return ("Documentation generation",
                "Generates content visible to end users. Output is regulated under FDA 21 CFR 801 / EU MDR Annex I labeling rules.")
    return ("Development tooling only",
            "Runs only on developer machines. Lightweight tool documentation per IEC 62304 §5.1.4.")

def classify_tool_risk(answers):
    a1 = answers.get("affects_product_safety")
    a2 = answers.get("affects_vv_evidence")
    a3 = answers.get("affects_quality")
    a4 = answers.get("other_controls_catch")
    if a1 == "Yes":
        return ("High", "A defect in this tool could lead to a product safety issue. Per FDA CSA, apply scripted testing with edge cases. Document IQ/OQ and ongoing change control.")
    if a2 == "Yes":
        return ("High", "Produces V&V evidence used for release decisions. A false-pass or false-fail could lead to incorrect release decisions. Per FDA CSA, apply scripted testing.")
    if a3 == "Yes" and a4 == "No":
        return ("Medium", "Affects product quality but a defect would not directly cause safety harm. Other controls provide secondary defense. Per FDA CSA, unscripted functional testing is appropriate.")
    if a3 == "Yes" and a4 == "Yes":
        return ("Low", "Downstream controls would catch any tool-introduced defect. Per FDA CSA, vendor reliance with light internal smoke checks is sufficient.")
    return ("Low", "Does not affect shipped product, V&V evidence, or customer-facing content. Per FDA CSA, minimal validation required.")

def suggest_validation_approach(risk_level):
    if risk_level == "High":
        return ("Scripted with edge cases (formal IQ/OQ + edge case testing)",
                "Per FDA CSA, High-risk tools warrant scripted testing covering normal use AND edge cases.")
    if risk_level == "Medium":
        return ("Scripted testing (documented test cases executed)",
                "Per FDA CSA, Medium-risk tools warrant scripted but lighter testing.")
    return ("Vendor reliance (mature widely-used tool, lightweight evidence)",
            "Per FDA CSA 'least burdensome' principle, Low-risk tools can rely on vendor evidence.")

# ============================================================
# UI
# ============================================================

st.title("SOUP & Tool Agent")
st.caption("IEC 62304 §5.3.3 (SOUP) + §5.1.4 + FDA CSA (Tools) for SaMD / SiMD")

# ----- SIDEBAR -----
with st.sidebar:
    st.header("⚙️ Controls")
    if st.button("🔄 Refresh All Now", type="primary", use_container_width=True):
        with st.spinner("Refreshing all items..."):
            n, new_cves = refresh_all("manual_button")
        st.success(f"Refreshed {n} items. {new_cves} new CVEs found.")
        st.rerun()
    
    st.divider()
    
    # Daily refresh schedule
    st.markdown("**🕘 Daily auto-refresh:** 9:00 AM IST")
    try:
        next_run = scheduler.get_job("daily_refresh").next_run_time
        if next_run:
            st.caption(f"Next: {next_run.strftime('%Y-%m-%d %H:%M %Z')}")
    except Exception: pass
    
    st.divider()
    
    # Workbook link
    sheet_url = st.secrets.get("sheet_url", "")
    if sheet_url:
        st.markdown(f"[📊 Open Workbook ↗]({sheet_url})")
    st.caption("Workbook: SOUP, Tool, Refresh Log tabs.")
    
    st.divider()
    
    # AI status
    st.markdown("**🤖 AI Status**")
    if gemini_available():
        st.success("Gemini AI enabled")
        st.caption("AI auto-fill available on review tabs")
        
        # Diagnostic button — helps when AI fails silently
        if st.button("🔬 Test Gemini connection", use_container_width=True):
            with st.spinner("Testing..."):
                test_result = call_gemini(
                    "Reply with exactly one word: WORKING",
                    max_tokens=10,
                )
            if test_result.startswith("ERROR"):
                st.error(test_result)
                st.caption("⚠️ AI suggest buttons will fail. Fix the error above first.")
            elif "WORKING" in test_result.upper():
                st.success(f"✅ Gemini responded: '{test_result}'")
                st.caption("AI suggest buttons should work.")
            else:
                st.warning(f"⚠️ Unexpected response: '{test_result[:100]}'")
                st.caption("Connection works but response is odd. AI buttons may behave strangely.")
    else:
        st.warning("Gemini AI not configured")
        with st.expander("Enable AI features"):
            st.markdown("""
1. Go to [aistudio.google.com/apikey](https://aistudio.google.com/apikey)
2. Click "Create API key"
3. Copy the key
4. In Streamlit Cloud: Settings → Secrets
5. Add line: `gemini_api_key = "YOUR_KEY"`
6. Reboot app

Free tier: 1500 requests/day. No credit card needed.
            """)
    
    st.divider()
    
    # HELP IN SIDEBAR (replaces the Help tab)
    with st.expander("❓ Help & Definitions", expanded=False):
        st.markdown("""
**Workbook structure:**
- 📦 SOUP Inventory — items in the device (§5.3.3)
- 🛠️ Tool Inventory — dev/build/test tools (§5.1.4 + FDA CSA)
- 📋 Refresh Log — audit trail

**Quick rules:**
- SOUP = code that ships in the device
- Tool = code used to build/test/maintain the device
- Tools and SOUP are documented differently

**Tool Risk Levels (FDA CSA):**
- 🔴 High = could cause safety issue or false V&V
- 🟡 Medium = affects quality, secondary controls exist
- 🟢 Low = limited impact

**Usage Contexts:**
- Production (runtime)
- Development tooling only
- Testing only
- Build pipeline only
- Documentation generation

**AI features (Gemini):**
Look for "✨ AI suggest" buttons. AI drafts → you review → you approve.
Every AI suggestion is marked in the "AI Review Status" column.

**Audit trail:**
Google Sheets revision history shows every change.
Click File → Version history in your workbook.
""")
    
    with st.expander("📚 IEC 62304 / FDA references"):
        st.markdown("""
- **§5.3.3** — SOUP functional/performance requirements
- **§5.3.4** — SOUP environment / anomaly list
- **§7** — SOUP risk-related items
- **§5.1.4** — Software tools used in development
- **FDA CSA (2022)** — Risk-based tool validation
- **FDA SBOM Guidance** — Software Bill of Materials
- **ISO 14971** — Risk management
- **21 CFR Part 11 / EU Annex 11** — Electronic records
""")

# ----- MAIN TABS -----
tab1, tab2, tab3, tab4, tab5, tab6 = st.tabs([
    "➕ Add Item",
    "🤔 Classify",
    "📦 Bulk Import",
    "📊 Inventory",
    "✅ SOUP Review",
    "🛠️ Tool Review",
])

# ============================================================
# TAB 1: ADD ITEM
# ============================================================
with tab1:
    st.subheader("Add a new item")
    
    col1, col2, col3 = st.columns([2, 2, 2])
    with col1:
        ecosystem = st.selectbox("Ecosystem", list(ECOSYSTEMS.keys()),
                                  format_func=lambda x: ECOSYSTEMS[x],
                                  help="The registry your developer uses to download this package.")
    with col2:
        name = st.text_input("Package name", placeholder="e.g., lodash, numpy")
    with col3:
        version = st.text_input("Version", placeholder="e.g., 4.17.21")
    
    item_type = st.radio(
        "Item Type",
        ITEM_TYPE_OPTIONS, horizontal=True,
        help="SOUP = ships in device. Tool = used in dev/build/test. Not sure? Use '🤔 Classify' tab.",
    )
    
    if item_type == "Not yet classified":
        st.warning("⚠️ Use the '🤔 Classify' tab first.")
    elif item_type == "SOUP":
        st.success("📦 Will be saved to **SOUP Inventory**")
    else:
        st.info("🛠️ Will be saved to **Tool Inventory**")
    
    st.markdown("---")
    st.markdown("**Optional now — fill later in the review tabs:**")
    
    col4, col5 = st.columns(2)
    with col4:
        intended_use = st.text_area("Intended use", height=80,
                                    placeholder="e.g., Parses patient JSON in registration module")
    with col5:
        usage_context = st.selectbox("Usage context", [""] + USAGE_CONTEXT_OPTIONS)
    owner = st.text_input("Owner", placeholder="Your name / team")
    
    if st.button("✨ Generate Record", type="primary"):
        if not name.strip() or not version.strip():
            st.error("Please enter both name and version.")
        elif item_type == "Not yet classified":
            st.error("Please classify the item first.")
        else:
            with st.spinner(f"Fetching data for {name}@{version}..."):
                try:
                    record = enrich(ecosystem, name.strip(), version.strip(), item_type)
                    if intended_use and item_type == "SOUP":
                        record["Intended Use"] = intended_use
                    if usage_context:
                        record["Usage Context"] = usage_context
                    if owner:
                        record["Owner"] = owner
                    target = SOUP_SHEET if item_type == "SOUP" else TOOL_SHEET
                    upsert_record(record, target)
                    st.success(f"✅ Added to **{target}**: {name}@{version}")
                    
                    c1, c2, c3, c4 = st.columns(4)
                    c1.metric("License", record["License"])
                    c2.metric("CVEs", record["CVE Count"])
                    c3.metric("Max CVSS", f"{record['Highest CVSS']:.1f}" if record["Highest CVSS"] else "—")
                    c4.metric("Outdated", record["Outdated"])
                    
                    if record["CVE Count"] > 0:
                        st.warning(f"⚠️ {record['CVE Count']} vulnerabilities found.")
                    if record["Outdated"] == "Yes":
                        st.info(f"ℹ️ Latest version: {record['Latest Version']}")
                    if item_type == "SOUP":
                        st.info(f"💡 Suggested safety class: **{record['Suggested Safety Class']}**")
                    
                    st.caption("Open the review tab to add details and (optionally) AI auto-fill.")
                except Exception as e:
                    st.error(f"Error: {e}")

# ============================================================
# TAB 2: CLASSIFY
# ============================================================
with tab2:
    st.subheader("🤔 Is this item SOUP or a Tool?")
    st.markdown("Answer up to **3 questions**. The classifier writes a justification and routes the item to the correct sheet.")
    
    all_df = read_all_items()
    classify_existing = False
    selected_item = None
    selected_sheet = None
    
    if not all_df.empty:
        classify_existing = st.checkbox("Classify an existing item")
        if classify_existing:
            labels = [f"[{r['_sheet']}] {r['Name']}@{r['Version']} ({r['Ecosystem']}) — {r.get('Item Type','—')}"
                      for _, r in all_df.iterrows()]
            idx = st.selectbox("Select item", range(len(labels)), format_func=lambda i: labels[i])
            selected_item = all_df.iloc[idx]
            selected_sheet = SOUP_SHEET if selected_item["_sheet"] == "SOUP" else TOOL_SHEET
    
    st.divider()
    
    st.markdown("### Question 1")
    st.markdown("**Does this software's code run on the customer's medical device, or get shipped inside the released product?**")
    st.caption("✅ YES: JSON parser in your SaMD, ML library running the diagnostic, crypto in the device  |  ❌ NO: code formatter, test framework, build tool")
    q1 = st.radio("Q1", ["Not yet answered", "Yes — runs inside the device", "No — never runs on the device"],
                  key="cq1", label_visibility="collapsed")
    q1_value = "Yes" if q1.startswith("Yes") else ("No" if q1.startswith("No") else None)
    
    q2_value = None
    q3_value = None
    
    if q1_value == "No":
        st.markdown("### Question 2")
        st.markdown("**Does this software produce or transform anything that ends up in the released device?**")
        st.caption("✅ YES: build tools, code generators, IFU generators  |  ❌ NO: test results, log files")
        q2 = st.radio("Q2", ["Not yet answered", "Yes — output ships in device/labeling", "No — output stays internal"],
                      key="cq2", label_visibility="collapsed")
        q2_value = "Yes" if q2.startswith("Yes") else ("No" if q2.startswith("No") else None)
        
        if q2_value == "No":
            st.markdown("### Question 3")
            st.markdown("**Does this software produce evidence used to verify or validate the device's quality?**")
            st.caption("✅ YES: pytest, coverage tools, static analyzers  |  ❌ NO: formatters, IDE plugins")
            q3 = st.radio("Q3", ["Not yet answered", "Yes — produces V&V evidence", "No — purely developer convenience"],
                          key="cq3", label_visibility="collapsed")
            q3_value = "Yes" if q3.startswith("Yes") else ("No" if q3.startswith("No") else None)
    
    chain_done = (q1_value == "Yes" or
                  (q1_value == "No" and q2_value == "Yes") or
                  (q1_value == "No" and q2_value == "No" and q3_value is not None))
    
    if chain_done:
        st.divider()
        answers = {"ships_in_device": q1_value, "output_in_device": q2_value, "affects_quality": q3_value}
        classification, justification = classify_tool_vs_soup(answers)
        
        if classification == "SOUP":
            st.error(f"### 📦 Classification: **{classification}**")
        else:
            st.warning(f"### 🛠️ Classification: **{classification}**")
        st.markdown(f"**Justification:**\n\n{justification}")
        
        if classify_existing and selected_item is not None:
            current_type = selected_item.get("Item Type", "")
            target_sheet = SOUP_SHEET if classification == "SOUP" else TOOL_SHEET
            if classification != current_type:
                st.warning(f"Currently **{current_type or 'unclassified'}** in **{selected_item['_sheet']}**. Will be moved to **{target_sheet}**.")
            if st.button("💾 Save classification", type="primary"):
                if classification != current_type and selected_sheet != target_sheet:
                    move_item_between_sheets(
                        selected_item["Name"], str(selected_item["Version"]), selected_item["Ecosystem"],
                        selected_sheet, target_sheet
                    )
                    update_user_fields(target_sheet, selected_item["Name"], str(selected_item["Version"]),
                                       selected_item["Ecosystem"],
                                       {"Item Type": classification, "Tool vs SOUP Justification": justification})
                    st.success(f"✅ Classified as {classification} and moved to {target_sheet}.")
                else:
                    update_user_fields(selected_sheet, selected_item["Name"], str(selected_item["Version"]),
                                       selected_item["Ecosystem"],
                                       {"Item Type": classification, "Tool vs SOUP Justification": justification})
                    st.success(f"✅ Saved.")

# ============================================================
# TAB 3: BULK IMPORT (NEW)
# ============================================================
with tab3:
    st.subheader("📦 Bulk Import from Dependency File")
    
    st.markdown("""
Upload your dev team's dependency file and the agent will:
1. Parse each package (name + version)
2. Fetch metadata, license, CVEs from public databases
3. **(If Gemini AI is enabled)** Classify each as SOUP or Tool with AI
4. Route each to the correct sheet

**Supported formats:** `requirements.txt` (Python), `package.json` (npm)
""")
    
    if not gemini_available():
        st.warning("⚠️ Gemini AI not configured. Items will be imported as 'Not yet classified' — you'll classify them manually using the Classify tab. Configure Gemini for auto-classification (see sidebar).")
    
    uploaded_file = st.file_uploader(
        "Upload dependency file",
        type=["txt", "json"],
        help="Drop your requirements.txt or package.json here"
    )
    
    if uploaded_file is not None:
        content = uploaded_file.read().decode("utf-8")
        st.text_area("File preview", value=content[:1000], height=150)
        
        # Parse based on file type
        items_to_import = []
        if uploaded_file.name.endswith(".json"):
            try:
                data = json.loads(content)
                deps = {}
                deps.update(data.get("dependencies", {}))
                deps.update(data.get("devDependencies", {}))
                for pkg_name, pkg_version in deps.items():
                    # Strip ^ ~ etc.
                    v = pkg_version.lstrip("^~>=<! ").split(" ")[0]
                    items_to_import.append({"ecosystem": "npm", "name": pkg_name, "version": v})
            except Exception as e:
                st.error(f"Could not parse JSON: {e}")
        elif uploaded_file.name.endswith(".txt") or "requirements" in uploaded_file.name.lower():
            for line in content.splitlines():
                line = line.strip()
                if not line or line.startswith("#"): continue
                # Handle pkg==1.2.3 format
                for sep in ["==", ">=", "<=", "~=", ">"]:
                    if sep in line:
                        parts = line.split(sep)
                        if len(parts) == 2:
                            items_to_import.append({
                                "ecosystem": "PyPI",
                                "name": parts[0].strip(),
                                "version": parts[1].strip().split(";")[0].split(" ")[0].strip(),
                            })
                            break
        
        if items_to_import:
            st.success(f"Found {len(items_to_import)} packages.")
            st.dataframe(pd.DataFrame(items_to_import), hide_index=True, use_container_width=True)
            
            owner_bulk = st.text_input("Owner for all items", placeholder="Your name / team")
            
            if st.button("🚀 Import All", type="primary"):
                progress = st.progress(0)
                status = st.empty()
                soup_count = 0
                tool_count = 0
                unclassified_count = 0
                ai_classified = 0
                ai_failed = 0
                
                for i, item in enumerate(items_to_import):
                    progress.progress((i + 1) / len(items_to_import))
                    status.write(f"Processing {item['name']}@{item['version']}...")
                    
                    # Determine item type
                    item_type = "Not yet classified"
                    tool_soup_just = ""
                    
                    # Fetch first to get description
                    try:
                        # First do basic enrichment as "Not yet classified" to get the description
                        temp_record = enrich(item["ecosystem"], item["name"], item["version"], "SOUP")
                        description = temp_record.get("Description", "")
                        
                        # Try AI classification if available
                        if gemini_available():
                            result = ai_classify_bulk_item(item["name"], item["ecosystem"], description)
                            if result and result.get("classification") in ("SOUP", "Tool"):
                                item_type = result["classification"]
                                tool_soup_just = (
                                    f"[AI-suggested, confidence: {result.get('confidence','Medium')}] "
                                    f"{result.get('reasoning','')} — REVIEW REQUIRED."
                                )
                                ai_classified += 1
                            else:
                                ai_failed += 1
                        
                        # Now build the real record with the right item type
                        record = enrich(item["ecosystem"], item["name"], item["version"], item_type)
                        record["Tool vs SOUP Justification"] = tool_soup_just
                        if owner_bulk:
                            record["Owner"] = owner_bulk
                        if tool_soup_just:
                            record["AI Review Status"] = "AI classification pending review"
                        
                        target = SOUP_SHEET if item_type == "SOUP" else (
                            TOOL_SHEET if item_type == "Tool" else SOUP_SHEET
                        )
                        upsert_record(record, target)
                        
                        if item_type == "SOUP": soup_count += 1
                        elif item_type == "Tool": tool_count += 1
                        else: unclassified_count += 1
                        
                        # Gentle rate limit pause
                        time.sleep(0.5)
                    except Exception as e:
                        st.warning(f"Failed: {item['name']} — {e}")
                
                progress.empty()
                status.empty()
                
                st.success(f"""
✅ Import complete:
- {soup_count} items → SOUP Inventory
- {tool_count} items → Tool Inventory
- {unclassified_count} items unclassified (default placed in SOUP — review and reclassify)
- {ai_classified} items classified by AI
- {ai_failed} AI classification failures (manual review needed)

**All AI classifications need your review** — they're marked in the "AI Review Status" column.
                """)

# ============================================================
# TAB 4: INVENTORY
# ============================================================
with tab4:
    st.subheader("Combined Inventory")
    if st.button("🔃 Reload from sheets"):
        st.cache_data.clear()
        st.rerun()
    
    try:
        all_df = read_all_items()
        soup_df = read_sheet(SOUP_SHEET)
        tool_df = read_sheet(TOOL_SHEET)
    except Exception as e:
        st.error(f"Could not load sheets: {e}")
        all_df = pd.DataFrame()
        soup_df = pd.DataFrame()
        tool_df = pd.DataFrame()
    
    if all_df.empty:
        st.info("No items yet. Add via '➕ Add Item' or '📦 Bulk Import' tab.")
    else:
        c1, c2, c3, c4, c5 = st.columns(5)
        c1.metric("Total", len(all_df))
        c2.metric("SOUP", len(soup_df))
        c3.metric("Tools", len(tool_df))
        soup_cves = int((pd.to_numeric(soup_df["CVE Count"], errors="coerce").fillna(0) > 0).sum()) if not soup_df.empty else 0
        tool_cves = int((pd.to_numeric(tool_df["CVE Count"], errors="coerce").fillna(0) > 0).sum()) if not tool_df.empty else 0
        c4.metric("With CVEs", soup_cves + tool_cves)
        c5.metric("Approved", int((all_df["Approval Status"] == "Approved").sum()))
        
        st.divider()
        sub_t1, sub_t2 = st.tabs([f"📦 SOUP ({len(soup_df)})", f"🛠️ Tools ({len(tool_df)})"])
        
        with sub_t1:
            if soup_df.empty:
                st.info("No SOUP items.")
            else:
                st.dataframe(
                    soup_df[["Name", "Version", "Ecosystem", "License", "CVE Count",
                             "Highest CVSS", "Outdated", "Confirmed Safety Class",
                             "Usage Context", "Approval Status", "Owner"]],
                    hide_index=True, use_container_width=True,
                )
        with sub_t2:
            if tool_df.empty:
                st.info("No Tool items.")
            else:
                st.dataframe(
                    tool_df[["Name", "Version", "Ecosystem", "License", "CVE Count",
                             "Tool Category", "Tool Risk Level", "Validation Status",
                             "Approval Status", "Owner"]],
                    hide_index=True, use_container_width=True,
                )

# ============================================================
# TAB 5: SOUP REVIEW (with AI features)
# ============================================================
with tab5:
    st.subheader("📦 SOUP Review")
    
    try: df = read_sheet(SOUP_SHEET)
    except Exception: df = pd.DataFrame()
    
    if df.empty:
        st.info("No SOUP items yet.")
    else:
        labels = [f"{r['Name']}@{r['Version']} ({r['Ecosystem']})" for _, r in df.iterrows()]
        idx = st.selectbox("Select SOUP item", range(len(labels)),
                           format_func=lambda i: labels[i], key="soup_sel")
        item = df.iloc[idx]
        
        st.markdown(f"### 📦 {item['Name']} `{item['Version']}`")
        
        # AI review status banner
        ai_status = item.get("AI Review Status", "")
        if ai_status and "pending" in ai_status.lower():
            st.warning(f"⚠️ AI Review Status: **{ai_status}** — confirm AI suggestions before approval.")
        
        with st.expander("📋 Auto-populated fields"):
            for f in ["Publisher", "License", "Description", "Repository URL", "Release Date", "Latest Version", "Outdated"]:
                st.markdown(f"**{f}:** {item.get(f, '—')}")
        
        cc = int(item.get("CVE Count", 0) or 0)
        with st.expander("🛡️ Vulnerabilities", expanded=cc > 0):
            if cc == 0:
                st.success("✅ No known vulnerabilities.")
            else:
                st.warning(f"⚠️ {cc} CVE(s) — Highest CVSS: {item.get('Highest CVSS', '—')}")
                st.text(item.get("CVE List", ""))
                
                # AI explain CVEs
                cve_pe_widget_key = f"cve_pe_{idx}"
                cve_pe_existing = item.get("CVE Plain English", "")
                
                if cve_pe_widget_key not in st.session_state:
                    st.session_state[cve_pe_widget_key] = cve_pe_existing
                
                if gemini_available():
                    if st.button("✨ AI-explain CVEs in plain English", key=f"cve_ai_btn_{idx}"):
                        cve_text = item.get("CVE List", "")
                        first_cve_line = cve_text.split("\n")[0] if cve_text else ""
                        with st.spinner("Generating plain-English explanation..."):
                            explanation = ai_cve_plain_english(
                                first_cve_line[:50],
                                first_cve_line[50:],
                                item.get("Highest CVSS", "")
                            )
                        if explanation.startswith("ERROR"):
                            st.error(f"❌ {explanation}")
                        else:
                            st.session_state[cve_pe_widget_key] = explanation
                            st.rerun()
                
                cve_explain = st.text_area(
                    "Plain-English CVE explanation (AI-generated, you review)",
                    key=cve_pe_widget_key,
                    height=100,
                )
                if cve_explain and cve_explain != cve_pe_existing:
                    st.caption("💡 AI-generated. Edit if needed, then save.")
        
        st.divider()
        
        # Tool vs SOUP justification
        existing_justif = item.get("Tool vs SOUP Justification", "")
        with st.expander("📝 Tool vs SOUP justification", expanded=not bool(existing_justif)):
            if existing_justif: st.info(existing_justif)
            else: st.caption("Use '🤔 Classify' tab to generate.")
            tool_soup_just = st.text_area("Edit (optional)", value=existing_justif, height=100, key=f"tsj_{idx}")
        
        st.divider()
        
        # Guided Usage Context picker
        st.markdown("### 📍 Usage Context — Guided Picker")
        st.caption("Stop at first 'Yes'.")
        st.markdown("**Q-A:** Does the code execute INSIDE the device?")
        rid = st.radio("A", ["Not answered", "Yes", "No"], key=f"rid_{idx}", horizontal=True, label_visibility="collapsed")
        pte = "Not answered"; tsc = "Not answered"; gcc = "Not answered"
        if rid == "No":
            st.markdown("**Q-B:** Does it produce V&V evidence?")
            pte = st.radio("B", ["Not answered", "Yes", "No"], key=f"pte_{idx}", horizontal=True, label_visibility="collapsed")
            if pte == "No":
                st.markdown("**Q-C:** Does it compile/transform the shipping code?")
                tsc = st.radio("C", ["Not answered", "Yes", "No"], key=f"tsc_{idx}", horizontal=True, label_visibility="collapsed")
                if tsc == "No":
                    st.markdown("**Q-D:** Does it generate customer-facing content?")
                    gcc = st.radio("D", ["Not answered", "Yes", "No"], key=f"gcc_{idx}", horizontal=True, label_visibility="collapsed")
        
        determined_ctx = ""; ctx_just = ""
        if rid == "Yes" or pte == "Yes" or tsc == "Yes" or gcc in ["Yes", "No"]:
            ctx_ans = {
                "runs_in_device": rid if rid != "Not answered" else None,
                "produces_test_evidence": pte if pte != "Not answered" else None,
                "transforms_shipped_code": tsc if tsc != "Not answered" else None,
                "generates_customer_content": gcc if gcc != "Not answered" else None,
            }
            determined_ctx, ctx_just = determine_usage_context(ctx_ans)
            st.success(f"📍 **Determined:** {determined_ctx}")
        
        ctx_options = [""] + USAGE_CONTEXT_OPTIONS
        current_ctx = item.get("Usage Context", "")
        default_ctx = determined_ctx if determined_ctx else current_ctx
        usage_context_final = st.selectbox("Final Usage Context", ctx_options,
            index=ctx_options.index(default_ctx) if default_ctx in ctx_options else 0,
            key=f"ctxf_{idx}")
        usage_ctx_justification = st.text_area("Usage Context Justification",
            value=ctx_just if ctx_just else item.get("Usage Context Justification", ""),
            height=80, key=f"ctxj_{idx}")
        
        st.divider()
        
        # AI-powered Intended Use
        st.markdown("### Intended Use")
        
        iu_existing = item.get("Intended Use", "")
        iu_widget_key = f"iu_{idx}"
        
        # Initialize widget state from existing value (only on first render)
        if iu_widget_key not in st.session_state:
            st.session_state[iu_widget_key] = iu_existing
        
        # AI suggest button
        if gemini_available():
            if st.button("✨ AI suggest Intended Use", key=f"iu_ai_btn_{idx}"):
                with st.spinner("Asking Gemini..."):
                    suggestion = ai_intended_use(
                        item["Name"], item["Version"], item["Ecosystem"],
                        item.get("Description", ""), usage_context_final or current_ctx,
                    )
                if suggestion.startswith("ERROR"):
                    st.error(f"❌ {suggestion}")
                    st.caption("Try the '🔬 Test Gemini connection' button in the sidebar to diagnose.")
                else:
                    # Write directly to the widget's state key, then rerun so the widget picks it up
                    st.session_state[iu_widget_key] = f"[AI-suggested] {suggestion}"
                    st.rerun()
        else:
            st.caption("Enable AI in sidebar to use AI suggest")
        
        intended_use = st.text_area(
            "Intended Use",
            key=iu_widget_key,
            height=100,
            label_visibility="collapsed",
        )
        if intended_use and intended_use.startswith("[AI-suggested]"):
            st.caption("✨ AI-suggested. Review, edit if needed, then save.")
        
        st.divider()
        
        # AI-powered Functional Requirements
        st.markdown("### Functional / Performance Requirements (§5.3.3)")
        
        fr_existing = item.get("Functional Requirements", "")
        fr_widget_key = f"fr_{idx}"
        
        if fr_widget_key not in st.session_state:
            st.session_state[fr_widget_key] = fr_existing
        
        if gemini_available():
            if st.button("✨ AI suggest Functional Requirements", key=f"fr_ai_btn_{idx}"):
                with st.spinner("Asking Gemini..."):
                    suggestion = ai_functional_requirements(
                        item["Name"], item["Version"],
                        item.get("Description", ""), intended_use,
                    )
                if suggestion.startswith("ERROR"):
                    st.error(f"❌ {suggestion}")
                else:
                    st.session_state[fr_widget_key] = f"[AI-suggested]\n{suggestion}"
                    st.rerun()
        
        func_req = st.text_area(
            "Functional Requirements",
            key=fr_widget_key,
            height=180,
            label_visibility="collapsed",
        )
        if func_req and func_req.startswith("[AI-suggested]"):
            st.caption("✨ AI-suggested. Review, edit if needed, then save.")
        
        st.divider()
        
        # Other QARA fields
        st.caption(f"Agent suggests safety class: **{item.get('Suggested Safety Class', '—')}**")
        sc_options = ["", "Class A", "Class B", "Class C", "Not applicable"]
        current_sc = item.get("Confirmed Safety Class", "")
        confirmed_class = st.selectbox("Confirmed Safety Class", sc_options,
            index=sc_options.index(current_sc) if current_sc in sc_options else 0, key=f"sc_{idx}")
        
        owner = st.text_input("Owner", value=item.get("Owner", ""), key=f"own_{idx}")
        verif = st.text_area("Verification Notes", value=item.get("Verification Notes", ""),
                              height=100, key=f"vn_{idx}")
        
        # AI Review Status
        st.markdown("### ✅ AI Review Acknowledgment")
        st.caption("If you used AI suggestions, mark this once you've reviewed and approved them.")
        ai_reviewed = st.checkbox("I have reviewed all AI-suggested content in this record",
                                   value=(ai_status == "Reviewed by QARA"),
                                   key=f"ai_rev_{idx}")
        
        approval = st.selectbox("Approval Status",
            ["Draft", "Under Review", "Approved", "Deprecated"],
            index=["Draft", "Under Review", "Approved", "Deprecated"].index(
                item.get("Approval Status", "Draft")
            ) if item.get("Approval Status", "Draft") in ["Draft", "Under Review", "Approved", "Deprecated"] else 0,
            key=f"ap_{idx}")
        
        col_save, col_del = st.columns([3, 1])
        with col_save:
            if st.button("💾 Save", type="primary", key=f"save_{idx}"):
                # Strip [AI-suggested] tags when saving — they served their purpose
                clean_iu = intended_use.replace("[AI-suggested] ", "")
                clean_fr = func_req.replace("[AI-suggested]\n", "")
                
                updates = {
                    "Tool vs SOUP Justification": tool_soup_just,
                    "Confirmed Safety Class": confirmed_class,
                    "Intended Use": clean_iu,
                    "Usage Context": usage_context_final,
                    "Usage Context Justification": usage_ctx_justification,
                    "Owner": owner,
                    "Functional Requirements": clean_fr,
                    "Verification Notes": verif,
                    "Approval Status": approval,
                    "AI Review Status": "Reviewed by QARA" if ai_reviewed else (ai_status or ""),
                    "CVE Plain English": cve_explain if cc > 0 else "",
                }
                with st.spinner("Saving..."):
                    update_user_fields(SOUP_SHEET, item["Name"], str(item["Version"]),
                                       item["Ecosystem"], updates)
                # Clear widget state so next render reflects the saved (clean) values
                for k in [f"iu_{idx}", f"fr_{idx}", f"cve_pe_{idx}"]:
                    if k in st.session_state: del st.session_state[k]
                st.success("✅ Saved.")
                st.rerun()
        with col_del:
            if st.button("🗑️ Delete", type="secondary", key=f"del_{idx}"):
                delete_row(SOUP_SHEET, item["Name"], str(item["Version"]), item["Ecosystem"])
                st.success("Deleted.")
                st.rerun()

# ============================================================
# TAB 6: TOOL REVIEW (with AI features)
# ============================================================
with tab6:
    st.subheader("🛠️ Tool Review (§5.1.4 + FDA CSA)")
    
    try: df = read_sheet(TOOL_SHEET)
    except Exception: df = pd.DataFrame()
    
    if df.empty:
        st.info("No Tool items yet.")
    else:
        labels = [f"{r['Name']}@{r['Version']} ({r['Ecosystem']})" for _, r in df.iterrows()]
        tidx = st.selectbox("Select Tool", range(len(labels)),
                            format_func=lambda i: labels[i], key="tool_sel")
        item = df.iloc[tidx]
        
        st.markdown(f"### 🛠️ {item['Name']} `{item['Version']}`")
        
        ai_status = item.get("AI Review Status", "")
        if ai_status and "pending" in ai_status.lower():
            st.warning(f"⚠️ AI Review Status: **{ai_status}**")
        
        with st.expander("📋 Auto-populated fields"):
            for f in ["Publisher", "License", "Description", "Repository URL", "Release Date", "Latest Version", "Outdated"]:
                st.markdown(f"**{f}:** {item.get(f, '—')}")
        
        cc = int(item.get("CVE Count", 0) or 0)
        with st.expander("🛡️ Vulnerabilities", expanded=cc > 0):
            if cc == 0:
                st.success("✅ No known vulnerabilities.")
            else:
                st.warning(f"⚠️ {cc} CVE(s)")
                st.text(item.get("CVE List", ""))
        
        with st.expander("📝 Tool vs SOUP justification"):
            existing = item.get("Tool vs SOUP Justification", "")
            if existing: st.info(existing)
            tool_soup_just_t = st.text_area("Edit", value=existing, height=100, key=f"ttsj_{tidx}")
        
        st.divider()
        st.markdown("### Tool Category & Function")
        col_tc1, col_tc2 = st.columns(2)
        with col_tc1:
            current_cat = item.get("Tool Category", "")
            tool_cat = st.selectbox("Tool Category", [""] + TOOL_CATEGORIES,
                index=([""] + TOOL_CATEGORIES).index(current_cat) if current_cat in ([""] + TOOL_CATEGORIES) else 0,
                key=f"tc_{tidx}")
        with col_tc2:
            tool_func = st.text_input("Tool Function in Process",
                value=item.get("Tool Function in Process", ""),
                placeholder="e.g., Runs unit tests during CI", key=f"tf_{tidx}")
        
        ctx_options = [""] + USAGE_CONTEXT_OPTIONS
        current_ctx_t = item.get("Usage Context", "")
        tool_ctx = st.selectbox("Usage Context", ctx_options,
            index=ctx_options.index(current_ctx_t) if current_ctx_t in ctx_options else 0,
            key=f"tctx_{tidx}")
        tool_ctx_just = st.text_area("Usage Context Justification",
            value=item.get("Usage Context Justification", ""), height=80, key=f"tctxj_{tidx}")
        
        st.divider()
        
        # Risk picker
        st.markdown("### 🎯 Tool Risk Level — Guided Picker (FDA CSA)")
        st.markdown("**Risk Q1:** Could a defect cause a product safety issue?")
        rq1 = st.radio("RQ1", ["Not answered", "Yes", "No"], key=f"rq1_{tidx}",
                       horizontal=True, label_visibility="collapsed")
        rq2 = "Not answered"; rq3 = "Not answered"; rq4 = "Not answered"
        if rq1 == "No":
            st.markdown("**Risk Q2:** Does it produce V&V evidence for release decisions?")
            rq2 = st.radio("RQ2", ["Not answered", "Yes", "No"], key=f"rq2_{tidx}",
                           horizontal=True, label_visibility="collapsed")
            if rq2 == "No":
                st.markdown("**Risk Q3:** Does it affect product quality (builds, transforms)?")
                rq3 = st.radio("RQ3", ["Not answered", "Yes", "No"], key=f"rq3_{tidx}",
                               horizontal=True, label_visibility="collapsed")
                if rq3 == "Yes":
                    st.markdown("**Risk Q4:** Would other controls catch any defect?")
                    rq4 = st.radio("RQ4", ["Not answered", "Yes", "No"], key=f"rq4_{tidx}",
                                   horizontal=True, label_visibility="collapsed")
        
        determined_risk = ""; risk_just = ""
        risk_chain_done = (rq1 == "Yes" or rq2 == "Yes" or
                           (rq3 == "Yes" and rq4 != "Not answered") or rq3 == "No")
        if risk_chain_done:
            risk_ans = {
                "affects_product_safety": rq1 if rq1 != "Not answered" else None,
                "affects_vv_evidence": rq2 if rq2 != "Not answered" else None,
                "affects_quality": rq3 if rq3 != "Not answered" else None,
                "other_controls_catch": rq4 if rq4 != "Not answered" else None,
            }
            determined_risk, risk_just = classify_tool_risk(risk_ans)
            if determined_risk == "High": st.error(f"🔴 Risk: **{determined_risk}**")
            elif determined_risk == "Medium": st.warning(f"🟡 Risk: **{determined_risk}**")
            else: st.success(f"🟢 Risk: **{determined_risk}**")
        
        current_risk = item.get("Tool Risk Level", "")
        default_risk = determined_risk if determined_risk else current_risk
        risk_final = st.selectbox("Tool Risk Level", [""] + TOOL_RISK_LEVELS,
            index=([""] + TOOL_RISK_LEVELS).index(default_risk) if default_risk in ([""] + TOOL_RISK_LEVELS) else 0,
            key=f"rf_{tidx}")
        
        # AI-powered Risk Justification
        rj_widget_key = f"rjf_{tidx}"
        rj_existing = risk_just if risk_just else item.get("Tool Risk Justification", "")
        
        if rj_widget_key not in st.session_state:
            st.session_state[rj_widget_key] = rj_existing
        
        if gemini_available() and risk_final:
            if st.button("✨ AI suggest Risk Justification", key=f"rj_ai_btn_{tidx}"):
                with st.spinner("Asking Gemini..."):
                    suggestion = ai_tool_risk_justification(
                        item["Name"], item.get("Description", ""),
                        risk_final, tool_func,
                    )
                if suggestion.startswith("ERROR"):
                    st.error(f"❌ {suggestion}")
                else:
                    st.session_state[rj_widget_key] = f"[AI-suggested] {suggestion}"
                    st.rerun()
        elif gemini_available() and not risk_final:
            st.caption("Set Risk Level above to enable AI suggest for Risk Justification.")
        
        risk_just_final = st.text_area(
            "Risk Justification",
            key=rj_widget_key,
            height=100,
        )
        if risk_just_final and risk_just_final.startswith("[AI-suggested]"):
            st.caption("✨ AI-suggested. Review before save.")
        
        # AI-powered Impact if Fails
        imp_widget_key = f"imp_{tidx}"
        imp_existing = item.get("Impact if Tool Fails", "")
        
        if imp_widget_key not in st.session_state:
            st.session_state[imp_widget_key] = imp_existing
        
        if gemini_available():
            if st.button("✨ AI suggest Impact if Tool Fails", key=f"imp_ai_btn_{tidx}"):
                with st.spinner("Asking Gemini..."):
                    suggestion = ai_impact_if_fails(
                        item["Name"], item.get("Description", ""), tool_func
                    )
                if suggestion.startswith("ERROR"):
                    st.error(f"❌ {suggestion}")
                else:
                    st.session_state[imp_widget_key] = f"[AI-suggested] {suggestion}"
                    st.rerun()
        
        impact = st.text_area(
            "Impact if Tool Fails",
            key=imp_widget_key,
            height=100,
        )
        if impact and impact.startswith("[AI-suggested]"):
            st.caption("✨ AI-suggested. Review before save.")
        
        st.divider()
        
        # Validation approach
        st.markdown("### 🧪 Validation Approach")
        suggested_approach = ""; approach_just = ""
        if risk_final:
            suggested_approach, approach_just = suggest_validation_approach(risk_final)
            st.info(f"💡 Suggested for {risk_final} risk: {suggested_approach}")
        
        current_va = item.get("Validation Approach", "")
        default_va = suggested_approach if suggested_approach else current_va
        validation_approach = st.selectbox("Validation Approach", [""] + VALIDATION_APPROACHES,
            index=([""] + VALIDATION_APPROACHES).index(default_va) if default_va in ([""] + VALIDATION_APPROACHES) else 0,
            key=f"va_{tidx}")
        validation_approach_just = st.text_area("Justification",
            value=approach_just if approach_just else item.get("Validation Approach Justification", ""),
            height=80, key=f"vaj_{tidx}")
        
        st.divider()
        st.markdown("### Validation Evidence & Controls")
        validation_evidence = st.text_area("Validation Evidence",
            value=item.get("Validation Evidence", ""),
            placeholder="e.g., Industry-standard tool, 50M+ downloads, smoke test confirms behavior",
            height=100, key=f"ve_{tidx}")
        tool_output_verif = st.text_area("Tool Output Verification",
            value=item.get("Tool Output Verification", ""), height=80, key=f"tov_{tidx}")
        config_mgmt = st.text_area("Configuration Management",
            value=item.get("Configuration Management", ""), height=80, key=f"cm_{tidx}")
        
        st.divider()
        col_vs1, col_vs2 = st.columns(2)
        with col_vs1:
            current_vs = item.get("Validation Status", "Pending")
            val_status = st.selectbox("Validation Status", VALIDATION_STATUSES,
                index=VALIDATION_STATUSES.index(current_vs) if current_vs in VALIDATION_STATUSES else 0,
                key=f"vs_{tidx}")
        with col_vs2:
            last_val = st.text_input("Last Validation Date",
                value=item.get("Last Validation Date", ""), key=f"lvd_{tidx}")
        
        tool_owner = st.text_input("Owner", value=item.get("Owner", ""), key=f"town_{tidx}")
        
        st.markdown("### ✅ AI Review Acknowledgment")
        ai_reviewed_t = st.checkbox("I have reviewed all AI-suggested content",
                                     value=(ai_status == "Reviewed by QARA"),
                                     key=f"ai_rev_t_{tidx}")
        
        tool_approval = st.selectbox("Approval Status",
            ["Draft", "Under Review", "Approved", "Deprecated"],
            index=["Draft", "Under Review", "Approved", "Deprecated"].index(
                item.get("Approval Status", "Draft")
            ) if item.get("Approval Status", "Draft") in ["Draft", "Under Review", "Approved", "Deprecated"] else 0,
            key=f"tap_{tidx}")
        
        col_sav, col_dl = st.columns([3, 1])
        with col_sav:
            if st.button("💾 Save", type="primary", key=f"tsave_{tidx}"):
                clean_rj = risk_just_final.replace("[AI-suggested] ", "")
                clean_imp = impact.replace("[AI-suggested] ", "")
                
                updates = {
                    "Tool vs SOUP Justification": tool_soup_just_t,
                    "Tool Category": tool_cat,
                    "Tool Function in Process": tool_func,
                    "Usage Context": tool_ctx,
                    "Usage Context Justification": tool_ctx_just,
                    "Tool Risk Level": risk_final,
                    "Tool Risk Justification": clean_rj,
                    "Impact if Tool Fails": clean_imp,
                    "Validation Approach": validation_approach,
                    "Validation Approach Justification": validation_approach_just,
                    "Validation Evidence": validation_evidence,
                    "Tool Output Verification": tool_output_verif,
                    "Configuration Management": config_mgmt,
                    "Validation Status": val_status,
                    "Last Validation Date": last_val,
                    "Owner": tool_owner,
                    "AI Review Status": "Reviewed by QARA" if ai_reviewed_t else (ai_status or ""),
                    "Approval Status": tool_approval,
                }
                with st.spinner("Saving..."):
                    update_user_fields(TOOL_SHEET, item["Name"], str(item["Version"]),
                                       item["Ecosystem"], updates)
                # Clear widget state so next render reflects the saved (clean) values
                for k in [f"rjf_{tidx}", f"imp_{tidx}"]:
                    if k in st.session_state: del st.session_state[k]
                st.success("✅ Saved.")
                st.rerun()
        with col_dl:
            if st.button("🗑️ Delete", type="secondary", key=f"tdel_{tidx}"):
                delete_row(TOOL_SHEET, item["Name"], str(item["Version"]), item["Ecosystem"])
                st.success("Deleted.")
                st.rerun()

st.divider()
st.caption("v5.5 • AI suggestions now appear in text boxes • Direct widget state writes • Gemini 2.5 Flash-Lite • IEC 62304 §5.3.3 + §5.1.4")
