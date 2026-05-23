"""
SOUP & Tool Agent v4 — Separate Sheets with Guided Pickers
===========================================================
For QARA professionals managing SOUP (IEC 62304 §5.3.3) and Tools (§5.1.4 + FDA CSA)
in SaMD / SiMD development & testing.

v4 changes:
  - Separate "SOUP Inventory" and "Tool Inventory" sheets in same workbook
  - Auto-routing: Tool classification moves item to Tool sheet (and vice versa)
  - Guided pickers for Tool Risk Level and Validation Approach (per FDA CSA)
  - Removed redundant info-box at top of Add Item
"""

import streamlit as st
import requests
import time
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

ECOSYSTEMS = {
    "npm": "npm — JavaScript / Node.js (web apps, frontends, React)",
    "PyPI": "PyPI — Python (AI/ML, data analysis, scripting)",
    "Maven": "Maven — Java (enterprise apps, Spring Boot, Android)",
    "NuGet": "NuGet — .NET / C# (Windows apps, Microsoft stack)",
    "Go": "Go — Go language (backend services)",
    "Cargo": "Cargo — Rust (systems software)",
    "RubyGems": "RubyGems — Ruby (Rails web apps)",
}

USAGE_CONTEXT_OPTIONS = [
    "Production (runtime)",
    "Development tooling only",
    "Testing only",
    "Build pipeline only",
    "Documentation generation",
]

TOOL_CATEGORIES = [
    "Build tool / Bundler",
    "Package manager",
    "Test framework",
    "Test data / Mocking",
    "Coverage tool",
    "Static analysis / Linter",
    "Code formatter",
    "CI/CD platform / plugin",
    "Documentation generator",
    "Diagram tool",
    "Code generator / Transpiler",
    "Container builder",
    "Debugger / Profiler",
    "IDE plugin",
    "Other",
]

TOOL_RISK_LEVELS = ["High", "Medium", "Low"]

VALIDATION_APPROACHES = [
    "Vendor reliance (mature widely-used tool, lightweight evidence)",
    "Unscripted testing (ad-hoc functional checks)",
    "Scripted testing (documented test cases executed)",
    "Scripted with edge cases (formal IQ/OQ + edge case testing)",
]

VALIDATION_STATUSES = ["Pending", "In Validation", "Validated", "Retired"]

# ============================================================
# COLUMN DEFINITIONS — separate for each sheet
# ============================================================

SOUP_COLUMNS = [
    "Name", "Version", "Ecosystem", "Item Type",
    "Tool vs SOUP Justification",
    "Publisher", "License", "Description", "Repository URL",
    "Homepage", "Release Date", "Latest Version", "Outdated",
    "CVE Count", "Highest CVSS", "CVE List", "Anomaly List",
    "Suggested Safety Class", "Confirmed Safety Class",
    "Intended Use", "Usage Context", "Usage Context Justification",
    "Functional Requirements", "Verification Notes",
    "Approval Status", "Owner", "Date Added", "Last Refreshed",
]

TOOL_COLUMNS = [
    "Name", "Version", "Ecosystem", "Item Type",
    "Tool vs SOUP Justification",
    "Publisher", "License", "Description", "Repository URL",
    "Homepage", "Release Date", "Latest Version", "Outdated",
    "CVE Count", "Highest CVSS", "CVE List",
    "Tool Category", "Tool Function in Process",
    "Usage Context", "Usage Context Justification",
    "Tool Risk Level", "Tool Risk Justification",
    "Impact if Tool Fails",
    "Validation Approach", "Validation Approach Justification",
    "Validation Evidence", "Tool Output Verification",
    "Configuration Management",
    "Validation Status", "Last Validation Date",
    "Approval Status", "Owner", "Date Added", "Last Refreshed",
]

ITEM_TYPE_OPTIONS = ["SOUP", "Tool", "Not yet classified"]

st.set_page_config(
    page_title="SOUP & Tool Agent — IEC 62304",
    page_icon="🩺",
    layout="wide",
)

# ============================================================
# GOOGLE SHEETS CONNECTION
# ============================================================

@st.cache_resource
def get_gsheet():
    try:
        scopes = [
            "https://www.googleapis.com/auth/spreadsheets",
            "https://www.googleapis.com/auth/drive",
        ]
        creds_dict = dict(st.secrets["gcp_service_account"])
        creds = Credentials.from_service_account_info(creds_dict, scopes=scopes)
        client = gspread.authorize(creds)
        return client.open_by_url(st.secrets["sheet_url"])
    except Exception as e:
        st.error(f"❌ Could not connect to Google Sheet. Error: {e}")
        st.stop()

def get_soup_ws():
    return get_gsheet().worksheet(SOUP_SHEET)

def get_tool_ws():
    return get_gsheet().worksheet(TOOL_SHEET)

def get_log_ws():
    return get_gsheet().worksheet(LOG_SHEET)

def read_sheet(sheet_name: str) -> pd.DataFrame:
    """Read either SOUP or Tool sheet into a DataFrame."""
    if sheet_name == SOUP_SHEET:
        ws = get_soup_ws()
        cols = SOUP_COLUMNS
    else:
        ws = get_tool_ws()
        cols = TOOL_COLUMNS
    records = ws.get_all_records()
    if not records:
        return pd.DataFrame(columns=cols)
    df = pd.DataFrame(records)
    for c in cols:
        if c not in df.columns:
            df[c] = ""
    return df

def read_all_items() -> pd.DataFrame:
    """Read both sheets and combine for unified views (inventory tab)."""
    soup = read_sheet(SOUP_SHEET).copy()
    tool = read_sheet(TOOL_SHEET).copy()
    soup["_sheet"] = "SOUP"
    tool["_sheet"] = "Tool"
    # Align column sets
    all_cols = set(soup.columns) | set(tool.columns)
    for c in all_cols:
        if c not in soup.columns:
            soup[c] = ""
        if c not in tool.columns:
            tool[c] = ""
    return pd.concat([soup, tool], ignore_index=True, sort=False)

def find_row(sheet_name: str, name: str, version: str, ecosystem: str) -> int:
    df = read_sheet(sheet_name)
    if df.empty:
        return 0
    mask = (
        (df["Name"].astype(str).str.lower() == name.lower()) &
        (df["Version"].astype(str) == version) &
        (df["Ecosystem"].astype(str) == ecosystem)
    )
    matches = df.index[mask].tolist()
    return matches[0] + 2 if matches else 0

def find_item_anywhere(name: str, version: str, ecosystem: str) -> tuple:
    """Return (sheet_name, row_index) or (None, 0) if not found anywhere."""
    r = find_row(SOUP_SHEET, name, version, ecosystem)
    if r > 0:
        return (SOUP_SHEET, r)
    r = find_row(TOOL_SHEET, name, version, ecosystem)
    if r > 0:
        return (TOOL_SHEET, r)
    return (None, 0)

def upsert_record(record: dict, target_sheet: str):
    """Insert or update record in target sheet."""
    cols = SOUP_COLUMNS if target_sheet == SOUP_SHEET else TOOL_COLUMNS
    ws = get_soup_ws() if target_sheet == SOUP_SHEET else get_tool_ws()
    row_data = [record.get(col, "") for col in cols]
    existing = find_row(target_sheet, record["Name"], record["Version"], record["Ecosystem"])
    
    if existing > 0:
        # Update auto-fetched fields, preserve user-edited fields
        user_cols = {
            "Item Type", "Tool vs SOUP Justification",
            "Confirmed Safety Class", "Intended Use", "Usage Context",
            "Usage Context Justification", "Functional Requirements",
            "Verification Notes", "Approval Status", "Owner", "Date Added",
            # Tool-specific user fields
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

def move_item_between_sheets(name: str, version: str, ecosystem: str,
                              from_sheet: str, to_sheet: str):
    """Move a row from one sheet to another, preserving shared field values."""
    # Read current row
    src_df = read_sheet(from_sheet)
    mask = (
        (src_df["Name"].astype(str).str.lower() == name.lower()) &
        (src_df["Version"].astype(str) == version) &
        (src_df["Ecosystem"].astype(str) == ecosystem)
    )
    if not mask.any():
        return False
    
    row = src_df[mask].iloc[0].to_dict()
    
    # Add to target sheet
    target_cols = SOUP_COLUMNS if to_sheet == SOUP_SHEET else TOOL_COLUMNS
    target_ws = get_soup_ws() if to_sheet == SOUP_SHEET else get_tool_ws()
    new_row = [row.get(col, "") for col in target_cols]
    target_ws.append_row(new_row, value_input_option="USER_ENTERED")
    
    # Remove from source sheet
    src_row_idx = find_row(from_sheet, name, version, ecosystem)
    if src_row_idx > 0:
        src_ws = get_soup_ws() if from_sheet == SOUP_SHEET else get_tool_ws()
        src_ws.delete_rows(src_row_idx)
    
    return True

def update_user_fields(sheet_name: str, name: str, version: str, ecosystem: str, updates: dict):
    ws = get_soup_ws() if sheet_name == SOUP_SHEET else get_tool_ws()
    cols = SOUP_COLUMNS if sheet_name == SOUP_SHEET else TOOL_COLUMNS
    row = find_row(sheet_name, name, version, ecosystem)
    if row == 0:
        return False
    for field, value in updates.items():
        if field in cols:
            col_idx = cols.index(field) + 1
            ws.update_cell(row, col_idx, value)
            time.sleep(0.1)
    return True

def delete_row(sheet_name: str, name: str, version: str, ecosystem: str):
    ws = get_soup_ws() if sheet_name == SOUP_SHEET else get_tool_ws()
    row = find_row(sheet_name, name, version, ecosystem)
    if row > 0:
        ws.delete_rows(row)

def log_refresh(trigger: str, items: int, new_cves: int, notes: str = ""):
    try:
        ws = get_log_ws()
        ws.append_row([
            datetime.now(IST).isoformat(),
            trigger, items, new_cves, notes
        ], value_input_option="USER_ENTERED")
    except Exception:
        pass

# ============================================================
# EXTERNAL APIs
# ============================================================

def fetch_depsdev(eco, name, version):
    try:
        r = requests.get(f"https://api.deps.dev/v3/systems/{eco}/packages/{name}/versions/{version}", timeout=15)
        if r.status_code == 200:
            return r.json()
    except Exception:
        pass
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
    except Exception:
        pass
    return ""

def fetch_osv_vulns(eco, name, version):
    try:
        r = requests.post("https://api.osv.dev/v1/query",
                          json={"package": {"name": name, "ecosystem": eco}, "version": version}, timeout=15)
        if r.status_code == 200:
            return r.json().get("vulns", [])
    except Exception:
        pass
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
    except Exception:
        pass
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
        if score > highest_cvss:
            highest_cvss = score
    
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
        "Name": name,
        "Version": version,
        "Ecosystem": eco,
        "Item Type": item_type,
        "Tool vs SOUP Justification": "",
        "Publisher": meta.get("registries", [eco])[0] if meta.get("registries") else eco,
        "License": license_str,
        "Description": meta.get("description", "")[:500] or f"{name} {version}",
        "Repository URL": repo_url,
        "Homepage": homepage,
        "Release Date": meta.get("publishedAt", ""),
        "Latest Version": latest,
        "Outdated": "Yes" if is_outdated else "No",
        "CVE Count": len(cves),
        "Highest CVSS": highest_cvss,
        "CVE List": cve_text,
        "Approval Status": "Draft",
        "Owner": "",
        "Date Added": datetime.now(IST).strftime("%Y-%m-%d %H:%M IST"),
        "Last Refreshed": datetime.now(IST).strftime("%Y-%m-%d %H:%M IST"),
        "Usage Context": "",
        "Usage Context Justification": "",
    }
    
    if item_type == "Tool":
        base.update({
            "Tool Category": "",
            "Tool Function in Process": "",
            "Tool Risk Level": "",
            "Tool Risk Justification": "",
            "Impact if Tool Fails": "",
            "Validation Approach": "",
            "Validation Approach Justification": "",
            "Validation Evidence": "",
            "Tool Output Verification": "",
            "Configuration Management": "",
            "Validation Status": "Pending",
            "Last Validation Date": "",
        })
    else:
        base.update({
            "Anomaly List": anomaly_text,
            "Suggested Safety Class": suggest_safety_class(len(cves), highest_cvss, is_outdated, item_type),
            "Confirmed Safety Class": "",
            "Intended Use": "",
            "Functional Requirements": "",
            "Verification Notes": "",
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
                if diff > 0:
                    new_cves_total += diff
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
            return ("Tool", base + "However, it transforms code or generates content that DOES ship "
                    "(e.g., build tool, code generator, document generator for IFU). Therefore classified as a Tool "
                    "per IEC 62304 §5.1.4. Apply tool validation proportional to risk (FDA CSA approach).")
        if q3 == "Yes":
            return ("Tool", base + "It produces evidence used in V&V or quality decisions (e.g., test framework, "
                    "static analysis tool). Therefore classified as a Tool per IEC 62304 §5.1.4. Validate to ensure "
                    "reliable verification evidence (FDA CSA risk-based approach).")
        return ("Tool", base + "It is used only for developer convenience (e.g., code formatter, IDE plugin) and "
                "does not affect product code, output, or V&V evidence. Classified as low-risk Tool per IEC 62304 §5.1.4. "
                "Minimal validation required; document version and license for completeness.")
    
    return ("Not yet classified", "Insufficient information to classify.")

def determine_usage_context(answers):
    if answers.get("runs_in_device") == "Yes":
        return ("Production (runtime)",
                "Executes within the medical device during normal operation. In scope for full IEC 62304 "
                "§5.3.3 / §5.3.4 SOUP treatment. Patient safety considerations apply.")
    if answers.get("produces_test_evidence") == "Yes":
        return ("Testing only",
                "Used to produce V&V evidence for the medical device but does not ship with it. Validate per "
                "IEC 62304 §5.1.4 with rigor proportional to evidence importance (FDA CSA approach).")
    if answers.get("transforms_shipped_code") == "Yes":
        return ("Build pipeline only",
                "Compiles, packages, or transforms code that ships in the device. Defects could introduce "
                "vulnerabilities in the shipped product. Address under supply-chain integrity and tool validation.")
    if answers.get("generates_customer_content") == "Yes":
        return ("Documentation generation",
                "Generates content visible to end users (IFU, manual, on-screen labeling). Output is regulated "
                "under FDA 21 CFR 801 / EU MDR Annex I labeling rules.")
    return ("Development tooling only",
            "Runs only on developer machines and does not affect shipped product, V&V evidence, build output, "
            "or customer-facing content. Lightweight tool documentation per IEC 62304 §5.1.4.")

def classify_tool_risk(answers):
    """FDA CSA risk classification for tools.
    
    High: Tool defect could result in product safety issue or false V&V evidence
    Medium: Tool defect could result in product quality issue requiring rework
    Low: Tool defect would be caught by other controls or has minimal impact
    """
    a1 = answers.get("affects_product_safety")  # safety-critical output
    a2 = answers.get("affects_vv_evidence")     # affects V&V
    a3 = answers.get("affects_quality")          # affects quality only
    a4 = answers.get("other_controls_catch")     # other controls catch defects
    
    if a1 == "Yes":
        return ("High",
                "A defect in this tool could lead to a product safety issue (compromised shipped code, "
                "undetected critical bugs in V&V, corrupted regulated content). Per FDA CSA, apply scripted "
                "testing with edge cases. Document IQ/OQ and ongoing change control.")
    
    if a2 == "Yes":
        return ("High",
                "This tool produces V&V evidence used to demonstrate product conformity. A false-pass or "
                "false-fail from the tool could lead to incorrect release decisions. Per FDA CSA, apply scripted "
                "testing. Confirm tool reliability through targeted test cases and spot-checks.")
    
    if a3 == "Yes" and a4 == "No":
        return ("Medium",
                "Tool affects product quality (build, code transformation, content generation) but a defect would "
                "not directly cause safety harm. Other controls (code review, integration tests) provide secondary "
                "defense. Per FDA CSA, unscripted functional testing is appropriate.")
    
    if a3 == "Yes" and a4 == "Yes":
        return ("Low",
                "Tool affects product quality but downstream controls (code review, automated tests, manual QA) "
                "would catch any tool-introduced defect. Per FDA CSA, vendor reliance with light internal smoke "
                "checks is sufficient.")
    
    return ("Low",
            "Tool does not affect shipped product, V&V evidence, or customer-facing content directly. Per FDA CSA, "
            "minimal validation required — document name, version, license; rely on vendor for tool correctness.")

def suggest_validation_approach(risk_level):
    """Match validation approach to risk level per FDA CSA 'least burdensome' principle."""
    if risk_level == "High":
        return ("Scripted with edge cases (formal IQ/OQ + edge case testing)",
                "Per FDA CSA, High-risk tools warrant scripted testing covering normal use AND edge cases. "
                "Document Installation Qualification (correct install/version) and Operational Qualification "
                "(correct behavior across representative inputs). Maintain change control records.")
    if risk_level == "Medium":
        return ("Scripted testing (documented test cases executed)",
                "Per FDA CSA, Medium-risk tools warrant scripted but lighter testing — document representative "
                "use cases and confirm correct behavior. No need for exhaustive edge-case coverage if downstream "
                "controls exist.")
    return ("Vendor reliance (mature widely-used tool, lightweight evidence)",
            "Per FDA CSA 'least burdensome' principle, Low-risk tools can rely on vendor evidence — record version, "
            "vendor reputation, widespread industry use. Internal smoke check optional. Document rationale.")

# ============================================================
# UI
# ============================================================

st.title("🩺 SOUP & Tool Agent — IEC 62304")
st.caption("Tracks SOUP (§5.3.3) and Tools (§5.1.4 + FDA CSA) for SaMD / SiMD development & testing")

with st.sidebar:
    st.header("⚙️ Controls")
    if st.button("🔄 Refresh All Now", type="primary", use_container_width=True):
        with st.spinner("Refreshing all items..."):
            n, new_cves = refresh_all("manual_button")
        st.success(f"Refreshed {n} items. {new_cves} new CVEs found.")
        st.rerun()
    
    st.divider()
    st.markdown("**🕘 Daily auto-refresh:** 9:00 AM IST")
    try:
        next_run = scheduler.get_job("daily_refresh").next_run_time
        if next_run:
            st.caption(f"Next: {next_run.strftime('%Y-%m-%d %H:%M %Z')}")
    except Exception:
        pass
    
    st.divider()
    sheet_url = st.secrets.get("sheet_url", "")
    if sheet_url:
        st.markdown(f"[📊 Open Workbook ↗]({sheet_url})")
    st.caption("Workbook has 3 tabs: SOUP, Tool, Refresh Log.")

# Tabs
tab1, tab2, tab3, tab4, tab5, tab6 = st.tabs([
    "➕ Add Item",
    "🤔 Classify: Tool or SOUP?",
    "📊 Inventory",
    "✅ SOUP Review",
    "🛠️ Tool Review",
    "ℹ️ Help",
])

# ============================================================
# TAB 1: ADD ITEM
# ============================================================
with tab1:
    st.subheader("Add a new SOUP item or Tool")
    
    col1, col2, col3 = st.columns([2, 2, 2])
    with col1:
        ecosystem = st.selectbox(
            "Ecosystem",
            list(ECOSYSTEMS.keys()),
            format_func=lambda x: ECOSYSTEMS[x],
            help="The registry where this package comes from. Pick the language/platform your developers use.",
        )
    with col2:
        name = st.text_input("Package name", placeholder="e.g., lodash, numpy, pytest")
    with col3:
        version = st.text_input("Version", placeholder="e.g., 4.17.21")
    
    item_type = st.radio(
        "Item Type",
        ITEM_TYPE_OPTIONS,
        horizontal=True,
        help=(
            "SOUP = software incorporated INTO the medical device (its code runs on the device). "
            "Tool = software used to develop, build, test, or maintain the device but NOT shipped with it. "
            "Not sure? Use the '🤔 Classify' tab for a guided answer."
        ),
    )
    
    if item_type == "Not yet classified":
        st.warning("⚠️ Use the **'🤔 Classify: Tool or SOUP?'** tab to determine this before saving.")
    elif item_type == "SOUP":
        st.success("📦 Will be saved to the **SOUP Inventory** sheet.")
    else:
        st.info("🛠️ Will be saved to the **Tool Inventory** sheet.")
    
    st.markdown("---")
    st.markdown("**Optional now — fill later in the review tabs:**")
    
    col4, col5 = st.columns(2)
    with col4:
        intended_use = st.text_area(
            "Intended use in your software",
            height=80,
            placeholder="e.g., Parses incoming JSON patient data in the registration module",
        )
    with col5:
        usage_context = st.selectbox(
            "Usage context (optional)",
            [""] + USAGE_CONTEXT_OPTIONS,
        )
    
    owner = st.text_input("Owner / Responsible person", placeholder="Your name, dev team, etc.")
    
    if st.button("✨ Generate Record", type="primary"):
        if not name.strip() or not version.strip():
            st.error("Please enter both name and version.")
        elif item_type == "Not yet classified":
            st.error("Please classify the item first (use the '🤔 Classify' tab).")
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
                    
                    target_sheet = SOUP_SHEET if item_type == "SOUP" else TOOL_SHEET
                    upsert_record(record, target_sheet)
                    
                    st.success(f"✅ Record added to **{target_sheet}**: {name}@{version}")
                    
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
                        st.caption("Open the **'✅ SOUP Review'** tab to add intended use, confirm safety class, and approve.")
                    else:
                        st.info("💡 Open the **'🛠️ Tool Review'** tab to set risk level, validation approach, and validation evidence.")
                except Exception as e:
                    st.error(f"Error: {e}")

# ============================================================
# TAB 2: CLASSIFY
# ============================================================
with tab2:
    st.subheader("🤔 Is this item SOUP or a Tool?")
    st.markdown(
        "Answer up to **3 questions** below. The agent will tell you which category applies and write the "
        "justification to your sheet. If the item gets reclassified, it will be moved between the SOUP and "
        "Tool sheets automatically."
    )
    
    st.divider()
    
    # Item lookup
    all_df = read_all_items()
    classify_existing = False
    selected_item = None
    selected_sheet = None
    
    if not all_df.empty:
        classify_existing = st.checkbox("Classify an existing item")
        if classify_existing:
            labels = [
                f"[{r['_sheet']}] {r['Name']}@{r['Version']} ({r['Ecosystem']}) — currently: {r.get('Item Type','—')}"
                for _, r in all_df.iterrows()
            ]
            idx = st.selectbox("Select item to classify", range(len(labels)),
                               format_func=lambda i: labels[i])
            selected_item = all_df.iloc[idx]
            selected_sheet = SOUP_SHEET if selected_item["_sheet"] == "SOUP" else TOOL_SHEET
            st.markdown(f"**Classifying:** {selected_item['Name']}@{selected_item['Version']} "
                        f"(currently in **{selected_item['_sheet']}** sheet)")
    
    st.divider()
    
    # Question 1
    st.markdown("### Question 1")
    st.markdown(
        "**Does this software's code actually run on the customer's medical device, or get shipped inside the released product?**\n\n"
        "✅ YES examples: JSON parser bundled into your SaMD app, ML library running the AI model, cryptography library in the device, UI framework rendering the clinician dashboard\n\n"
        "❌ NO examples: Code formatter on dev laptops, test framework used in V&V but not shipped, build tool that packages code"
    )
    q1 = st.radio("Q1", ["Not yet answered", "Yes — its code runs inside the device", "No — it never runs on the device"],
                  key="q1", label_visibility="collapsed")
    q1_value = "Yes" if q1.startswith("Yes") else ("No" if q1.startswith("No") else None)
    
    q2_value = None
    q3_value = None
    
    if q1_value == "No":
        st.divider()
        st.markdown("### Question 2")
        st.markdown(
            "**Does this software produce or transform anything that ends up in the released device?**\n\n"
            "✅ YES: Build tools (Maven, webpack), code generators, IFU/manual generators, on-screen labeling tools\n\n"
            "❌ NO: Test results, log files, internal dev docs"
        )
        q2 = st.radio("Q2", ["Not yet answered", "Yes — its output ships or appears in the device/labeling",
                              "No — its output stays internal"],
                      key="q2", label_visibility="collapsed")
        q2_value = "Yes" if q2.startswith("Yes") else ("No" if q2.startswith("No") else None)
        
        if q2_value == "No":
            st.divider()
            st.markdown("### Question 3")
            st.markdown(
                "**Does this software produce evidence used to verify or validate the device's quality?**\n\n"
                "✅ YES: pytest, JUnit, coverage tools, static analyzers driving code changes, test data generators\n\n"
                "❌ NO: Code formatters, IDE plugins, debuggers"
            )
            q3 = st.radio("Q3", ["Not yet answered", "Yes — it produces V&V or quality evidence",
                                  "No — it's purely for developer convenience"],
                          key="q3", label_visibility="collapsed")
            q3_value = "Yes" if q3.startswith("Yes") else ("No" if q3.startswith("No") else None)
    
    chain_complete = (
        q1_value == "Yes" or
        (q1_value == "No" and q2_value == "Yes") or
        (q1_value == "No" and q2_value == "No" and q3_value is not None)
    )
    
    if chain_complete:
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
            
            st.markdown("---")
            
            if classification != current_type:
                st.warning(
                    f"This item is currently classified as **{current_type or 'unclassified'}** in the "
                    f"**{selected_item['_sheet']} sheet**. New classification is **{classification}**, "
                    f"so it will be **moved to the {target_sheet}**."
                )
            
            if st.button("💾 Save classification (and move if needed)", type="primary"):
                if classification != current_type and selected_sheet != target_sheet:
                    # Move row between sheets
                    move_item_between_sheets(
                        selected_item["Name"], str(selected_item["Version"]), selected_item["Ecosystem"],
                        selected_sheet, target_sheet
                    )
                    # Then update the moved row with classification info
                    update_user_fields(
                        target_sheet, selected_item["Name"], str(selected_item["Version"]), selected_item["Ecosystem"],
                        {"Item Type": classification, "Tool vs SOUP Justification": justification}
                    )
                    st.success(f"✅ Classified as **{classification}** and moved to **{target_sheet}**.")
                else:
                    update_user_fields(
                        selected_sheet, selected_item["Name"], str(selected_item["Version"]), selected_item["Ecosystem"],
                        {"Item Type": classification, "Tool vs SOUP Justification": justification}
                    )
                    st.success(f"✅ Classification saved as **{classification}** in **{selected_sheet}**.")
        else:
            st.info(f"To save this classification, add the item via the **'➕ Add Item'** tab with "
                    f"**{classification}** selected as the Item Type, then come back here to attach the justification.")

# ============================================================
# TAB 3: INVENTORY
# ============================================================
with tab3:
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
        st.info("No items yet. Add one in the '➕ Add Item' tab.")
    else:
        c1, c2, c3, c4, c5 = st.columns(5)
        c1.metric("Total items", len(all_df))
        c2.metric("SOUP", len(soup_df))
        c3.metric("Tools", len(tool_df))
        soup_cves = int((pd.to_numeric(soup_df["CVE Count"], errors="coerce").fillna(0) > 0).sum()) if not soup_df.empty else 0
        tool_cves = int((pd.to_numeric(tool_df["CVE Count"], errors="coerce").fillna(0) > 0).sum()) if not tool_df.empty else 0
        c4.metric("With CVEs", soup_cves + tool_cves)
        approved = int((all_df["Approval Status"] == "Approved").sum())
        c5.metric("Approved", approved)
        
        st.divider()
        
        sub_t1, sub_t2 = st.tabs([f"📦 SOUP Inventory ({len(soup_df)})", f"🛠️ Tool Inventory ({len(tool_df)})"])
        
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
# TAB 4: SOUP REVIEW
# ============================================================
with tab4:
    st.subheader("📦 SOUP Review")
    
    try:
        df = read_sheet(SOUP_SHEET)
    except Exception:
        df = pd.DataFrame()
    
    if df.empty:
        st.info("No SOUP items yet.")
    else:
        labels = [f"{r['Name']}@{r['Version']} ({r['Ecosystem']})" for _, r in df.iterrows()]
        idx = st.selectbox("Select SOUP item", range(len(labels)),
                           format_func=lambda i: labels[i], key="soup_select")
        item = df.iloc[idx]
        
        st.markdown(f"### 📦 {item['Name']} `{item['Version']}`")
        
        with st.expander("📋 Auto-populated fields", expanded=False):
            for f in ["Publisher", "License", "Description", "Repository URL",
                      "Release Date", "Latest Version", "Outdated"]:
                st.markdown(f"**{f}:** {item.get(f, '—')}")
        
        with st.expander("🛡️ Vulnerabilities", expanded=int(item.get("CVE Count", 0) or 0) > 0):
            cc = int(item.get("CVE Count", 0) or 0)
            if cc == 0:
                st.success("✅ No known vulnerabilities.")
            else:
                st.warning(f"⚠️ {cc} CVE(s) — Highest CVSS: {item.get('Highest CVSS', '—')}")
                st.text(item.get("CVE List", ""))
        
        with st.expander("📝 Tool vs SOUP justification", expanded=not bool(item.get("Tool vs SOUP Justification"))):
            existing = item.get("Tool vs SOUP Justification", "")
            if existing:
                st.info(existing)
            else:
                st.warning("No justification yet. Use the '🤔 Classify' tab to generate one.")
            tool_soup_just = st.text_area("Edit justification (optional)", value=existing, height=120, key=f"tsj_{idx}")
        
        st.divider()
        
        # Guided Usage Context picker
        st.markdown("### 📍 Usage Context — Guided Picker")
        st.caption("Answer in order. Stop at first 'Yes'.")
        
        st.markdown("**Question A:** Does the code execute INSIDE the device during patient/clinician use?")
        rid = st.radio("A", ["Not answered", "Yes", "No"], key=f"rid_{idx}", horizontal=True, label_visibility="collapsed")
        
        pte = "Not answered"
        tsc = "Not answered"
        gcc = "Not answered"
        
        if rid == "No":
            st.markdown("**Question B:** Does it produce V&V evidence (test results, coverage data)?")
            pte = st.radio("B", ["Not answered", "Yes", "No"], key=f"pte_{idx}", horizontal=True, label_visibility="collapsed")
            
            if pte == "No":
                st.markdown("**Question C:** Does it compile/package/transform the code that ships?")
                tsc = st.radio("C", ["Not answered", "Yes", "No"], key=f"tsc_{idx}", horizontal=True, label_visibility="collapsed")
                
                if tsc == "No":
                    st.markdown("**Question D:** Does it generate customer-facing content (IFU, manual, on-screen labeling)?")
                    gcc = st.radio("D", ["Not answered", "Yes", "No"], key=f"gcc_{idx}", horizontal=True, label_visibility="collapsed")
        
        determined_ctx = ""
        ctx_just = ""
        chain_done = rid == "Yes" or pte == "Yes" or tsc == "Yes" or gcc in ["Yes", "No"]
        
        if chain_done:
            ctx_ans = {
                "runs_in_device": rid if rid != "Not answered" else None,
                "produces_test_evidence": pte if pte != "Not answered" else None,
                "transforms_shipped_code": tsc if tsc != "Not answered" else None,
                "generates_customer_content": gcc if gcc != "Not answered" else None,
            }
            determined_ctx, ctx_just = determine_usage_context(ctx_ans)
            st.success(f"📍 **Determined:** {determined_ctx}")
            with st.expander("Why?", expanded=False):
                st.info(ctx_just)
        
        ctx_options = [""] + USAGE_CONTEXT_OPTIONS
        current_ctx = item.get("Usage Context", "")
        default_ctx = determined_ctx if determined_ctx else current_ctx
        usage_context_final = st.selectbox(
            "Final Usage Context",
            ctx_options,
            index=ctx_options.index(default_ctx) if default_ctx in ctx_options else 0,
            key=f"ctxf_{idx}",
        )
        existing_ctx_just = item.get("Usage Context Justification", "")
        usage_ctx_justification = st.text_area(
            "Usage Context Justification",
            value=ctx_just if ctx_just else existing_ctx_just,
            height=100, key=f"ctxj_{idx}",
        )
        
        st.divider()
        st.markdown("### Other QARA Decisions")
        
        st.caption(f"Agent suggests safety class: **{item.get('Suggested Safety Class', '—')}**")
        sc_options = ["", "Class A", "Class B", "Class C", "Not applicable"]
        current_sc = item.get("Confirmed Safety Class", "")
        confirmed_class = st.selectbox(
            "Confirmed Safety Class",
            sc_options,
            index=sc_options.index(current_sc) if current_sc in sc_options else 0,
            key=f"sc_{idx}",
        )
        
        intended_use = st.text_area("Intended use", value=item.get("Intended Use", ""),
                                     height=100, key=f"iu_{idx}")
        owner = st.text_input("Owner", value=item.get("Owner", ""), key=f"own_{idx}")
        func_req = st.text_area("Functional / Performance Requirements (§5.3.3)",
                                 value=item.get("Functional Requirements", ""),
                                 height=120, key=f"fr_{idx}")
        verif = st.text_area("Verification Notes", value=item.get("Verification Notes", ""),
                              height=100, key=f"vn_{idx}")
        approval = st.selectbox(
            "Approval Status",
            ["Draft", "Under Review", "Approved", "Deprecated"],
            index=["Draft", "Under Review", "Approved", "Deprecated"].index(
                item.get("Approval Status", "Draft")
            ) if item.get("Approval Status", "Draft") in ["Draft", "Under Review", "Approved", "Deprecated"] else 0,
            key=f"ap_{idx}",
        )
        
        col_save, col_del = st.columns([3, 1])
        with col_save:
            if st.button("💾 Save SOUP decisions", type="primary", key=f"save_{idx}"):
                updates = {
                    "Tool vs SOUP Justification": tool_soup_just,
                    "Confirmed Safety Class": confirmed_class,
                    "Intended Use": intended_use,
                    "Usage Context": usage_context_final,
                    "Usage Context Justification": usage_ctx_justification,
                    "Owner": owner,
                    "Functional Requirements": func_req,
                    "Verification Notes": verif,
                    "Approval Status": approval,
                }
                with st.spinner("Saving..."):
                    update_user_fields(SOUP_SHEET, item["Name"], str(item["Version"]),
                                       item["Ecosystem"], updates)
                st.success("✅ Saved to SOUP Inventory.")
        with col_del:
            if st.button("🗑️ Delete", type="secondary", key=f"del_{idx}"):
                delete_row(SOUP_SHEET, item["Name"], str(item["Version"]), item["Ecosystem"])
                st.success("Deleted.")
                st.rerun()

# ============================================================
# TAB 5: TOOL REVIEW (with guided risk picker)
# ============================================================
with tab5:
    st.subheader("🛠️ Tool Review (§5.1.4 + FDA CSA)")
    
    try:
        df = read_sheet(TOOL_SHEET)
    except Exception:
        df = pd.DataFrame()
    
    if df.empty:
        st.info("No Tool items yet.")
    else:
        labels = [f"{r['Name']}@{r['Version']} ({r['Ecosystem']})" for _, r in df.iterrows()]
        tidx = st.selectbox("Select Tool", range(len(labels)),
                            format_func=lambda i: labels[i], key="tool_select")
        item = df.iloc[tidx]
        
        st.markdown(f"### 🛠️ {item['Name']} `{item['Version']}`")
        
        with st.expander("📋 Auto-populated fields", expanded=False):
            for f in ["Publisher", "License", "Description", "Repository URL",
                      "Release Date", "Latest Version", "Outdated"]:
                st.markdown(f"**{f}:** {item.get(f, '—')}")
        
        with st.expander("🛡️ Vulnerabilities", expanded=int(item.get("CVE Count", 0) or 0) > 0):
            cc = int(item.get("CVE Count", 0) or 0)
            if cc == 0:
                st.success("✅ No known vulnerabilities.")
            else:
                st.warning(f"⚠️ {cc} CVE(s) — Highest CVSS: {item.get('Highest CVSS', '—')}")
                st.text(item.get("CVE List", ""))
        
        with st.expander("📝 Tool vs SOUP justification",
                         expanded=not bool(item.get("Tool vs SOUP Justification"))):
            existing = item.get("Tool vs SOUP Justification", "")
            if existing:
                st.info(existing)
            tool_soup_just_t = st.text_area("Edit (optional)", value=existing, height=100, key=f"ttsj_{tidx}")
        
        st.divider()
        
        # Tool Category & Function
        st.markdown("### Tool Category & Function")
        col_tc1, col_tc2 = st.columns(2)
        with col_tc1:
            current_cat = item.get("Tool Category", "")
            tool_cat = st.selectbox(
                "Tool Category",
                [""] + TOOL_CATEGORIES,
                index=([""] + TOOL_CATEGORIES).index(current_cat) if current_cat in ([""] + TOOL_CATEGORIES) else 0,
                key=f"tc_{tidx}",
            )
        with col_tc2:
            tool_func = st.text_input(
                "Tool Function in Process",
                value=item.get("Tool Function in Process", ""),
                placeholder="e.g., Runs unit tests during CI",
                key=f"tf_{tidx}",
            )
        
        # Usage Context (lighter for tools)
        st.markdown("**Usage Context:**")
        ctx_options = [""] + USAGE_CONTEXT_OPTIONS
        current_ctx_t = item.get("Usage Context", "")
        tool_ctx = st.selectbox(
            "Usage Context",
            ctx_options,
            index=ctx_options.index(current_ctx_t) if current_ctx_t in ctx_options else 0,
            key=f"tctx_{tidx}",
        )
        tool_ctx_just = st.text_area(
            "Usage Context Justification",
            value=item.get("Usage Context Justification", ""),
            height=80, key=f"tctxj_{tidx}",
        )
        
        st.divider()
        
        # ===================== GUIDED TOOL RISK PICKER =====================
        st.markdown("### 🎯 Tool Risk Level — Guided Picker (FDA CSA)")
        st.caption("Answer the questions in order. Stop at the first 'Yes'.")
        
        st.markdown("**Risk Q1:** Could a defect in this tool result in a product safety issue "
                    "(e.g., corrupted shipped code, undetected critical safety bug, tampered labeling)?")
        rq1 = st.radio("RQ1", ["Not answered", "Yes", "No"], key=f"rq1_{tidx}",
                       horizontal=True, label_visibility="collapsed")
        
        rq2 = "Not answered"
        rq3 = "Not answered"
        rq4 = "Not answered"
        
        if rq1 == "No":
            st.markdown("**Risk Q2:** Does this tool produce V&V evidence used for product release decisions "
                        "(test results, coverage reports, static analysis findings)?")
            rq2 = st.radio("RQ2", ["Not answered", "Yes", "No"], key=f"rq2_{tidx}",
                           horizontal=True, label_visibility="collapsed")
            
            if rq2 == "No":
                st.markdown("**Risk Q3:** Does this tool affect product quality (e.g., builds the shipping artifact, "
                            "transforms code, generates internal documentation)?")
                rq3 = st.radio("RQ3", ["Not answered", "Yes", "No"], key=f"rq3_{tidx}",
                               horizontal=True, label_visibility="collapsed")
                
                if rq3 == "Yes":
                    st.markdown("**Risk Q4:** Would other controls (code review, integration tests, manual QA) "
                                "reliably catch any defect introduced by this tool?")
                    rq4 = st.radio("RQ4", ["Not answered", "Yes", "No"], key=f"rq4_{tidx}",
                                   horizontal=True, label_visibility="collapsed")
        
        determined_risk = ""
        risk_just = ""
        risk_chain_done = (
            rq1 == "Yes" or rq2 == "Yes" or
            (rq3 == "Yes" and rq4 != "Not answered") or
            rq3 == "No"
        )
        
        if risk_chain_done:
            risk_ans = {
                "affects_product_safety": rq1 if rq1 != "Not answered" else None,
                "affects_vv_evidence": rq2 if rq2 != "Not answered" else None,
                "affects_quality": rq3 if rq3 != "Not answered" else None,
                "other_controls_catch": rq4 if rq4 != "Not answered" else None,
            }
            determined_risk, risk_just = classify_tool_risk(risk_ans)
            
            if determined_risk == "High":
                st.error(f"### 🔴 Risk Level: **{determined_risk}**")
            elif determined_risk == "Medium":
                st.warning(f"### 🟡 Risk Level: **{determined_risk}**")
            else:
                st.success(f"### 🟢 Risk Level: **{determined_risk}**")
            
            with st.expander("Why this risk level?", expanded=False):
                st.info(risk_just)
        
        st.markdown("**Final Risk Level (override if needed):**")
        current_risk = item.get("Tool Risk Level", "")
        default_risk = determined_risk if determined_risk else current_risk
        risk_final = st.selectbox(
            "Tool Risk Level",
            [""] + TOOL_RISK_LEVELS,
            index=([""] + TOOL_RISK_LEVELS).index(default_risk) if default_risk in ([""] + TOOL_RISK_LEVELS) else 0,
            key=f"rf_{tidx}",
        )
        risk_just_final = st.text_area(
            "Risk Justification",
            value=risk_just if risk_just else item.get("Tool Risk Justification", ""),
            height=100, key=f"rjf_{tidx}",
        )
        
        impact = st.text_area(
            "Impact if Tool Fails",
            value=item.get("Impact if Tool Fails", ""),
            placeholder="e.g., False-pass results could lead to releasing untested code",
            height=80, key=f"imp_{tidx}",
        )
        
        st.divider()
        
        # ===================== GUIDED VALIDATION APPROACH =====================
        st.markdown("### 🧪 Validation Approach — Guided by Risk Level")
        
        suggested_approach = ""
        approach_just = ""
        if risk_final:
            suggested_approach, approach_just = suggest_validation_approach(risk_final)
            st.info(f"💡 **Suggested validation approach for {risk_final} risk:** {suggested_approach}")
            with st.expander("Why?", expanded=False):
                st.markdown(approach_just)
        else:
            st.caption("Set the Risk Level above to see the suggested validation approach.")
        
        current_va = item.get("Validation Approach", "")
        default_va = suggested_approach if suggested_approach else current_va
        validation_approach = st.selectbox(
            "Final Validation Approach",
            [""] + VALIDATION_APPROACHES,
            index=([""] + VALIDATION_APPROACHES).index(default_va) if default_va in ([""] + VALIDATION_APPROACHES) else 0,
            key=f"va_{tidx}",
        )
        validation_approach_just = st.text_area(
            "Validation Approach Justification",
            value=approach_just if approach_just else item.get("Validation Approach Justification", ""),
            height=100, key=f"vaj_{tidx}",
        )
        
        st.divider()
        
        st.markdown("### Validation Evidence & Controls")
        validation_evidence = st.text_area(
            "Validation Evidence",
            value=item.get("Validation Evidence", ""),
            placeholder="e.g., Tool is industry-standard with >50M downloads; "
                        "internal smoke test confirms correct test execution on representative cases.",
            height=120, key=f"ve_{tidx}",
        )
        
        tool_output_verif = st.text_area(
            "Tool Output Verification",
            value=item.get("Tool Output Verification", ""),
            placeholder="e.g., CI pipeline asserts test reports are valid JSON and match expected schema.",
            height=100, key=f"tov_{tidx}",
        )
        
        config_mgmt = st.text_area(
            "Configuration Management",
            value=item.get("Configuration Management", ""),
            placeholder="e.g., Version pinned in requirements.txt; config file under version control in repo.",
            height=80, key=f"cm_{tidx}",
        )
        
        st.divider()
        
        col_vs1, col_vs2 = st.columns(2)
        with col_vs1:
            current_vs = item.get("Validation Status", "Pending")
            val_status = st.selectbox(
                "Validation Status",
                VALIDATION_STATUSES,
                index=VALIDATION_STATUSES.index(current_vs) if current_vs in VALIDATION_STATUSES else 0,
                key=f"vs_{tidx}",
            )
        with col_vs2:
            last_val = st.text_input(
                "Last Validation Date (YYYY-MM-DD)",
                value=item.get("Last Validation Date", ""),
                key=f"lvd_{tidx}",
            )
        
        tool_owner = st.text_input("Owner", value=item.get("Owner", ""), key=f"town_{tidx}")
        
        tool_approval = st.selectbox(
            "Approval Status",
            ["Draft", "Under Review", "Approved", "Deprecated"],
            index=["Draft", "Under Review", "Approved", "Deprecated"].index(
                item.get("Approval Status", "Draft")
            ) if item.get("Approval Status", "Draft") in ["Draft", "Under Review", "Approved", "Deprecated"] else 0,
            key=f"tap_{tidx}",
        )
        
        col_sav, col_dl = st.columns([3, 1])
        with col_sav:
            if st.button("💾 Save Tool decisions", type="primary", key=f"tsave_{tidx}"):
                updates = {
                    "Tool vs SOUP Justification": tool_soup_just_t,
                    "Tool Category": tool_cat,
                    "Tool Function in Process": tool_func,
                    "Usage Context": tool_ctx,
                    "Usage Context Justification": tool_ctx_just,
                    "Tool Risk Level": risk_final,
                    "Tool Risk Justification": risk_just_final,
                    "Impact if Tool Fails": impact,
                    "Validation Approach": validation_approach,
                    "Validation Approach Justification": validation_approach_just,
                    "Validation Evidence": validation_evidence,
                    "Tool Output Verification": tool_output_verif,
                    "Configuration Management": config_mgmt,
                    "Validation Status": val_status,
                    "Last Validation Date": last_val,
                    "Owner": tool_owner,
                    "Approval Status": tool_approval,
                }
                with st.spinner("Saving..."):
                    update_user_fields(TOOL_SHEET, item["Name"], str(item["Version"]),
                                       item["Ecosystem"], updates)
                st.success("✅ Saved to Tool Inventory.")
        with col_dl:
            if st.button("🗑️ Delete", type="secondary", key=f"tdel_{tidx}"):
                delete_row(TOOL_SHEET, item["Name"], str(item["Version"]), item["Ecosystem"])
                st.success("Deleted.")
                st.rerun()

# ============================================================
# TAB 6: HELP
# ============================================================
with tab6:
    st.subheader("Help & Definitions")
    
    st.markdown("### How records are organized")
    st.markdown("""
    Your workbook **"SOUP/Tool Inventory"** has three tabs:
    
    - **📦 SOUP Inventory** — items shipped inside the medical device. Full IEC 62304 §5.3.3 fields.
    - **🛠️ Tool Inventory** — items used to develop/build/test the device. FDA CSA-aligned fields.
    - **📋 Refresh Log** — daily refresh activity audit trail.
    
    When the classifier changes an item's type, the row is **automatically moved** between sheets.
    """)
    
    st.divider()
    
    st.markdown("### Tool Risk Levels (FDA CSA)")
    st.markdown("""
    | Risk | When | Validation Approach |
    |---|---|---|
    | 🔴 **High** | Defects could cause product safety issue OR produce false V&V evidence | Scripted testing with edge cases + IQ/OQ |
    | 🟡 **Medium** | Affects product quality; downstream controls provide secondary defense | Scripted testing with representative cases |
    | 🟢 **Low** | Limited impact OR strong downstream controls (code review, automated tests) | Vendor reliance + light internal checks |
    """)
    
    st.divider()
    
    st.markdown("### Validation Approaches (per FDA CSA 'least burdensome')")
    for approach in VALIDATION_APPROACHES:
        st.markdown(f"- **{approach}**")
    
    st.divider()
    
    st.markdown("### Common QARA reminders")
    st.markdown("""
    - **Tool validation effort scales with risk.** Don't over-validate Low-risk tools or under-validate High-risk ones.
    - **Tools used to test safety-critical functions = High risk by default.** A pytest bug that hides a critical failure is a real issue.
    - **Build tools deserve attention.** Supply-chain attacks (SolarWinds-style) make build pipeline integrity a regulator focus.
    - **Document the rationale.** "Why this risk level?" matters more than the level itself.
    """)

st.divider()
st.caption("🩺 SOUP & Tool Agent v4.0 • Separate sheets • Guided pickers • IEC 62304 §5.3.3 & §5.1.4 • FDA CSA")
