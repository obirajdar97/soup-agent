"""
SOUP Agent Dashboard (v3 — Google Sheets Edition with Guided Classification)
==============================================================================
For QARA professionals managing SOUP items per IEC 62304.

v3 changes:
  - Tool vs SOUP classifier (with guided questions)
  - Guided Usage Context picker (questions for non-QARA users)
  - Extended Google Sheet schema (3 new columns)

IEC 62304 §5.3.3, §5.3.4, §7, §8.1.2 (SOUP)
IEC 62304 §5.1.4 (Tool validation)
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
SHEET_NAME = "SOUP Inventory"
LOG_SHEET_NAME = "Refresh Log"

ECOSYSTEMS = {
    "npm": "npm — JavaScript / Node.js (web apps, frontends, React, Angular)",
    "PyPI": "PyPI — Python (AI/ML, data analysis, scripting)",
    "Maven": "Maven — Java (enterprise apps, Spring Boot, Android)",
    "NuGet": "NuGet — .NET / C# (Windows desktop apps, Microsoft stack)",
    "Go": "Go — Go language (modern backend services)",
    "Cargo": "Cargo — Rust (systems software, performance-critical)",
    "RubyGems": "RubyGems — Ruby (Rails web apps)",
}

USAGE_CONTEXT_OPTIONS = [
    "Production (runtime)",
    "Development tooling only",
    "Testing only",
    "Build pipeline only",
    "Documentation generation",
]

ITEM_TYPE_OPTIONS = ["SOUP", "Tool", "Not yet classified"]

# UPDATED COLUMN LIST — added 3 new columns
COLUMNS = [
    "Name", "Version", "Ecosystem", "Item Type",                # NEW: Item Type
    "Tool vs SOUP Justification",                                # NEW: Justification
    "Publisher", "License", "Description", "Repository URL",
    "Homepage", "Release Date", "Latest Version", "Outdated",
    "CVE Count", "Highest CVSS", "CVE List", "Anomaly List",
    "Suggested Safety Class", "Confirmed Safety Class",
    "Intended Use", "Usage Context",
    "Usage Context Justification",                                # NEW: Context Justification
    "Functional Requirements", "Verification Notes",
    "Approval Status", "Owner", "Date Added", "Last Refreshed",
]

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

def get_inventory_ws():
    return get_gsheet().worksheet(SHEET_NAME)

def get_log_ws():
    return get_gsheet().worksheet(LOG_SHEET_NAME)

def read_all_soup():
    ws = get_inventory_ws()
    records = ws.get_all_records()
    if not records:
        return pd.DataFrame(columns=COLUMNS)
    df = pd.DataFrame(records)
    for col in COLUMNS:
        if col not in df.columns:
            df[col] = ""
    return df

def find_row_index(name: str, version: str, ecosystem: str) -> int:
    df = read_all_soup()
    if df.empty:
        return 0
    mask = (
        (df["Name"].astype(str).str.lower() == name.lower()) &
        (df["Version"].astype(str) == version) &
        (df["Ecosystem"].astype(str) == ecosystem)
    )
    matches = df.index[mask].tolist()
    return matches[0] + 2 if matches else 0

def upsert_soup_row(record: dict):
    ws = get_inventory_ws()
    row_data = [record.get(col, "") for col in COLUMNS]
    existing = find_row_index(record["Name"], record["Version"], record["Ecosystem"])
    
    if existing > 0:
        user_cols = {
            "Item Type", "Tool vs SOUP Justification",
            "Confirmed Safety Class", "Intended Use", "Usage Context",
            "Usage Context Justification", "Functional Requirements",
            "Verification Notes", "Approval Status", "Owner", "Date Added",
        }
        for i, col in enumerate(COLUMNS):
            if col not in user_cols:
                ws.update_cell(existing, i + 1, row_data[i])
                time.sleep(0.1)
    else:
        ws.append_row(row_data, value_input_option="USER_ENTERED")

def update_user_fields(name: str, version: str, ecosystem: str, updates: dict):
    ws = get_inventory_ws()
    row = find_row_index(name, version, ecosystem)
    if row == 0:
        return False
    for field, value in updates.items():
        if field in COLUMNS:
            col_idx = COLUMNS.index(field) + 1
            ws.update_cell(row, col_idx, value)
            time.sleep(0.1)
    return True

def delete_soup_row(name: str, version: str, ecosystem: str):
    ws = get_inventory_ws()
    row = find_row_index(name, version, ecosystem)
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

def fetch_depsdev(ecosystem, name, version):
    url = f"https://api.deps.dev/v3/systems/{ecosystem}/packages/{name}/versions/{version}"
    try:
        r = requests.get(url, timeout=15)
        if r.status_code == 200:
            return r.json()
    except Exception:
        pass
    return {}

def fetch_depsdev_latest(ecosystem, name):
    url = f"https://api.deps.dev/v3/systems/{ecosystem}/packages/{name}"
    try:
        r = requests.get(url, timeout=15)
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

def fetch_osv_vulns(ecosystem, name, version):
    try:
        r = requests.post("https://api.osv.dev/v1/query",
                          json={"package": {"name": name, "ecosystem": ecosystem},
                                "version": version}, timeout=15)
        if r.status_code == 200:
            return r.json().get("vulns", [])
    except Exception:
        pass
    return []

def fetch_nvd_cvss(cve_id):
    try:
        r = requests.get(
            f"https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={cve_id}", timeout=15)
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
        return "N/A — Tool (use §5.1.4 tool validation, not SOUP safety class)"
    if highest_cvss >= 7.0 or cve_count >= 3:
        return "Class B/C — HUMAN REVIEW REQUIRED (significant vulns)"
    if is_outdated and cve_count > 0:
        return "Class B — HUMAN REVIEW REQUIRED (outdated with vulns)"
    return "Class A (suggested — confirm based on usage)"

# ============================================================
# ENRICHMENT
# ============================================================

def enrich_soup(ecosystem, name, version, item_type="SOUP"):
    meta = fetch_depsdev(ecosystem, name, version)
    latest = fetch_depsdev_latest(ecosystem, name)
    is_outdated = bool(latest and latest != version)
    vulns = fetch_osv_vulns(ecosystem, name, version)
    
    cve_summary = []
    highest_cvss = 0.0
    for v in vulns:
        cve_ids = [a for a in v.get("aliases", []) if a.startswith("CVE-")]
        primary = cve_ids[0] if cve_ids else v.get("id", "Unknown")
        score = 0.0
        if cve_ids:
            score = fetch_nvd_cvss(cve_ids[0])
            time.sleep(0.6)
        cve_summary.append({
            "id": primary,
            "summary": v.get("summary", "")[:200],
            "cvss": score,
            "severity": severity_label(score),
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
        for c in cve_summary
    ]) or "No known vulnerabilities"
    
    anomaly_text = "\n".join([f"• {c['id']}: {c['summary']}" for c in cve_summary]) \
        or "None identified from public sources"
    
    return {
        "Name": name,
        "Version": version,
        "Ecosystem": ecosystem,
        "Item Type": item_type,
        "Tool vs SOUP Justification": "",
        "Publisher": meta.get("registries", [ecosystem])[0] if meta.get("registries") else ecosystem,
        "License": license_str,
        "Description": meta.get("description", "")[:500] or f"{name} {version}",
        "Repository URL": repo_url,
        "Homepage": homepage,
        "Release Date": meta.get("publishedAt", ""),
        "Latest Version": latest,
        "Outdated": "Yes" if is_outdated else "No",
        "CVE Count": len(cve_summary),
        "Highest CVSS": highest_cvss,
        "CVE List": cve_text,
        "Anomaly List": anomaly_text,
        "Suggested Safety Class": suggest_safety_class(len(cve_summary), highest_cvss, is_outdated, item_type),
        "Confirmed Safety Class": "",
        "Intended Use": "",
        "Usage Context": "",
        "Usage Context Justification": "",
        "Functional Requirements": "",
        "Verification Notes": "",
        "Approval Status": "Draft",
        "Owner": "",
        "Date Added": datetime.now(IST).strftime("%Y-%m-%d %H:%M IST"),
        "Last Refreshed": datetime.now(IST).strftime("%Y-%m-%d %H:%M IST"),
    }

# ============================================================
# REFRESH
# ============================================================

def refresh_all(trigger="manual"):
    df = read_all_soup()
    if df.empty:
        log_refresh(trigger, 0, 0, "Nothing to refresh")
        return 0, 0
    new_cves_total = 0
    for _, row in df.iterrows():
        try:
            old = int(row.get("CVE Count", 0) or 0)
            item_type = row.get("Item Type", "SOUP") or "SOUP"
            rec = enrich_soup(row["Ecosystem"], row["Name"], str(row["Version"]), item_type)
            diff = rec["CVE Count"] - old
            if diff > 0:
                new_cves_total += diff
            upsert_soup_row(rec)
        except Exception as e:
            print(f"Refresh failed for {row.get('Name','?')}: {e}")
    log_refresh(trigger, len(df), new_cves_total)
    return len(df), new_cves_total

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
# CLASSIFIER LOGIC — Tool vs SOUP
# ============================================================

def classify_tool_vs_soup(answers: dict) -> tuple:
    """Determine if item is SOUP or Tool based on 3 questions.
    
    The core IEC 62304 distinction:
      - SOUP: software INCORPORATED INTO the medical device
      - Tool: software used to develop/build/test/maintain the device
    
    Returns (classification, justification_text)
    """
    q1 = answers.get("ships_in_device")
    q2 = answers.get("output_in_device")
    q3 = answers.get("affects_quality")
    
    justification_parts = []
    
    if q1 == "Yes":
        justification_parts.append(
            "This item is incorporated into the released medical device — its code runs "
            "on the device or as part of the released software."
        )
        return ("SOUP", " ".join(justification_parts) + " Therefore classified as SOUP per IEC 62304 §3.31. "
                "Apply §5.3.3, §5.3.4, and §7 requirements.")
    
    if q1 == "No":
        justification_parts.append(
            "This item does NOT ship inside the medical device — its code does not execute "
            "on the customer's device or as part of the released product."
        )
        
        if q2 == "Yes":
            justification_parts.append(
                "However, it transforms code or generates content that DOES ship "
                "(e.g., build tool, code generator, document generator for IFU)."
            )
            return ("Tool", " ".join(justification_parts) + " Therefore classified as a Tool per IEC 62304 §5.1.4. "
                    "Apply tool validation proportional to risk that defects could affect product quality (FDA CSA approach).")
        
        if q3 == "Yes":
            justification_parts.append(
                "It produces evidence used in V&V or quality decisions (e.g., test framework, "
                "static analysis tool, test data generator)."
            )
            return ("Tool", " ".join(justification_parts) + " Therefore classified as a Tool per IEC 62304 §5.1.4. "
                    "Validate to ensure reliable verification evidence (FDA CSA risk-based approach).")
        
        justification_parts.append(
            "It is used only for developer convenience (e.g., code formatter, IDE plugin) "
            "and does not affect product code, output, or V&V evidence."
        )
        return ("Tool", " ".join(justification_parts) + " Classified as low-risk Tool per IEC 62304 §5.1.4. "
                "Minimal validation required; document version and license for completeness.")
    
    return ("Not yet classified", "Insufficient information to classify.")

def determine_usage_context(answers: dict) -> tuple:
    """Determine usage context based on guided answers.
    Returns (context, justification_text)
    """
    runs_in_device = answers.get("runs_in_device")
    produces_test_evidence = answers.get("produces_test_evidence")
    transforms_shipped_code = answers.get("transforms_shipped_code")
    generates_customer_content = answers.get("generates_customer_content")
    
    if runs_in_device == "Yes":
        return ("Production (runtime)",
                "This item executes within the medical device during normal operation. It is in scope "
                "for full IEC 62304 §5.3.3 / §5.3.4 SOUP treatment. Patient safety considerations apply.")
    
    if produces_test_evidence == "Yes":
        return ("Testing only",
                "This item is used to produce verification/validation evidence for the medical device "
                "but does not ship with it. Validate per IEC 62304 §5.1.4 with rigor proportional to "
                "the importance of the evidence it produces (FDA CSA approach).")
    
    if transforms_shipped_code == "Yes":
        return ("Build pipeline only",
                "This item compiles, packages, or transforms the code that ships in the device. Although "
                "the tool itself does not run on the device, defects could introduce vulnerabilities in "
                "the shipped product. Address under supply-chain integrity and tool validation.")
    
    if generates_customer_content == "Yes":
        return ("Documentation generation",
                "This item generates content visible to end users (IFU, user manual, on-screen labeling). "
                "Output is regulated under FDA 21 CFR 801 / EU MDR Annex I labeling rules. Verify the tool "
                "reliably reproduces source content in the final output.")
    
    return ("Development tooling only",
            "This item runs only on developer machines and does not affect shipped product, V&V evidence, "
            "build output, or customer-facing content. Lightweight tool documentation per IEC 62304 §5.1.4.")

# ============================================================
# UI
# ============================================================

st.title("🩺 SOUP & Tool Agent — IEC 62304")
st.caption("Tracks SOUP items (§5.3.3) and Tools (§5.1.4) for SaMD / SiMD development & testing")

# Sidebar
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
        st.markdown(f"[📊 Open Google Sheet ↗]({sheet_url})")
    st.caption("Tip: edit any cell directly in the sheet.")

# Tabs
tab1, tab2, tab3, tab4, tab5 = st.tabs([
    "➕ Add Item",
    "🤔 Classify: Tool or SOUP?",
    "📊 Inventory",
    "✅ QARA Review",
    "ℹ️ Help & Definitions",
])

# ============================================================
# TAB 1: ADD ITEM
# ============================================================
with tab1:
    st.subheader("Add a new SOUP item or Tool")
    st.info(
        "💡 **Not sure if your item is SOUP or a Tool?** "
        "Go to the **'🤔 Classify: Tool or SOUP?'** tab first — it'll guide you through 3 questions and tell you which one.\n\n"
        "**Quick rule:** If the software's code runs *inside* your medical device → **SOUP**. "
        "If it only helps you build, test, or deliver the device → **Tool**."
    )
    
    col1, col2, col3 = st.columns([2, 2, 2])
    with col1:
        ecosystem = st.selectbox("Ecosystem", list(ECOSYSTEMS.keys()),
                                  format_func=lambda x: ECOSYSTEMS[x],
                                  help="Pick the registry your developer/tester downloads this from.")
    with col2:
        name = st.text_input("Package name", placeholder="e.g., lodash, numpy, pytest")
    with col3:
        version = st.text_input("Version", placeholder="e.g., 4.17.21")
    
    item_type = st.radio(
        "Item Type",
        ITEM_TYPE_OPTIONS,
        horizontal=True,
        help="SOUP = ships in the device. Tool = used to develop/build/test the device. Not sure? Use the 'Classify' tab."
    )
    
    if item_type == "Not yet classified":
        st.warning("⚠️ Use the **'🤔 Classify: Tool or SOUP?'** tab to determine this before submitting.")
    
    st.markdown("---")
    st.markdown("**Optional now — can be filled later in the QARA Review tab:**")
    
    col4, col5 = st.columns(2)
    with col4:
        intended_use = st.text_area(
            "Intended use in your software",
            height=80,
            placeholder="e.g., Parses incoming JSON patient data in the registration module",
            help="A one-sentence description of how this is used in YOUR specific software."
        )
    with col5:
        usage_context = st.selectbox(
            "Usage context (or leave blank for now)",
            [""] + USAGE_CONTEXT_OPTIONS,
            help="Where does this item run? See the Help tab or QARA Review tab for guidance."
        )
    
    owner = st.text_input("Owner / Responsible person", placeholder="Your name, dev team, etc.")
    
    if st.button("✨ Generate Record", type="primary"):
        if not name.strip() or not version.strip():
            st.error("Please enter both name and version.")
        else:
            with st.spinner(f"Fetching data for {name}@{version}..."):
                try:
                    record = enrich_soup(ecosystem, name.strip(), version.strip(), item_type)
                    if intended_use:
                        record["Intended Use"] = intended_use
                    if usage_context:
                        record["Usage Context"] = usage_context
                    if owner:
                        record["Owner"] = owner
                    
                    upsert_soup_row(record)
                    st.success(f"✅ Record added: {name}@{version} ({item_type})")
                    
                    c1, c2, c3, c4 = st.columns(4)
                    c1.metric("License", record["License"])
                    c2.metric("CVEs", record["CVE Count"])
                    c3.metric("Max CVSS", f"{record['Highest CVSS']:.1f}" if record["Highest CVSS"] else "—")
                    c4.metric("Outdated", record["Outdated"])
                    
                    if record["CVE Count"] > 0:
                        st.warning(f"⚠️ {record['CVE Count']} vulnerabilities found.")
                    if record["Outdated"] == "Yes":
                        st.info(f"ℹ️ Latest version available: {record['Latest Version']}")
                    
                    st.info(f"💡 Suggested safety class: **{record['Suggested Safety Class']}**")
                    st.caption("Open QARA Review tab to add intended use, confirm class, and approve.")
                except Exception as e:
                    st.error(f"Error: {e}")

# ============================================================
# TAB 2: CLASSIFY TOOL VS SOUP
# ============================================================
with tab2:
    st.subheader("🤔 Is this item SOUP or a Tool?")
    
    st.markdown("""
    **Why this matters:** IEC 62304 treats these differently.
    
    - **SOUP** (§5.3.3, §5.3.4, §7): Software *incorporated into* the medical device. 
      Heavy documentation, full risk analysis, anomaly tracking, SBOM inclusion.
    - **Tool** (§5.1.4): Software used to *develop, build, test, or maintain* the device but 
      not part of the released product. Validation proportional to risk (FDA CSA approach).
    
    Answer **3 questions** below. The agent will tell you which category your item falls into 
    and write the justification to your sheet.
    """)
    
    st.divider()
    
    # Item lookup
    col_lookup1, col_lookup2 = st.columns(2)
    df_classify = read_all_soup() if "df_classify_loaded" not in st.session_state else st.session_state.get("df_classify_cached", read_all_soup())
    
    if not df_classify.empty:
        with col_lookup1:
            classify_existing = st.checkbox("Classify an existing item in inventory")
    else:
        classify_existing = False
    
    selected_item = None
    if classify_existing and not df_classify.empty:
        labels = [f"{r['Name']}@{r['Version']} ({r['Ecosystem']}) — currently: {r.get('Item Type','—')}"
                  for _, r in df_classify.iterrows()]
        idx = st.selectbox("Select item to classify", range(len(labels)),
                           format_func=lambda i: labels[i])
        selected_item = df_classify.iloc[idx]
        st.markdown(f"**Classifying:** {selected_item['Name']}@{selected_item['Version']}")
    else:
        st.markdown("**Or describe a new item to classify:**")
        col_d1, col_d2 = st.columns(2)
        with col_d1:
            classify_name = st.text_input("Item name (for reference)", key="classify_name")
        with col_d2:
            st.caption("You can save this to inventory after classifying.")
    
    st.divider()
    
    # The 3 questions
    st.markdown("### Question 1")
    st.markdown(
        "**Does this software's code actually run on the customer's medical device, "
        "or get shipped inside the released product?**\n\n"
        "Examples of YES:\n"
        "- A JSON parser bundled into your iOS SaMD app\n"
        "- A machine learning library running the diagnostic algorithm\n"
        "- A cryptography library protecting patient data in your device\n"
        "- A UI framework rendering the clinician dashboard on the device\n\n"
        "Examples of NO:\n"
        "- A code formatter that runs only on developer laptops\n"
        "- A testing framework used during V&V but never installed on the device\n"
        "- A build tool that packages your code"
    )
    q1 = st.radio(
        "Your answer:",
        ["Not yet answered", "Yes — its code runs inside the device", "No — it never runs on the device"],
        key="q1",
        label_visibility="collapsed",
    )
    
    q1_value = None
    if q1.startswith("Yes"): q1_value = "Yes"
    elif q1.startswith("No"): q1_value = "No"
    
    q2_value = None
    q3_value = None
    
    if q1_value == "No":
        st.divider()
        st.markdown("### Question 2")
        st.markdown(
            "**Does this software produce or transform anything that ends up in the released device?**\n\n"
            "This includes:\n"
            "- Build tools (Maven, Gradle, webpack, Vite) — they package the shipping code\n"
            "- Code generators that produce source code that ships\n"
            "- Tools that generate the IFU, user manual, or on-screen labeling\n"
            "- Document tools that produce regulated content the customer sees\n\n"
            "Does NOT include:\n"
            "- Test results, log files, or internal dev documentation"
        )
        q2 = st.radio(
            "Your answer:",
            ["Not yet answered", "Yes — its output ships or appears in the device/labeling",
             "No — its output stays internal"],
            key="q2",
            label_visibility="collapsed",
        )
        if q2.startswith("Yes"): q2_value = "Yes"
        elif q2.startswith("No"): q2_value = "No"
        
        if q2_value == "No":
            st.divider()
            st.markdown("### Question 3")
            st.markdown(
                "**Does this software produce evidence used to verify or validate the device's quality?**\n\n"
                "Examples of YES:\n"
                "- pytest, JUnit, NUnit — produce test results that prove the device works\n"
                "- Coverage tools (Coverage.py, JaCoCo) — produce coverage evidence\n"
                "- Static analysis tools whose findings drive code changes\n"
                "- Test data generators that create test fixtures\n\n"
                "Examples of NO:\n"
                "- A code formatter (just cosmetic)\n"
                "- An IDE plugin for syntax highlighting\n"
                "- A debugger used during development"
            )
            q3 = st.radio(
                "Your answer:",
                ["Not yet answered", "Yes — it produces V&V or quality evidence",
                 "No — it's purely for developer convenience"],
                key="q3",
                label_visibility="collapsed",
            )
            if q3.startswith("Yes"): q3_value = "Yes"
            elif q3.startswith("No"): q3_value = "No"
    
    # Show classification result
    answered = q1_value == "Yes" or \
               (q1_value == "No" and q2_value == "Yes") or \
               (q1_value == "No" and q2_value == "No" and q3_value is not None)
    
    if answered:
        st.divider()
        answers = {
            "ships_in_device": q1_value,
            "output_in_device": q2_value,
            "affects_quality": q3_value,
        }
        classification, justification = classify_tool_vs_soup(answers)
        
        if classification == "SOUP":
            st.error(f"### 📦 Classification: **{classification}**")
        else:
            st.warning(f"### 🛠️ Classification: **{classification}**")
        
        st.markdown(f"**Justification:**\n\n{justification}")
        
        st.markdown("---")
        st.markdown("**Save this classification?**")
        
        if classify_existing and selected_item is not None:
            if st.button("💾 Save classification to inventory", type="primary"):
                update_user_fields(
                    selected_item["Name"], str(selected_item["Version"]), selected_item["Ecosystem"],
                    {
                        "Item Type": classification,
                        "Tool vs SOUP Justification": justification,
                    }
                )
                st.success(f"✅ Saved. {selected_item['Name']} is now classified as **{classification}** in your sheet.")
        else:
            st.info("To save this classification, first add the item via the **'➕ Add Item'** tab, "
                    f"selecting **{classification}** as the Item Type. Then come back here to attach the justification.")

# ============================================================
# TAB 3: INVENTORY
# ============================================================
with tab3:
    st.subheader("Inventory")
    if st.button("🔃 Reload from sheet"):
        st.cache_data.clear()
        st.rerun()
    
    try:
        df = read_all_soup()
    except Exception as e:
        st.error(f"Could not load sheet: {e}")
        df = pd.DataFrame()
    
    if df.empty:
        st.info("No items yet. Add one in the '➕ Add Item' tab.")
    else:
        c1, c2, c3, c4, c5 = st.columns(5)
        c1.metric("Total items", len(df))
        c2.metric("SOUP", int((df["Item Type"] == "SOUP").sum()))
        c3.metric("Tools", int((df["Item Type"] == "Tool").sum()))
        c4.metric("With CVEs", int((pd.to_numeric(df["CVE Count"], errors="coerce").fillna(0) > 0).sum()))
        c5.metric("Approved", int((df["Approval Status"] == "Approved").sum()))
        
        st.divider()
        
        col_f1, col_f2 = st.columns(2)
        with col_f1:
            type_filter = st.multiselect(
                "Filter by Item Type",
                ITEM_TYPE_OPTIONS,
                default=ITEM_TYPE_OPTIONS,
            )
        with col_f2:
            status_filter = st.multiselect(
                "Filter by Approval Status",
                ["Draft", "Under Review", "Approved", "Deprecated"],
                default=["Draft", "Under Review", "Approved"],
            )
        
        filtered = df[df["Item Type"].isin(type_filter) & df["Approval Status"].isin(status_filter)]
        
        st.dataframe(
            filtered[["Name", "Version", "Ecosystem", "Item Type", "License", "CVE Count",
                      "Highest CVSS", "Outdated", "Usage Context", "Approval Status",
                      "Owner", "Last Refreshed"]],
            hide_index=True,
            use_container_width=True,
        )

# ============================================================
# TAB 4: QARA REVIEW
# ============================================================
with tab4:
    st.subheader("QARA Review")
    
    try:
        df = read_all_soup()
    except Exception:
        df = pd.DataFrame()
    
    if df.empty:
        st.info("No items to review yet.")
    else:
        labels = [f"{r['Name']}@{r['Version']} ({r['Ecosystem']}) — {r.get('Item Type','—')}"
                  for _, r in df.iterrows()]
        idx = st.selectbox("Select item", range(len(labels)),
                           format_func=lambda i: labels[i])
        item = df.iloc[idx]
        
        st.markdown(f"### {item['Name']} `{item['Version']}` — *{item.get('Item Type', '—')}*")
        
        # Show technical fields
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
        
        # Tool vs SOUP justification (editable)
        with st.expander("📝 Tool vs SOUP justification", expanded=not bool(item.get("Tool vs SOUP Justification"))):
            existing_justif = item.get("Tool vs SOUP Justification", "")
            if existing_justif:
                st.info(existing_justif)
            else:
                st.warning("No justification yet. Use the **'🤔 Classify'** tab to generate one, or write one manually below.")
            tool_soup_just = st.text_area(
                "Edit justification (optional)",
                value=existing_justif,
                height=120,
                key=f"tsjust_{idx}",
            )
        
        st.divider()
        
        # ==================== GUIDED USAGE CONTEXT ====================
        st.markdown("### 📍 Usage Context — Guided Picker")
        st.caption(
            "Answer these 4 questions in order. Stop as soon as you get a 'Yes'. "
            "The agent will pick the right context and explain why."
        )
        
        st.markdown("**Question A:** Does this software's code execute INSIDE the medical device when the patient or clinician uses it?")
        runs_in_device = st.radio(
            "Q-A",
            ["Not answered", "Yes", "No"],
            key=f"runs_in_device_{idx}",
            horizontal=True,
            label_visibility="collapsed",
        )
        
        produces_test_evidence = "Not answered"
        transforms_shipped_code = "Not answered"
        generates_customer_content = "Not answered"
        
        if runs_in_device == "No":
            st.markdown("**Question B:** Is this software used to produce verification or validation evidence (e.g., test framework, coverage tool, test data generator)?")
            produces_test_evidence = st.radio(
                "Q-B",
                ["Not answered", "Yes", "No"],
                key=f"prod_test_{idx}",
                horizontal=True,
                label_visibility="collapsed",
            )
            
            if produces_test_evidence == "No":
                st.markdown("**Question C:** Does this software compile, package, or transform the code that ships in the device (build tool, bundler, code generator)?")
                transforms_shipped_code = st.radio(
                    "Q-C",
                    ["Not answered", "Yes", "No"],
                    key=f"trans_code_{idx}",
                    horizontal=True,
                    label_visibility="collapsed",
                )
                
                if transforms_shipped_code == "No":
                    st.markdown("**Question D:** Does this software generate content the customer sees (user manual, IFU, on-screen labeling)?")
                    generates_customer_content = st.radio(
                        "Q-D",
                        ["Not answered", "Yes", "No"],
                        key=f"cust_content_{idx}",
                        horizontal=True,
                        label_visibility="collapsed",
                    )
        
        # Auto-determine context
        determined_context = ""
        context_justification = ""
        any_answered = runs_in_device != "Not answered"
        
        if any_answered:
            ctx_answers = {
                "runs_in_device": runs_in_device if runs_in_device != "Not answered" else None,
                "produces_test_evidence": produces_test_evidence if produces_test_evidence != "Not answered" else None,
                "transforms_shipped_code": transforms_shipped_code if transforms_shipped_code != "Not answered" else None,
                "generates_customer_content": generates_customer_content if generates_customer_content != "Not answered" else None,
            }
            
            # Only finalize when we have a definitive answer
            chain_complete = (
                runs_in_device == "Yes" or
                produces_test_evidence == "Yes" or
                transforms_shipped_code == "Yes" or
                generates_customer_content in ["Yes", "No"]
            )
            
            if chain_complete:
                determined_context, context_justification = determine_usage_context(ctx_answers)
                st.success(f"📍 **Determined context:** {determined_context}")
                with st.expander("ℹ️ Why this context?", expanded=False):
                    st.info(context_justification)
        
        st.markdown("**Override (optional):**")
        ctx_options = [""] + USAGE_CONTEXT_OPTIONS
        current_ctx = item.get("Usage Context", "")
        default_ctx = determined_context if determined_context else current_ctx
        
        usage_context_final = st.selectbox(
            "Final Usage Context (you can override the guided answer)",
            ctx_options,
            index=ctx_options.index(default_ctx) if default_ctx in ctx_options else 0,
            key=f"ctx_{idx}",
        )
        
        existing_ctx_just = item.get("Usage Context Justification", "")
        usage_context_justification = st.text_area(
            "Usage Context Justification",
            value=context_justification if context_justification else existing_ctx_just,
            height=100,
            key=f"ctxjust_{idx}",
        )
        
        st.divider()
        
        # Other QARA fields
        st.markdown("### Other QARA Decisions")
        
        st.caption(f"Agent suggests safety class: **{item.get('Suggested Safety Class', '—')}**")
        sc_options = ["", "Class A", "Class B", "Class C", "N/A (Tool)", "Not applicable"]
        current_sc = item.get("Confirmed Safety Class", "")
        confirmed_class = st.selectbox(
            "Confirmed Safety Class",
            sc_options,
            index=sc_options.index(current_sc) if current_sc in sc_options else 0,
            key=f"sc_{idx}",
            help="For Tools, select 'N/A (Tool)' — tool validation uses §5.1.4 instead of SOUP safety class.",
        )
        
        intended_use = st.text_area(
            "Intended use",
            value=item.get("Intended Use", ""),
            height=100,
            key=f"iu_{idx}",
            help="One sentence on how this is used in YOUR software."
        )
        
        owner = st.text_input("Owner", value=item.get("Owner", ""), key=f"own_{idx}")
        
        func_req = st.text_area(
            "Functional / Performance Requirements (IEC 62304 §5.3.3)",
            value=item.get("Functional Requirements", ""),
            height=120,
            key=f"fr_{idx}",
        )
        
        verif = st.text_area(
            "Verification Notes",
            value=item.get("Verification Notes", ""),
            height=100,
            key=f"vn_{idx}",
        )
        
        approval = st.selectbox(
            "Approval Status",
            ["Draft", "Under Review", "Approved", "Deprecated"],
            index=["Draft", "Under Review", "Approved", "Deprecated"].index(
                item.get("Approval Status", "Draft")
            ) if item.get("Approval Status", "Draft") in
                ["Draft", "Under Review", "Approved", "Deprecated"] else 0,
            key=f"ap_{idx}",
        )
        
        col_save, col_del = st.columns([3, 1])
        with col_save:
            if st.button("💾 Save QARA decisions to sheet", type="primary", key=f"save_{idx}"):
                updates = {
                    "Tool vs SOUP Justification": tool_soup_just,
                    "Confirmed Safety Class": confirmed_class,
                    "Intended Use": intended_use,
                    "Usage Context": usage_context_final,
                    "Usage Context Justification": usage_context_justification,
                    "Owner": owner,
                    "Functional Requirements": func_req,
                    "Verification Notes": verif,
                    "Approval Status": approval,
                }
                with st.spinner("Saving..."):
                    update_user_fields(item["Name"], str(item["Version"]),
                                       item["Ecosystem"], updates)
                st.success("✅ Saved to Google Sheet.")
        with col_del:
            if st.button("🗑️ Delete", type="secondary", key=f"del_{idx}"):
                delete_soup_row(item["Name"], str(item["Version"]), item["Ecosystem"])
                st.success("Deleted.")
                st.rerun()

# ============================================================
# TAB 5: HELP & DEFINITIONS
# ============================================================
with tab5:
    st.subheader("Help & Definitions")
    
    st.markdown("### Tool vs SOUP — Quick Reference")
    st.markdown("""
    | Aspect | SOUP | Tool |
    |---|---|---|
    | **Ships inside device?** | Yes | No |
    | **IEC 62304 reference** | §5.3.3, §5.3.4, §7 | §5.1.4 |
    | **FDA approach** | SBOM + cybersecurity | CSA (Computer Software Assurance) |
    | **Documentation depth** | Heavy (functional/perf req, anomaly list, risk analysis) | Proportional to risk |
    | **Examples** | UI framework in device, ML library, cryptography lib, JSON parser bundled in app | pytest, Maven, ESLint, Sphinx, Docker, Git |
    """)
    
    st.divider()
    
    st.markdown("### Usage Context — Definitions")
    
    with st.expander("🩺 Production (runtime) — HIGHEST RISK"):
        st.markdown("""
        **The software's code runs inside the device during normal use.**
        
        Examples:
        - JSON parser processing patient data inside your SaMD
        - TensorFlow running the AI diagnostic model
        - Cryptography library protecting patient data in transit
        - UI framework rendering the clinician's dashboard
        
        QARA treatment:
        - Full IEC 62304 §5.3.3 / §5.3.4 SOUP documentation
        - Functional and performance requirements documented
        - Hardware/software environment requirements documented
        - Anomaly list reviewed
        - Risk analysis per ISO 14971
        - Continuous CVE monitoring required
        - Included in SBOM for FDA submission
        """)
    
    with st.expander("🛠️ Development tooling only — LOWEST RISK"):
        st.markdown("""
        **Used only by developers on their machines. Doesn't affect product, test evidence, or build output.**
        
        Examples:
        - Code formatter (Prettier, Black)
        - Linter (ESLint, Pylint) — flags coding style
        - IDE syntax highlighter plugin
        - Debugger used during development
        
        QARA treatment:
        - Lightweight IEC 62304 §5.1.4 tool documentation
        - Record name, version, license
        - Validation only if the tool could affect code that ships
        """)
    
    with st.expander("🧪 Testing only — MODERATE RISK"):
        st.markdown("""
        **Used to test the software. Doesn't ship — but produces V&V evidence you rely on.**
        
        Examples:
        - pytest, JUnit, Jest, NUnit
        - Mock libraries faking external services in tests
        - Coverage tools (Coverage.py, JaCoCo)
        - Test data generators (Faker)
        - E2E test tools (Selenium, Cypress)
        
        QARA treatment:
        - IEC 62304 §5.1.4 + FDA CSA (risk-based test tool validation)
        - Mature widely-used tools get lighter validation
        - Custom or obscure test tools need more rigorous validation
        - The risk: a buggy test tool could give false confidence in test results
        """)
    
    with st.expander("🔧 Build pipeline only — MODERATE RISK"):
        st.markdown("""
        **Compiles, packages, or transforms code on its way to becoming the shipped product.**
        
        Examples:
        - Maven, Gradle, npm, pip (package management & build)
        - webpack, Vite, Rollup (bundlers)
        - Docker, BuildKit (container builders)
        - Code signing tools
        - CI/CD pipeline plugins
        
        QARA treatment:
        - IEC 62304 §5.1.4 tool validation
        - FDA cybersecurity guidance — supply chain integrity
        - Verify build reproducibility
        - Monitor for vulnerabilities (supply chain attacks like SolarWinds)
        """)
    
    with st.expander("📄 Documentation generation — LOW to MODERATE RISK"):
        st.markdown("""
        **Generates documentation, manuals, or labeling.**
        
        Examples:
        - Sphinx, MkDocs, Doxygen, JSDoc — developer docs
        - Mermaid, PlantUML — diagrams
        - Tools generating the user manual or IFU
        - Tools generating on-screen help content
        
        QARA treatment:
        - If output is internal developer docs: lightweight
        - If output is user-facing (IFU, manual, labeling):
          - FDA 21 CFR 801 / EU MDR Annex I labeling rules apply
          - Verify the tool reliably reproduces source content
          - Validate output against source as part of release
        """)
    
    st.divider()
    
    st.markdown("### Three Common QARA Mistakes")
    st.markdown("""
    1. **Calling everything SOUP "to be safe."** This drowns the team in paperwork and dilutes attention 
       from items that actually matter. Be honest about what ships and what doesn't.
    
    2. **Classifying Production items as Testing because they're also used in unit tests.** 
       If a library runs in production AND in tests, the production usage dominates. Pick Production.
    
    3. **Ignoring build tools because "they don't ship."** Build tools produce the shipped artifact. 
       A compromised build tool means a compromised product (SolarWinds-style supply chain attack).
    """)

st.divider()
st.caption("🩺 SOUP & Tool Agent v3.0 • Guided classification • IEC 62304 §5.3.3, §5.3.4, §5.1.4 • Data: deps.dev, OSV.dev, NVD")
