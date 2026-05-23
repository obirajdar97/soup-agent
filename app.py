"""
SOUP Agent Dashboard (v2 — Google Sheets Edition)
=================================================
For QARA professionals managing SOUP items per IEC 62304.

This version stores ALL data in YOUR Google Sheet (not a local file).
Benefits:
  - Open the sheet anytime in any browser
  - Built-in revision history (audit trail)
  - Easy backup / sharing / export
  - Survives laptop crashes or moves

Compliance reference: IEC 62304 §5.3.3, §5.3.4, §7, §8.1.2
"""

import streamlit as st
import requests
import json
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
SHEET_NAME = "SOUP Inventory"  # main worksheet/tab name
LOG_SHEET_NAME = "Refresh Log"  # log tab name

ECOSYSTEMS = {
    "npm": "npm (JavaScript/Node.js)",
    "PyPI": "PyPI (Python)",
    "Maven": "Maven (Java)",
    "NuGet": "NuGet (.NET)",
    "Go": "Go modules",
    "Cargo": "Cargo (Rust)",
    "RubyGems": "RubyGems (Ruby)",
}

# Column order in the Google Sheet — must match the template
COLUMNS = [
    "Name", "Version", "Ecosystem", "Publisher", "License",
    "Description", "Repository URL", "Homepage", "Release Date",
    "Latest Version", "Outdated", "CVE Count", "Highest CVSS",
    "CVE List", "Anomaly List", "Suggested Safety Class",
    "Confirmed Safety Class", "Intended Use", "Usage Context",
    "Functional Requirements", "Verification Notes",
    "Approval Status", "Owner", "Date Added", "Last Refreshed",
]

st.set_page_config(
    page_title="SOUP Agent — IEC 62304",
    page_icon="🩺",
    layout="wide",
)

# ============================================================
# GOOGLE SHEETS CONNECTION
# ============================================================

@st.cache_resource
def get_gsheet():
    """Connect to Google Sheets using service account credentials.
    Credentials come from Streamlit secrets (st.secrets) — never hardcoded.
    """
    try:
        scopes = [
            "https://www.googleapis.com/auth/spreadsheets",
            "https://www.googleapis.com/auth/drive",
        ]
        creds_dict = dict(st.secrets["gcp_service_account"])
        creds = Credentials.from_service_account_info(creds_dict, scopes=scopes)
        client = gspread.authorize(creds)
        sheet_url = st.secrets["sheet_url"]
        sh = client.open_by_url(sheet_url)
        return sh
    except Exception as e:
        st.error(
            f"❌ Could not connect to Google Sheet.\n\n"
            f"Make sure you've set up secrets correctly. Error: {e}"
        )
        st.stop()

def get_inventory_ws():
    return get_gsheet().worksheet(SHEET_NAME)

def get_log_ws():
    return get_gsheet().worksheet(LOG_SHEET_NAME)

def read_all_soup():
    """Read entire SOUP sheet into a DataFrame."""
    ws = get_inventory_ws()
    records = ws.get_all_records()
    if not records:
        return pd.DataFrame(columns=COLUMNS)
    return pd.DataFrame(records)

def find_row_index(name: str, version: str, ecosystem: str) -> int:
    """Return 1-indexed row number in the sheet (header is row 1).
    Returns 0 if not found."""
    df = read_all_soup()
    if df.empty:
        return 0
    mask = (
        (df["Name"].astype(str).str.lower() == name.lower()) &
        (df["Version"].astype(str) == version) &
        (df["Ecosystem"].astype(str) == ecosystem)
    )
    matches = df.index[mask].tolist()
    if matches:
        return matches[0] + 2  # +2 = +1 for 1-indexed, +1 for header row
    return 0

def upsert_soup_row(record: dict):
    """Insert or update a SOUP record in the sheet."""
    ws = get_inventory_ws()
    row_data = [record.get(col, "") for col in COLUMNS]
    
    existing_row = find_row_index(record["Name"], record["Version"], record["Ecosystem"])
    
    if existing_row > 0:
        # Update specific fields (preserve user-edited fields)
        # We'll update everything EXCEPT user-edited columns
        user_cols = {"Confirmed Safety Class", "Intended Use", "Usage Context",
                     "Functional Requirements", "Verification Notes",
                     "Approval Status", "Owner", "Date Added"}
        for i, col in enumerate(COLUMNS):
            if col not in user_cols:
                ws.update_cell(existing_row, i + 1, row_data[i])
                time.sleep(0.1)  # gentle rate-limit cushion
    else:
        ws.append_row(row_data, value_input_option="USER_ENTERED")

def update_user_fields(name: str, version: str, ecosystem: str, updates: dict):
    """Update QARA-editable fields for a row."""
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
        pass  # don't crash app if logging fails

# ============================================================
# EXTERNAL APIs — Enrichment Pipeline
# ============================================================

def fetch_depsdev(ecosystem: str, name: str, version: str) -> dict:
    url = f"https://api.deps.dev/v3/systems/{ecosystem}/packages/{name}/versions/{version}"
    try:
        r = requests.get(url, timeout=15)
        if r.status_code == 200:
            return r.json()
    except Exception:
        pass
    return {}

def fetch_depsdev_latest(ecosystem: str, name: str) -> str:
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

def fetch_osv_vulns(ecosystem: str, name: str, version: str) -> list:
    url = "https://api.osv.dev/v1/query"
    payload = {"package": {"name": name, "ecosystem": ecosystem}, "version": version}
    try:
        r = requests.post(url, json=payload, timeout=15)
        if r.status_code == 200:
            return r.json().get("vulns", [])
    except Exception:
        pass
    return []

def fetch_nvd_cvss(cve_id: str) -> float:
    url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={cve_id}"
    try:
        r = requests.get(url, timeout=15)
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

def severity_label(score: float) -> str:
    if score == 0: return "—"
    if score < 4.0: return "Low"
    if score < 7.0: return "Medium"
    if score < 9.0: return "High"
    return "Critical"

def suggest_safety_class(cve_count: int, highest_cvss: float, is_outdated: bool) -> str:
    if highest_cvss >= 7.0 or cve_count >= 3:
        return "Class B/C — HUMAN REVIEW REQUIRED (significant vulns)"
    if is_outdated and cve_count > 0:
        return "Class B — HUMAN REVIEW REQUIRED (outdated with vulns)"
    return "Class A (suggested — confirm based on usage)"

# ============================================================
# ENRICHMENT — the agent's brain
# ============================================================

def enrich_soup(ecosystem: str, name: str, version: str) -> dict:
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
            time.sleep(0.6)  # NVD rate limit
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
    
    # Format CVE list as readable text for the sheet
    cve_text = "\n".join([
        f"• {c['id']} [{c['severity']}, CVSS {c['cvss']}]: {c['summary']}"
        for c in cve_summary
    ]) or "No known vulnerabilities"
    
    anomaly_text = "\n".join([
        f"• {c['id']}: {c['summary']}" for c in cve_summary
    ]) or "None identified from public sources"
    
    return {
        "Name": name,
        "Version": version,
        "Ecosystem": ecosystem,
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
        "Suggested Safety Class": suggest_safety_class(len(cve_summary), highest_cvss, is_outdated),
        "Confirmed Safety Class": "",
        "Intended Use": "",
        "Usage Context": "",
        "Functional Requirements": "",
        "Verification Notes": "",
        "Approval Status": "Draft",
        "Owner": "",
        "Date Added": datetime.now(IST).strftime("%Y-%m-%d %H:%M IST"),
        "Last Refreshed": datetime.now(IST).strftime("%Y-%m-%d %H:%M IST"),
    }

# ============================================================
# REFRESH LOGIC
# ============================================================

def refresh_all(trigger: str = "manual"):
    df = read_all_soup()
    if df.empty:
        log_refresh(trigger, 0, 0, "Nothing to refresh")
        return 0, 0
    
    new_cves_total = 0
    for _, row in df.iterrows():
        try:
            old_cve_count = int(row.get("CVE Count", 0) or 0)
            record = enrich_soup(row["Ecosystem"], row["Name"], str(row["Version"]))
            new_cves = record["CVE Count"] - old_cve_count
            if new_cves > 0:
                new_cves_total += new_cves
            upsert_soup_row(record)
        except Exception as e:
            print(f"Refresh failed for {row.get('Name','?')}: {e}")
    
    log_refresh(trigger, len(df), new_cves_total)
    return len(df), new_cves_total

# ============================================================
# SCHEDULER
# ============================================================

@st.cache_resource
def get_scheduler():
    scheduler = BackgroundScheduler(timezone=IST)
    scheduler.add_job(
        lambda: refresh_all("scheduled_9am_IST"),
        CronTrigger(hour=9, minute=0, timezone=IST),
        id="daily_refresh",
        replace_existing=True,
    )
    scheduler.start()
    return scheduler

scheduler = get_scheduler()

# ============================================================
# UI
# ============================================================

st.title("🩺 SOUP Agent — Google Sheets Edition")
st.caption("SOUP tracking for SaMD/SiMD per IEC 62304 • Data stored in your Google Sheet")

# Sidebar
with st.sidebar:
    st.header("⚙️ Controls")
    
    if st.button("🔄 Refresh All Now", type="primary", use_container_width=True):
        with st.spinner("Refreshing all SOUP items from public databases..."):
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
    st.caption("Tip: You can edit any cell directly in the sheet.")

# Tabs
tab1, tab2, tab3, tab4 = st.tabs([
    "➕ Add SOUP Item",
    "📊 SOUP Inventory",
    "✅ QARA Review",
    "ℹ️ About & Help",
])

# -------- TAB 1: ADD --------
with tab1:
    st.subheader("Add a new SOUP item")
    st.markdown(
        "Enter the **package name** and **version**. The agent fetches metadata, "
        "license, and known vulnerabilities, then writes a row to your Google Sheet."
    )
    
    col1, col2, col3 = st.columns([2, 2, 2])
    with col1:
        ecosystem = st.selectbox("Ecosystem", list(ECOSYSTEMS.keys()),
                                  format_func=lambda x: ECOSYSTEMS[x])
    with col2:
        name = st.text_input("Package name", placeholder="e.g., lodash")
    with col3:
        version = st.text_input("Version", placeholder="e.g., 4.17.21")
    
    st.markdown("**QARA context (optional now, fill later in the sheet):**")
    col4, col5 = st.columns(2)
    with col4:
        intended_use = st.text_area("Intended use", height=80,
            placeholder="e.g., Input data validation in patient registration")
    with col5:
        usage_context = st.selectbox("Usage context", [
            "", "Production (runtime)", "Development tooling only",
            "Testing only", "Build pipeline only", "Documentation"
        ])
    owner = st.text_input("Owner", placeholder="Your name or team")
    
    if st.button("✨ Generate SOUP Record", type="primary"):
        if not name.strip() or not version.strip():
            st.error("Please enter both name and version.")
        else:
            with st.spinner(f"Fetching data for {name}@{version}..."):
                try:
                    record = enrich_soup(ecosystem, name.strip(), version.strip())
                    # Apply user inputs
                    if intended_use:
                        record["Intended Use"] = intended_use
                    if usage_context:
                        record["Usage Context"] = usage_context
                    if owner:
                        record["Owner"] = owner
                    
                    upsert_soup_row(record)
                    st.success(f"✅ SOUP record added for {name}@{version}")
                    
                    c1, c2, c3, c4 = st.columns(4)
                    c1.metric("License", record["License"])
                    c2.metric("CVEs", record["CVE Count"])
                    c3.metric("Max CVSS", f"{record['Highest CVSS']:.1f}" if record["Highest CVSS"] else "—")
                    c4.metric("Outdated", record["Outdated"])
                    
                    if record["CVE Count"] > 0:
                        st.warning(f"⚠️ {record['CVE Count']} vulnerabilities found. Review them in the Google Sheet or QARA Review tab.")
                    if record["Outdated"] == "Yes":
                        st.info(f"ℹ️ Latest version is {record['Latest Version']}")
                    
                    st.info(f"💡 Suggested safety class: **{record['Suggested Safety Class']}**")
                    st.caption("Open your Google Sheet to view, edit, or share the record.")
                except Exception as e:
                    st.error(f"Error: {e}")

# -------- TAB 2: INVENTORY --------
with tab2:
    st.subheader("Your SOUP Inventory")
    
    if st.button("🔃 Reload from sheet"):
        st.cache_data.clear()
        st.rerun()
    
    try:
        df = read_all_soup()
    except Exception as e:
        st.error(f"Could not load sheet: {e}")
        df = pd.DataFrame()
    
    if df.empty:
        st.info("No SOUP items yet. Add one in the 'Add SOUP Item' tab.")
    else:
        c1, c2, c3, c4 = st.columns(4)
        c1.metric("Total items", len(df))
        c2.metric("With CVEs", int((pd.to_numeric(df["CVE Count"], errors="coerce").fillna(0) > 0).sum()))
        c3.metric("Outdated", int((df["Outdated"] == "Yes").sum()))
        c4.metric("Approved", int((df["Approval Status"] == "Approved").sum()))
        
        st.divider()
        st.dataframe(
            df[["Name", "Version", "Ecosystem", "License", "CVE Count",
                "Highest CVSS", "Outdated", "Approval Status", "Owner", "Last Refreshed"]],
            hide_index=True,
            use_container_width=True,
        )
        st.caption("💡 To edit any field, open the Google Sheet (link in sidebar).")

# -------- TAB 3: QARA REVIEW --------
with tab3:
    st.subheader("QARA Review — Make Decisions")
    st.markdown("Use this form to record your QARA decisions. Changes save directly to the Google Sheet.")
    
    try:
        df = read_all_soup()
    except Exception:
        df = pd.DataFrame()
    
    if df.empty:
        st.info("No items to review yet.")
    else:
        labels = [f"{r['Name']}@{r['Version']} ({r['Ecosystem']})" for _, r in df.iterrows()]
        idx = st.selectbox("Select SOUP item", range(len(labels)),
                           format_func=lambda i: labels[i])
        item = df.iloc[idx]
        
        st.markdown(f"### {item['Name']} `{item['Version']}`")
        
        # Show the data
        with st.expander("📋 Auto-populated technical fields", expanded=False):
            for field in ["Publisher", "License", "Description", "Repository URL",
                          "Release Date", "Latest Version", "Outdated"]:
                st.markdown(f"**{field}:** {item.get(field, '—')}")
        
        with st.expander("🛡️ Vulnerabilities", expanded=item.get("CVE Count", 0) > 0):
            cve_count = int(item.get("CVE Count", 0) or 0)
            if cve_count == 0:
                st.success("✅ No known vulnerabilities.")
            else:
                st.warning(f"⚠️ {cve_count} CVE(s) — Highest CVSS: {item.get('Highest CVSS', '—')}")
                st.text(item.get("CVE List", ""))
        
        st.markdown("### Your QARA decisions")
        st.caption(f"Agent suggests: **{item.get('Suggested Safety Class', '—')}**")
        
        confirmed_class = st.selectbox(
            "Confirmed safety class",
            ["", "Class A", "Class B", "Class C", "Not applicable"],
            index=["", "Class A", "Class B", "Class C", "Not applicable"].index(
                item.get("Confirmed Safety Class", "")) if item.get("Confirmed Safety Class", "") in
                ["", "Class A", "Class B", "Class C", "Not applicable"] else 0,
        )
        
        intended_use = st.text_area("Intended use", value=item.get("Intended Use", ""), height=100)
        
        ctx_options = ["", "Production (runtime)", "Development tooling only",
                       "Testing only", "Build pipeline only", "Documentation"]
        usage_context = st.selectbox(
            "Usage context",
            ctx_options,
            index=ctx_options.index(item.get("Usage Context", "")) if item.get("Usage Context", "") in ctx_options else 0,
        )
        
        owner = st.text_input("Owner", value=item.get("Owner", ""))
        
        func_req = st.text_area(
            "Functional requirements (IEC 62304 §5.3.3)",
            value=item.get("Functional Requirements", ""),
            height=120,
        )
        
        verif = st.text_area(
            "Verification notes",
            value=item.get("Verification Notes", ""),
            height=100,
        )
        
        approval = st.selectbox(
            "Approval status",
            ["Draft", "Under Review", "Approved", "Deprecated"],
            index=["Draft", "Under Review", "Approved", "Deprecated"].index(
                item.get("Approval Status", "Draft")
            ) if item.get("Approval Status", "Draft") in
                ["Draft", "Under Review", "Approved", "Deprecated"] else 0,
        )
        
        col_save, col_del = st.columns([3, 1])
        with col_save:
            if st.button("💾 Save QARA decisions to sheet", type="primary"):
                updates = {
                    "Confirmed Safety Class": confirmed_class,
                    "Intended Use": intended_use,
                    "Usage Context": usage_context,
                    "Owner": owner,
                    "Functional Requirements": func_req,
                    "Verification Notes": verif,
                    "Approval Status": approval,
                }
                with st.spinner("Saving to Google Sheet..."):
                    update_user_fields(item["Name"], str(item["Version"]),
                                       item["Ecosystem"], updates)
                st.success("✅ Saved. Refresh the inventory tab to see changes.")
        
        with col_del:
            if st.button("🗑️ Delete", type="secondary"):
                delete_soup_row(item["Name"], str(item["Version"]), item["Ecosystem"])
                st.success("Deleted from sheet.")
                st.rerun()

# -------- TAB 4: ABOUT --------
with tab4:
    st.subheader("About this agent")
    st.markdown("""
    **Purpose:** Track SOUP items for SaMD/SiMD per IEC 62304 §5.3.3, §5.3.4, §7, §8.1.2.

    **Where your data lives:** In **your Google Sheet** — fully under your control.
    Open it anytime, edit any cell, share it, download as Excel.

    **Data sources used (all free, public):**
    - [deps.dev](https://deps.dev) (Google) — package metadata, licenses
    - [OSV.dev](https://osv.dev) (Google) — vulnerability database
    - [NVD](https://nvd.nist.gov) (NIST) — CVSS severity scores

    **Auto-refresh:** Daily at 9:00 AM IST when the app is running, plus on-demand via the sidebar button.

    **QARA reminders:**
    - The agent **suggests** safety class; you **confirm** it per IEC 62304's risk-based criteria.
    - Document **intended use** for every SOUP — only you can describe how it's used in your software.
    - Treat this agent itself as a tool requiring validation per IEC 62304 §5.1.4 / FDA CSA if you use its outputs in formal submissions.
    - Google Sheets revision history provides a built-in audit trail (right-click → "Show edit history" in the sheet).
    """)

st.divider()
st.caption("🩺 SOUP Agent v2.0 (Google Sheets edition) • Data: deps.dev, OSV.dev, NVD • All QARA decisions require human review.")
