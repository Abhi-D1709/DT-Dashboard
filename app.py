import streamlit as st
import pandas as pd
import requests
import numpy as np
import re
import time
import io
import random
from datetime import datetime, timedelta, date
from typing import Dict, Any, Tuple, List, Optional

# -------------------------------
# Page Config
# -------------------------------
st.set_page_config(page_title="DT Compliance Checker", layout="wide")

# -------------------------------
# HTTP / Headers
# -------------------------------
HEADERS = {
    "User-Agent": (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
        "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
    ),
    "Accept": "application/json, text/plain, */*",
    "Accept-Language": "en-US,en;q=0.9",
}

BSE_HEADERS = {
    **HEADERS,
    "Origin": "https://www.bseindia.com",
    "Referer": "https://www.bseindia.com/",
}

# -------------------------------
# Period End Dates
# -------------------------------
QUARTER_END_DATES = {"Q1": "06-30", "Q2": "09-30", "Q3": "12-31", "Q4": "03-31"}
HALF_YEAR_END_DATES = {"H1": "09-30", "H2": "03-31"}

# -------------------------------
# Regulatory Checks Dictionary (15 checks)
# -------------------------------
CHECKS_DICT = {
    "Security Cover Certificate": "Quarterly (Q1-Q3: 75 days, Q4: 90 days)",
    "Statement of value of pledged securities": "Quarterly",
    "Statement of value for Debt Service Reserve Account": "Quarterly",
    "Net worth certificate of Personal Guarantor": "Half-Yearly (Within 75 days)",
    "Financials/Value of Corporate Guarantor": "Annual (Within 75 days from FY end)",
    "Valuation Report": "Once every 3 years (Within 75 days from FY end)",
    "Title Search Report": "Once every 3 years (Within 75 days from FY end)",
    "Status Report on breach of covenants": "Quarterly (Within 90 days)",
    "NOC/No dues certificate/consent/permission": "Event Based (Within 2 working days)",
    "Breach of Minimum Security Cover": "Event Based (Within 2 working days)",
    "Default in payment of interest or redemption amount": "Event Based (Within 1 day)",
    "Failure to create charge on assets": "Event Based (Within 1 day)",
    "Disclosure of status of payment of debt securities – Defaulted": "Event Based (Within 9 days of maturity)",
    "Status of payment of defaulted debt securities": "Annual (7th working day of April)",
    "Developments that impact the status of default": "Event Based (Within 1 working day)",
}

# -------------------------------
# Helpers: safer HTTP with retries
# -------------------------------
def request_json_with_retries(
    session: requests.Session,
    url: str,
    headers: Optional[dict] = None,
    timeout: int = 15,
    max_tries: int = 4,
    base_sleep: float = 0.8,
) -> Tuple[Optional[Any], Optional[str]]:
    last_err = None
    for attempt in range(1, max_tries + 1):
        try:
            resp = session.get(url, headers=headers, timeout=timeout)
            if resp.status_code == 200:
                try:
                    return resp.json(), None
                except Exception as e:
                    last_err = f"JSON decode error: {e}"
            else:
                last_err = f"HTTP {resp.status_code}"
        except Exception as e:
            last_err = f"Request error: {e}"

        sleep_s = base_sleep * (2 ** (attempt - 1)) + random.uniform(0.1, 0.6)
        time.sleep(sleep_s)

    return None, f"Failed after retries: {last_err} | URL: {url}"


def request_text_with_retries(
    session: requests.Session,
    url: str,
    headers: Optional[dict] = None,
    timeout: int = 15,
    max_tries: int = 4,
    base_sleep: float = 0.8,
) -> Tuple[Optional[str], Optional[str]]:
    last_err = None
    for attempt in range(1, max_tries + 1):
        try:
            resp = session.get(url, headers=headers, timeout=timeout)
            if resp.status_code == 200:
                return resp.text, None
            last_err = f"HTTP {resp.status_code}"
        except Exception as e:
            last_err = f"Request error: {e}"

        sleep_s = base_sleep * (2 ** (attempt - 1)) + random.uniform(0.1, 0.6)
        time.sleep(sleep_s)

    return None, f"Failed after retries: {last_err} | URL: {url}"


# -------------------------------
# NSE session bootstrap
# -------------------------------
def make_nse_session() -> requests.Session:
    s = requests.Session()
    s.headers.update(HEADERS)
    try:
        s.get("https://www.nseindia.com", timeout=10)
    except Exception:
        pass
    return s


# -------------------------------
# Background data: Master ISIN list
# -------------------------------
@st.cache_data(ttl=86400)
def get_master_isin_list() -> Dict[str, Dict[str, Any]]:
    """
    Returns dict:
      isin -> {ISIN, BSE_Scrip, NSE_Symbol, Name}
    """
    isin_dict: Dict[str, Dict[str, Any]] = {}
    s = requests.Session()

    # 1) BSE Debentures & Bonds master
    bse_url = (
        "https://api.bseindia.com/BseIndiaAPI/api/ListofScripData/w"
        "?Group=&Scripcode=&segment=Debentures+and+Bonds&status=Active"
    )
    bse_json, bse_err = request_json_with_retries(s, bse_url, headers=BSE_HEADERS, timeout=20)
    if bse_json is None:
        st.warning(f"Could not load BSE master list: {bse_err}")
    else:
        for item in bse_json:
            isin = str(item.get("ISIN_NUMBER", "")).strip()
            if not isin:
                continue
            isin_dict[isin] = {
                "ISIN": isin,
                "BSE_Scrip": str(item.get("SCRIP_CD", "")).strip() or None,
                "Name": str(item.get("Scrip_Name", "")).strip() or "Unknown",
                "NSE_Symbol": None,
            }

    # 2) NSE DEBT.csv master
    nse_url = "https://nsearchives.nseindia.com/content/equities/DEBT.csv"
    csv_text, nse_err = request_text_with_retries(s, nse_url, headers=HEADERS, timeout=20)
    if csv_text is None:
        st.warning(f"Could not load NSE master list: {nse_err}")
    else:
        nse_cols = [
            "SYMBOL", "NAME OF COMPANY", "SERIES", "FACE VALUE", "PAID UP VALUE", "MKT LOT", "IP RATE",
            "DATE OF LISTING", "DATE OF ALLOTMENT", "REDEMPTION DATE", "REDEMPTION AMT",
            "CONVERSION DATE", "CONVERSION AMT", "INTEREST PAYMENT DT", "ISIN"
        ]
        nse_df = pd.read_csv(io.StringIO(csv_text), names=nse_cols, header=0)
        for _, row in nse_df.iterrows():
            isin = str(row.get("ISIN", "")).strip()
            if not isin or isin.upper() == "NAN":
                continue
            comp_name = str(row.get("NAME OF COMPANY", "")).strip()
            symbol = str(row.get("SYMBOL", "")).strip()
            name_to_use = comp_name if comp_name and comp_name.lower() != "nan" else (symbol or "Unknown")

            if isin in isin_dict:
                isin_dict[isin]["NSE_Symbol"] = symbol or None
                if not isin_dict[isin].get("Name") or isin_dict[isin]["Name"] == "Unknown":
                    isin_dict[isin]["Name"] = name_to_use
            else:
                isin_dict[isin] = {
                    "ISIN": isin,
                    "BSE_Scrip": None,
                    "NSE_Symbol": symbol or None,
                    "Name": name_to_use,
                }

    return isin_dict


# -------------------------------
# NSDL DT name fetch
# -------------------------------
def get_dt_name_from_nsdl(isin: str) -> str:
    url = f"https://indiabondinfo.nsdl.com/bds-service/v1/public/bdsinfo/keycontacts?isin={isin}"
    s = requests.Session()
    json_data, err = request_json_with_retries(s, url, headers=HEADERS, timeout=12, max_tries=3)
    
    if json_data:
        dt_name = json_data.get("debtTrusteeName", "")
        dt_name = " ".join(str(dt_name).split())
        return dt_name if dt_name else "Not Available"
    
    return "Not Available"


# -------------------------------
# Classification / parsing
# -------------------------------
def classify_disclosure(text: str) -> str:
    text_lower = str(text).lower()
    mapping = {
        "security cover": "Security Cover Certificate",
        "pledged": "Statement of value of pledged securities",
        "reserve account": "Statement of value for Debt Service Reserve Account",
        "dsra": "Statement of value for Debt Service Reserve Account",
        "net worth": "Net worth certificate of Personal Guarantor",
        "corporate guarantor": "Financials/Value of Corporate Guarantor",
        "valuation": "Valuation Report",
        "title search": "Title Search Report",
        "breach of covenants": "Status Report on breach of covenants",
        "noc": "NOC/No dues certificate/consent/permission",
        "no dues": "NOC/No dues certificate/consent/permission",
        "consent": "NOC/No dues certificate/consent/permission",
        "breach of minimum": "Breach of Minimum Security Cover",
        "default in payment": "Default in payment of interest or redemption amount",
        "failure to create charge": "Failure to create charge on assets",
        "defaulted debt securities": "Disclosure of status of payment of debt securities – Defaulted",
        "status of payment of defaulted": "Status of payment of defaulted debt securities",
        "developments that impact": "Developments that impact the status of default",
    }
    for key, standard_name in mapping.items():
        if key in text_lower:
            return standard_name
    return "Other / Miscellaneous"


def extract_nse_period_fy(text: str, default_year: int) -> Tuple[str, int]:
    text_upper = str(text).upper()
    period = "Unknown"
    fy_start = default_year

    fy_match = re.search(r"FY\s*(\d{4})", text_upper) or re.search(r"(20\d{2})-(20)?\d{2}", text_upper)
    if fy_match:
        fy_start = int(fy_match.group(1))

    if re.search(r"\bQ1\b|QUARTER 1|FIRST QUARTER|JUN", text_upper):
        period = "Q1"
    elif re.search(r"\bQ2\b|QUARTER 2|SECOND QUARTER|SEP", text_upper):
        period = "Q2"
    elif re.search(r"\bQ3\b|QUARTER 3|THIRD QUARTER|DEC", text_upper):
        period = "Q3"
    elif re.search(r"\bQ4\b|QUARTER 4|FOURTH QUARTER|MAR", text_upper):
        period = "Q4"
    elif re.search(r"\bH1\b|HALF YEARLY|FIRST HALF", text_upper):
        period = "H1"
    elif re.search(r"\bH2\b|SECOND HALF", text_upper):
        period = "H2"
    elif re.search(r"ANNUAL|YEARLY", text_upper):
        period = "Annual"

    return period, fy_start


def get_due_date(period: str, fin_year_start: int, check_category: str) -> str:
    if "Event Based" in CHECKS_DICT.get(check_category, ""):
        return "Manual Review"

    try:
        if check_category == "Status of payment of defaulted debt securities":
            return str(np.busday_offset(f"{fin_year_start + 1}-04-01", 6, roll="forward"))

        if check_category == "Status Report on breach of covenants" and period in QUARTER_END_DATES:
            year = fin_year_start if period in ["Q1", "Q2", "Q3"] else fin_year_start + 1
            q_end = datetime.strptime(f"{year}-{QUARTER_END_DATES[period]}", "%Y-%m-%d")
            return (q_end + timedelta(days=90)).strftime("%Y-%m-%d")

        if period in QUARTER_END_DATES:
            year = fin_year_start if period in ["Q1", "Q2", "Q3"] else fin_year_start + 1
            q_end = datetime.strptime(f"{year}-{QUARTER_END_DATES[period]}", "%Y-%m-%d")
            return (q_end + timedelta(days=90 if period == "Q4" else 75)).strftime("%Y-%m-%d")

        if period in ["H1", "H2"]:
            h_end = f"{fin_year_start}-{HALF_YEAR_END_DATES['H1']}" if period == "H1" else f"{fin_year_start + 1}-{HALF_YEAR_END_DATES['H2']}"
            return (datetime.strptime(h_end, "%Y-%m-%d") + timedelta(days=75)).strftime("%Y-%m-%d")

        if check_category in ["Financials/Value of Corporate Guarantor", "Valuation Report", "Title Search Report"]:
            return (datetime.strptime(f"{fin_year_start + 1}-03-31", "%Y-%m-%d") + timedelta(days=75)).strftime("%Y-%m-%d")

        return "Manual Review"
    except Exception:
        return "Manual Review"

def get_date_chunks(start_date: date, end_date: date, chunk_days: int = 90) -> List[Tuple[date, date]]:
    """Breaks a large date range into smaller, API-safe chunks (e.g., 90 days)."""
    chunks = []
    current_start = start_date
    while current_start <= end_date:
        current_end = current_start + timedelta(days=chunk_days - 1)
        if current_end > end_date:
            current_end = end_date
        chunks.append((current_start, current_end))
        current_start = current_end + timedelta(days=1)
    return chunks

# -------------------------------
# Main fetch: NSE + BSE (Upgraded with Date Chunking)
# -------------------------------
def fetch_disclosures_for_isin(isin_data: Dict[str, Any], from_dt: date, to_dt: date, dt_name_global: str) -> Tuple[pd.DataFrame, List[str]]:
    errors, records = [], []
    
    # Break the requested dates into safe 90-day chunks to bypass Exchange limits
    date_chunks = get_date_chunks(from_dt, to_dt, chunk_days=90)
    
    bse_scrip = isin_data.get("BSE_Scrip")
    nse_session = make_nse_session() # Re-use one session for all NSE chunks

    for chunk_start, chunk_end in date_chunks:
        # ---- 1. BSE Fetch for this chunk ----
        if bse_scrip:
            bse_from, bse_to = chunk_start.strftime("%Y%m%d"), chunk_end.strftime("%Y%m%d")
            bse_url = f"https://api.bseindia.com/BseIndiaAPI/api/DisclosureDT/w?fromdt={bse_from}&scripcode={bse_scrip}&todt={bse_to}"
            s = requests.Session()
            bse_json, bse_err = request_json_with_retries(s, bse_url, headers=BSE_HEADERS, timeout=15)
            
            if bse_json is None: 
                errors.append(f"[BSE {bse_from}-{bse_to}] {bse_err}")
            else:
                for item in bse_json.get("Table", []):
                    try: sub_date = datetime.strptime(str(item.get("InsDttm", ""))[:10], "%Y-%m-%d")
                    except Exception: continue
                    
                    fy_raw = item.get("Financial_year")
                    fy_start = int(str(fy_raw)[:4]) if fy_raw else sub_date.year
                    period, raw_text, doc_link = str(item.get("period", "")).strip(), str(item.get("Body_text", "")).strip(), str(item.get("pdf_name", "")).strip()
                    category = classify_disclosure(raw_text)
                    due_date_str = get_due_date(period, fy_start, category)
                    status = "Manual Review Required" if due_date_str == "Manual Review" else ("On Time" if sub_date <= datetime.strptime(due_date_str, "%Y-%m-%d") else "Delayed")

                    records.append({
                        "ISIN": isin_data.get("ISIN"), "Entity": isin_data.get("Name", "Unknown"), "Exchange": "BSE", "Debenture Trustee": dt_name_global,
                        "Check Category": category, "Raw Disclosure Name": raw_text, "Period/FY": f"{period} {fy_start}",
                        "Submission Date": sub_date.strftime("%Y-%m-%d"), "Calculated Due Date": due_date_str, "Compliance Status": status, "Document Link": doc_link,
                    })

        # ---- 2. NSE Fetch for this chunk ----
        nse_from, nse_to = chunk_start.strftime("%d-%m-%Y"), chunk_end.strftime("%d-%m-%Y")
        nse_url = f"https://www.nseindia.com/api/NextApi/apiClient/GetQuoteApi?functionName=getDTDisclosures&comp_name=&dt_name=&ISIN={isin_data.get('ISIN','')}&subject=&from_date={nse_from}&to_date={nse_to}"

        nse_json, nse_err = request_json_with_retries(nse_session, nse_url, headers=HEADERS, timeout=15)
        if nse_json is None: 
            errors.append(f"[NSE {nse_from}-{nse_to}] {nse_err}")
        else:
            for item in nse_json:
                try: sub_date = datetime.strptime(item.get("exchdissTime", ""), "%d-%b-%Y %H:%M:%S")
                except Exception:
                    try: sub_date = datetime.strptime(item.get("dt", ""), "%d-%b-%Y %H:%M:%S")
                    except Exception: continue

                raw_text, broad_text, doc_link = str(item.get("desc", "")).strip(), str(item.get("broadText", "")).strip(), str(item.get("attchmntName", "")).strip()
                period, fy_start = extract_nse_period_fy(f"{raw_text} {broad_text}", sub_date.year)
                category = classify_disclosure(raw_text)
                due_date_str = get_due_date(period, fy_start, category)
                status = "Manual Review Required" if due_date_str == "Manual Review" else ("On Time" if sub_date <= datetime.strptime(due_date_str, "%Y-%m-%d") else "Delayed")

                records.append({
                    "ISIN": isin_data.get("ISIN"), "Entity": isin_data.get("Name", "Unknown"), "Exchange": "NSE", "Debenture Trustee": dt_name_global,
                    "Check Category": category, "Raw Disclosure Name": raw_text, "Period/FY": f"{period} {fy_start}" if period != "Unknown" else "Check Text",
                    "Submission Date": sub_date.strftime("%Y-%m-%d"), "Calculated Due Date": due_date_str, "Compliance Status": status, "Document Link": doc_link,
                })
                
        # Give the servers a tiny breather between chunks
        time.sleep(0.1)

    # Because we stitched multiple chunks together, we might get duplicates if the exchanges have overlap.
    # This safely removes any exact duplicate rows before returning the final table.
    df = pd.DataFrame(records)
    if not df.empty:
        df = df.drop_duplicates(subset=["Exchange", "Raw Disclosure Name", "Submission Date", "Document Link"])
        
    return df, errors

# -------------------------------
# Checklist builder (per ISIN)
# -------------------------------
def build_checklist_for_isin(isin: str, isin_data: Dict[str, Any], df_disc: pd.DataFrame) -> pd.DataFrame:
    checklist_rows = []
    for check, rule in CHECKS_DICT.items():
        found = (
            df_disc[df_disc["Check Category"] == check].sort_values(by="Submission Date", ascending=False)
            if not df_disc.empty else pd.DataFrame()
        )

        if not found.empty:
            exchanges = ", ".join(found["Exchange"].dropna().unique())
            bse_dates = found[found["Exchange"] == "BSE"]["Submission Date"].tolist()
            nse_dates = found[found["Exchange"] == "NSE"]["Submission Date"].tolist()

            date_strs = []
            if bse_dates:
                date_strs.append(f"BSE: {bse_dates[0]}")
            if nse_dates:
                date_strs.append(f"NSE: {nse_dates[0]}")

            statuses = found["Compliance Status"].tolist()
            overall_status = (
                "On Time" if "On Time" in statuses
                else ("Manual Review Required" if "Manual Review Required" in statuses else "Delayed")
            )

            checklist_rows.append({
                "ISIN": isin,
                "Entity": isin_data.get("Name", "Unknown"),
                "Regulatory Provision": check,
                "Timeline Rule": rule,
                "Status": "✅ Submitted",
                "Exchange(s)": exchanges,
                "Submission Date(s)": " | ".join(date_strs),
                "Compliance": overall_status,
            })
        else:
            checklist_rows.append({
                "ISIN": isin,
                "Entity": isin_data.get("Name", "Unknown"),
                "Regulatory Provision": check,
                "Timeline Rule": rule,
                "Status": "❌ Not Found",
                "Exchange(s)": "-",
                "Submission Date(s)": "-",
                "Compliance": "No Data in Period",
            })

    return pd.DataFrame(checklist_rows)


# -------------------------------
# ISIN cleaning
# -------------------------------
ISIN_RE = re.compile(r"^[A-Z]{2}[A-Z0-9]{9}\d$")

def normalize_isin_list(values: List[str]) -> List[str]:
    cleaned = []
    for v in values:
        x = str(v).strip().upper()
        if not x or x in {"NAN", "NONE"}:
            continue
        cleaned.append(x)

    # preserve order + unique
    seen = set()
    uniq = []
    for x in cleaned:
        if x not in seen:
            seen.add(x)
            uniq.append(x)
    return uniq


def highlight_status(val: str) -> str:
    if val == "✅ Submitted":
        return "background-color: #e6ffe6"
    if val == "❌ Not Found":
        return "background-color: #ffe6e6"
    return ""

# -------------------------------
# Session State Initialization
# -------------------------------
if "single_results" not in st.session_state:
    st.session_state.single_results = None
if "bulk_results" not in st.session_state:
    st.session_state.bulk_results = None

# -------------------------------
# UI
# -------------------------------
with st.spinner("Syncing latest ISIN master lists from BSE and NSE..."):
    master_isins = get_master_isin_list()

st.title("📋 DT Submissions to SEs - Dashboard")

st.sidebar.header("Audit Parameters")
mode = st.sidebar.radio("Select Input Mode", ["Single ISIN Search", "Bulk Excel Upload"])
start_date = st.sidebar.date_input("From Date", datetime(2025, 10, 1))
end_date = st.sidebar.date_input("To Date", datetime(2025, 12, 31))

if start_date > end_date:
    st.error("From Date cannot be after To Date.")
    st.stop()

# -------------------------------
# Single ISIN
# -------------------------------
# -------------------------------
# Single ISIN
# -------------------------------
if mode == "Single ISIN Search":
    isin_options = list(master_isins.keys())
    selected_isin = st.sidebar.selectbox(
        "Search ISIN (Type to auto-complete)",
        options=[""] + isin_options,
        format_func=lambda x: f"{x} - {master_isins[x]['Name'][:40]}..." if x else "Type or select an ISIN..."
    )

    if st.sidebar.button("Run 15-Point Compliance Check") and selected_isin:
        isin_data = master_isins[selected_isin]
        with st.spinner("Querying NSDL & Exchanges..."):
            master_dt_name = get_dt_name_from_nsdl(selected_isin)
            disclosures_df, errs = fetch_disclosures_for_isin(isin_data, start_date, end_date, master_dt_name)
            checklist_df = build_checklist_for_isin(selected_isin, isin_data, disclosures_df)
            
            # Save to session state so it survives downloads
            st.session_state.single_results = {
                "isin_data": isin_data,
                "dt_name": master_dt_name,
                "disclosures_df": disclosures_df,
                "checklist_df": checklist_df,
                "errs": errs
            }
            # Clear bulk results to avoid confusion if switching modes
            st.session_state.bulk_results = None 

    # Render UI from Session State
    if st.session_state.single_results and mode == "Single ISIN Search":
        res = st.session_state.single_results
        
        st.info(
            f"**Entity:** {res['isin_data'].get('Name')} | **ISIN:** {res['isin_data'].get('ISIN')} | "
            f"**Debenture Trustee:** {res['dt_name']} | **BSE Scrip:** {res['isin_data'].get('BSE_Scrip', 'N/A')} | "
            f"**NSE Match:** {'Yes' if res['isin_data'].get('NSE_Symbol') else 'No'}"
        )

        st.subheader("📋 15-Point Regulatory Checklist")
        st.dataframe(res['checklist_df'].style.map(highlight_status, subset=["Status"]), use_container_width=True)

        if not res['disclosures_df'].empty:
            st.subheader("🔍 Raw Disclosures Found")
            st.dataframe(
                res['disclosures_df'].drop(columns=["Check Category", "ISIN", "Entity"], errors="ignore"),
                use_container_width=True,
                column_config={"Document Link": st.column_config.LinkColumn("Document Link", display_text="Open PDF")}
            )
            
            csv = res['disclosures_df'].to_csv(index=False).encode('utf-8')
            st.download_button("Download Raw Disclosures CSV", data=csv, file_name=f"{res['isin_data'].get('ISIN')}_Disclosures.csv", mime="text/csv")
        else:
            st.warning("No disclosures found for this ISIN in the selected date range.")

        if res['errs']:
            with st.expander("Debug: fetch errors (NSE/BSE/NSDL)"):
                for e in res['errs']:
                    st.write(e)

# -------------------------------
# Bulk upload (SEQUENTIAL ONLY)
# -------------------------------
# -------------------------------
# Bulk upload (SEQUENTIAL ONLY)
# -------------------------------
elif mode == "Bulk Excel Upload":
    st.sidebar.info("Upload an Excel/CSV. The app reads the **first column** as ISINs and runs sequentially.")
    uploaded_file = st.sidebar.file_uploader("Upload Excel File (.xlsx/.xls/.csv)", type=["xlsx", "xls", "csv"])

    if uploaded_file and st.sidebar.button("Run Bulk Analysis"):
        try:
            if uploaded_file.name.lower().endswith(".csv"):
                df_upload = pd.read_csv(uploaded_file)
            else:
                df_upload = pd.read_excel(uploaded_file)

            raw_isins = df_upload.iloc[:, 0].dropna().astype(str).tolist()
            unique_isins = normalize_isin_list(raw_isins)

            if len(unique_isins) == 0:
                st.error("No ISINs found in the first column.")
                st.stop()

            if len(unique_isins) > 50:
                st.warning(f"File contains {len(unique_isins)} ISINs. Processing only the first 50.")
                unique_isins = unique_isins[:50]

            st.success(f"Processing {len(unique_isins)} ISIN(s) sequentially.")

            progress_bar = st.progress(0.0)
            status_text = st.empty()

            all_disclosures = []
            all_checklists = []
            debug_rows = []

            completed = 0
            for isin in unique_isins:
                isin_data = master_isins.get(isin, {"ISIN": isin, "Name": "Unknown Entity", "BSE_Scrip": None, "NSE_Symbol": None})
                dt_name = get_dt_name_from_nsdl(isin)

                time.sleep(1.0) # polite delay

                df_disc, errs = fetch_disclosures_for_isin(isin_data, start_date, end_date, dt_name)
                df_check = build_checklist_for_isin(isin, isin_data, df_disc)

                if not df_disc.empty:
                    all_disclosures.append(df_disc)
                if not df_check.empty:
                    all_checklists.append(df_check)

                debug_rows.append({
                    "ISIN": isin, "Entity": isin_data.get("Name", "Unknown"),
                    "Errors": " | ".join(errs) if errs else "",
                    "Disclosures Found": int(len(df_disc)),
                })

                completed += 1
                progress_bar.progress(completed / len(unique_isins))
                status_text.text(f"Processed {completed}/{len(unique_isins)} ISINs...")

            progress_bar.empty()
            status_text.empty()
            
            # Aggregate Results
            final_checklists_df = pd.concat(all_checklists, ignore_index=True) if all_checklists else pd.DataFrame()
            final_bulk_df = pd.concat(all_disclosures, ignore_index=True) if all_disclosures else pd.DataFrame()
            debug_df = pd.DataFrame(debug_rows).sort_values(by="Disclosures Found", ascending=True)

            # Save to Session State
            st.session_state.bulk_results = {
                "checklists": final_checklists_df,
                "disclosures": final_bulk_df,
                "debug": debug_df,
                "count": len(unique_isins)
            }
            st.session_state.single_results = None # Clear single search state
            
        except Exception as e:
            st.error(f"Failed to process the uploaded file: {e}")

    # Render UI from Session State
    if st.session_state.bulk_results and mode == "Bulk Excel Upload":
        res = st.session_state.bulk_results
        
        st.subheader("📊 Bulk Processing Results")

        if not res['checklists'].empty:
            st.markdown("### 1) Master Compliance Checklist (Gap Analysis)")
            st.dataframe(res['checklists'].style.map(highlight_status, subset=["Status"]), use_container_width=True)

            csv_check = res['checklists'].to_csv(index=False).encode("utf-8")
            st.download_button(
                "Download Master Checklist CSV",
                data=csv_check,
                file_name=f"Bulk_Master_Checklist_{start_date}_to_{end_date}.csv",
                mime="text/csv",
            )
            st.markdown("---")

        if not res['disclosures'].empty:
            st.markdown("### 2) Raw Disclosures Found")
            st.metric("Total Actual Disclosures Found", len(res['disclosures']))

            st.dataframe(
                res['disclosures'].drop(columns=["Check Category"], errors="ignore"),
                use_container_width=True,
                column_config={"Document Link": st.column_config.LinkColumn("Document Link", display_text="Open PDF")},
            )

            csv_raw = res['disclosures'].to_csv(index=False).encode("utf-8")
            st.download_button(
                "Download Raw Disclosures CSV",
                data=csv_raw,
                file_name=f"Bulk_Raw_Disclosures_{start_date}_to_{end_date}.csv",
                mime="text/csv",
            )
        else:
            st.warning("No disclosures found for any ISIN in this date range.")

        with st.expander("Debug: per-ISIN fetch status"):
            st.dataframe(res['debug'], use_container_width=True)