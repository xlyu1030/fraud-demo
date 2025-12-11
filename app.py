# Overwrite app.py with Dynamic Executive Summary Calculations
code = """
import streamlit as st
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go

# --- 1. SETUP ---
st.set_page_config(page_title="FinSecure Fraud Defense Platform", layout="wide", page_icon="🛡️")

# Custom CSS for "Manager" feel
st.markdown(\"\"\"
    <style>
    .big-font { font-size:24px !important; font-weight: bold; }
    .metric-card { background-color: #f9f9f9; padding: 15px; border-radius: 10px; border-left: 5px solid #4CAF50; }
    </style>
\"\"\", unsafe_allow_html=True)

# --- 2. DATA LOADING ---
@st.cache_data
def load_data():
    try:
        df = pd.read_csv("DS_interview.csv")
    except:
        return pd.DataFrame()
        
    # --- Feature Engineering ---
    df['is_traveling'] = df['user_country'] != df['ip_country']
    df['is_new_user'] = df['time_on_file'] < 1000
    
    cols_to_numeric = ['model_score', 'time_on_file', 'failed_logins_24h', 'transaction_amount']
    for col in cols_to_numeric:
        df[col] = pd.to_numeric(df[col], errors='coerce').fillna(0)
        
    return df

try:
    df = load_data()
    if df.empty:
        st.error("DS_interview.csv not found!")
        st.stop()
except Exception as e:
    st.error(f"Error loading data: {e}")
    st.stop()

# --- 3. TABS SETUP ---
tab1, tab2 = st.tabs(["📊 Analyst Report (Insights)", "🎛️ Manager Simulator (Live Strategy)"])

# ==============================================================================
# TAB 1: ANALYST REPORT (Insights)
# ==============================================================================
with tab1:
    st.title("🔎 ATO Fraud Analysis & Solution Proposal")
    st.markdown("### **Executive Summary**")
    
    # --- DYNAMIC CALCULATION OF METRICS ---
    total_vol = df['transaction_amount'].sum()
    fraud_vol = df[df['fraud_flag'] == 1]['transaction_amount'].sum()
    fraud_vol_rate = (fraud_vol / total_vol) * 100
    
    total_count = len(df)
    fraud_count = len(df[df['fraud_flag'] == 1])
    fraud_rate = (fraud_count / total_count) * 100
    
    avg_fraud_ticket = df[df['fraud_flag'] == 1]['transaction_amount'].mean()
    avg_overall_ticket = df['transaction_amount'].mean()
    
    # Display Dynamic Metrics
    col1, col2, col3, col4 = st.columns(4)
    col1.metric("Total Fraud Volume", f"${fraud_vol/1_000_000:.1f}M", f"{fraud_vol_rate:.1f}% of Volume")
    col2.metric("Fraud Sessions", f"{fraud_count/1000:.1f}K", f"{fraud_rate:.1f}% Rate")
    col3.metric("Avg Fraud Ticket", f"${avg_fraud_ticket:.0f}", f"vs ${avg_overall_ticket:.0f} Overall")
    col4.metric("Key Insight", "Low Value Attack", "To Bypass 2FA")
    
    st.divider()
    
    # --- INSIGHT 1: The $0 Transaction Discovery ---
    st.subheader("1. The 'Credential Stuffing' Discovery ($0 Transactions)")
    st.markdown(\"\"\"
    **Finding:** A distinct pattern emerges when comparing **$0 Fraud** (Credential Checks) vs **>$0 Fraud** (Theft).
    $0 attacks are automated and concentrated in specific high-risk vectors compared to standard payment fraud.
    \"\"\")
    
    # Prepare Data for Grouped Plot (Filter to Fraud Only)
    fraud_df = df[df['fraud_flag'] == 1].copy()
    fraud_df['Txn Type'] = fraud_df['transaction_amount'].apply(lambda x: '$0 Fraud (Bot)' if x == 0 else '>$0 Fraud (Theft)')
    
    # Row 1: Country and OS
    c1, c2 = st.columns(2)
    
    with c1:
        top_countries = fraud_df['ip_country'].value_counts().head(10).index
        country_grp = fraud_df[fraud_df['ip_country'].isin(top_countries)].groupby(['ip_country', 'Txn Type']).size().reset_index(name='Count')
        fig_country = px.bar(country_grp, x='ip_country', y='Count', color='Txn Type',
                             barmode='group', 
                             title="Top 10 Fraud Countries: $0 vs >$0",
                             color_discrete_map={'$0 Fraud (Bot)': '#FF4B4B', '>$0 Fraud (Theft)': '#1F77B4'})
        st.plotly_chart(fig_country, use_container_width=True)
        
    with c2:
        top_os = fraud_df['os_version'].value_counts().head(10).index
        os_grp = fraud_df[fraud_df['os_version'].isin(top_os)].groupby(['os_version', 'Txn Type']).size().reset_index(name='Count')
        fig_os = px.bar(os_grp, x='os_version', y='Count', color='Txn Type',
                        barmode='group', 
                        title="Top 10 OS Versions: $0 vs >$0",
                        color_discrete_map={'$0 Fraud (Bot)': '#FF4B4B', '>$0 Fraud (Theft)': '#1F77B4'})
        st.plotly_chart(fig_os, use_container_width=True)

    # Row 2: Device and Browser
    c3, c4 = st.columns(2)

    with c3:
        top_devices = fraud_df['device_model'].value_counts().head(10).index
        device_grp = fraud_df[fraud_df['device_model'].isin(top_devices)].groupby(['device_model', 'Txn Type']).size().reset_index(name='Count')
        fig_device = px.bar(device_grp, x='device_model', y='Count', color='Txn Type',
                             barmode='group', 
                             title="Top 10 Fraud Devices: $0 vs >$0",
                             color_discrete_map={'$0 Fraud (Bot)': '#FF4B4B', '>$0 Fraud (Theft)': '#1F77B4'})
        st.plotly_chart(fig_device, use_container_width=True)

    with c4:
        top_browsers = fraud_df['browser'].value_counts().head(10).index
        browser_grp = fraud_df[fraud_df['browser'].isin(top_browsers)].groupby(['browser', 'Txn Type']).size().reset_index(name='Count')
        fig_browser = px.bar(browser_grp, x='browser', y='Count', color='Txn Type',
                             barmode='group', 
                             title="Top 10 Fraud Browsers: $0 vs >$0",
                             color_discrete_map={'$0 Fraud (Bot)': '#FF4B4B', '>$0 Fraud (Theft)': '#1F77B4'})
        st.plotly_chart(fig_browser, use_container_width=True)

    st.divider()

    # --- INSIGHT 2: The New Decision Tree Rule ---
    st.subheader("2. Proposed 'Decision Tree' Logic")
    st.markdown(\"\"\"
    We trained a Decision Tree to find the optimal combination of rules. 
    The **Best Path** identified captures **95% of fraud** with minimal friction.
    \"\"\")
    
    st.info("💡 **New Rule Logic:** IF (Score > 500) AND (Tenure < 1170 days) AND (Failed Logins > 0)")
    
    perf_data = pd.DataFrame({
        "Metric": ["Fraud Capture Rate", "False Positive Rate", "Volume Covered"],
        "Current Rule": ["31%", "48%", "< 1%"],
        "New Decision Tree": ["95%", "1%", "90%"]
    })
    
    st.table(perf_data)
    
    st.markdown("---")
    st.markdown("👉 **Go to the 'Manager Simulator' tab to test this rule live.**")

# ==============================================================================
# TAB 2: MANAGER SIMULATOR (Interactive)
# ==============================================================================
with tab2:
    st.title("🎛️ Dynamic Fraud Strategy Simulator")
    
    # --- SIDEBAR CONTROLS ---
    st.sidebar.header("Strategy Controls")
    
    st.sidebar.subheader("1. Baseline Rules")
    decline_thresh = st.sidebar.slider("Auto-Decline Score Threshold", 500, 1000, 950)
    strict_geo = st.sidebar.checkbox("Strict Geo-Blocking (Travelers)", False)
    
    st.sidebar.subheader("2. New Advanced Rules")
    use_dt_rule = st.sidebar.checkbox("✅ Apply 'Amy's Decision Tree' Rule", value=True, 
                                      help="Applies: Score > 500 & Tenure < 1170 & Failed Login > 0")
    
    target_action = st.sidebar.radio("Action for New Rule:", ["Manual Review", "2FA / Step-Up", "Decline"], index=1)

    # --- STRATEGY ENGINE ---
    def run_strategy(df, decline_thresh, strict_geo, use_dt_rule, target_action):
        df['decision'] = 'Approve'
        df['reason'] = 'Clean'
        
        df.loc[df['high_velocity_indicator'] == 1, 'decision'] = 'Decline'
        df.loc[df['high_velocity_indicator'] == 1, 'reason'] = 'High Velocity'
        
        if strict_geo:
            mask = df['is_traveling']
            df.loc[mask, 'decision'] = 'Decline'
            df.loc[mask, 'reason'] = 'Geo Mismatch'
            
        mask_score = (df['decision'] == 'Approve') & (df['model_score'] > decline_thresh)
        df.loc[mask_score, 'decision'] = 'Decline'
        df.loc[mask_score, 'reason'] = 'High Model Score'
        
        if use_dt_rule:
            mask_dt = (
                (df['decision'] == 'Approve') & 
                (df['model_score'] > 500) & 
                (df['time_on_file'] < 1170) & 
                (df['failed_logins_24h'] > 0.5)
            )
            df.loc[mask_dt, 'decision'] = target_action
            df.loc[mask_dt, 'reason'] = "Amy's DT Rule"
            
        return df

    sim_df = df.copy()
    sim_df = run_strategy(sim_df, decline_thresh, strict_geo, use_dt_rule, target_action)
    
    fraud_caught = sim_df[(sim_df['decision'].isin(['Decline', '2FA / Step-Up'])) & (sim_df['fraud_flag'] == 1)]['transaction_amount'].sum()
    total_fraud = sim_df[sim_df['fraud_flag'] == 1]['transaction_amount'].sum()
    
    fp_count = len(sim_df[(sim_df['decision'] != 'Approve') & (sim_df['fraud_flag'] == 0)])
    
    queue_counts = sim_df['decision'].value_counts()
    
    m1, m2, m3 = st.columns(3)
    
    with m1:
        st.metric("💰 Fraud Volume Caught", f"${fraud_caught:,.0f}", 
                  f"{fraud_caught/total_fraud:.1%} of Total")
        
    with m2:
        st.metric("⚠️ False Positives (Friction)", f"{fp_count:,}", "Good Customers Impacted")
        
    with m3:
        step_up_count = queue_counts.get("2FA / Step-Up", 0)
        st.metric("📱 Sent to 2FA / Step-Up", f"{step_up_count:,}")

    c1, c2 = st.columns([2, 1])
    
    with c1:
        fig_dec = px.histogram(sim_df, x='decision', color='fraud_flag', 
                               title="Strategy Outcome: Where did the Fraud Go?",
                               color_discrete_map={0: 'lightgrey', 1: 'red'},
                               labels={'fraud_flag': 'Is Fraud?'})
        st.plotly_chart(fig_dec, use_container_width=True)
        
    with c2:
        reason_counts = sim_df[sim_df['decision'] != 'Approve']['reason'].value_counts().reset_index()
        reason_counts.columns = ['Reason', 'Count']
        fig_reason = px.pie(reason_counts, values='Count', names='Reason', title="Why were they blocked?", hole=0.4)
        st.plotly_chart(fig_reason, use_container_width=True)
"""

with open("app.py", "w") as f:
    f.write(code)

print("app.py updated with dynamic calculations.")
