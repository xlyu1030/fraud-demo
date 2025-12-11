# Create the app.py file with the integrated analysis and simulator
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
        # Create dummy data if file is missing (for robust demo)
        return pd.DataFrame()
        
    # --- Feature Engineering from User Analysis ---
    # 1. Traveler Flag
    df['is_traveling'] = df['user_country'] != df['ip_country']
    
    # 2. Tenure Logic (User found < 1000 days is risky)
    df['is_new_user'] = df['time_on_file'] < 1000
    
    # 3. Decision Tree Logic Features
    # The user's rule uses: model_score, time_on_file, failed_logins_24h
    # Ensure columns are numeric
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
# TAB 1: ANALYST REPORT (The User's PPT & Notebook Insights)
# ==============================================================================
with tab1:
    st.title("🔎 ATO Fraud Analysis & Solution Proposal")
    st.markdown("### **Executive Summary**")
    
    # Metrics from PPT
    col1, col2, col3, col4 = st.columns(4)
    col1.metric("Total Fraud Volume", "$5.0M", "5.6% of Volume")
    col2.metric("Fraud Sessions", "83,000", "11.4% Rate")
    col3.metric("Avg Fraud Ticket", "$62", "vs $126 Overall")
    col4.metric("Key Insight", "Low Value Attack", "To Bypass 2FA")
    
    st.divider()
    
    # --- INSIGHT 1: The $0 Transaction Discovery ---
    st.subheader("1. The 'Credential Stuffing' Discovery ($0 Transactions)")
    st.markdown(\"\"\"
    **Finding:** Fraudsters are using **$0 transactions** to verify credentials before attacking. 
    These attacks are highly concentrated in specific regions and OS versions, but have **0 transaction attempts**.
    \"\"\")
    
    # Filter for $0 fraud
    zero_fraud = df[(df['transaction_amount'] == 0) & (df['fraud_flag'] == 1)]
    
    c1, c2 = st.columns(2)
    with c1:
        # Replicating the 'IP Country' Chart from Notebook
        country_counts = zero_fraud['ip_country'].value_counts().head(10).reset_index()
        country_counts.columns = ['Country', 'Count']
        fig_country = px.bar(country_counts, x='Country', y='Count', 
                             title="Concentration of $0 Fraud by IP Country", color_discrete_sequence=['#FF4B4B'])
        st.plotly_chart(fig_country, use_container_width=True)
        
    with c2:
        # Replicating the 'OS Version' Chart
        os_counts = zero_fraud['os_version'].value_counts().head(10).reset_index()
        os_counts.columns = ['OS', 'Count']
        fig_os = px.bar(os_counts, x='OS', y='Count', 
                        title="Concentration of $0 Fraud by OS Version", color_discrete_sequence=['#FF4B4B'])
        st.plotly_chart(fig_os, use_container_width=True)

    st.divider()

    # --- INSIGHT 2: The New Decision Tree Rule ---
    st.subheader("2. Proposed 'Decision Tree' Logic")
    st.markdown(\"\"\"
    We trained a Decision Tree to find the optimal combination of rules. 
    The **Best Path** identified captures **95% of fraud** with minimal friction.
    \"\"\")
    
    st.info("💡 **New Rule Logic:** IF (Score > 500) AND (Tenure < 1170 days) AND (Failed Logins > 0)")
    
    # Compare Performance (Hardcoded from User's PPT for impact)
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
    # THE USER'S NEW RULE
    use_dt_rule = st.sidebar.checkbox("✅ Apply 'Amy's Decision Tree' Rule", value=True, 
                                      help="Applies: Score > 500 & Tenure < 1170 & Failed Login > 0")
    
    target_action = st.sidebar.radio("Action for New Rule:", ["Manual Review", "2FA / Step-Up", "Decline"], index=1)

    # --- STRATEGY ENGINE ---
    def run_strategy(df, decline_thresh, strict_geo, use_dt_rule, target_action):
        # 1. Default: Approve
        df['decision'] = 'Approve'
        df['reason'] = 'Clean'
        
        # 2. Baseline: Velocity (Always Bad)
        df.loc[df['high_velocity_indicator'] == 1, 'decision'] = 'Decline'
        df.loc[df['high_velocity_indicator'] == 1, 'reason'] = 'High Velocity'
        
        # 3. Baseline: Strict Geo
        if strict_geo:
            mask = df['is_traveling']
            df.loc[mask, 'decision'] = 'Decline'
            df.loc[mask, 'reason'] = 'Geo Mismatch'
            
        # 4. Baseline: Score Threshold
        mask_score = (df['decision'] == 'Approve') & (df['model_score'] > decline_thresh)
        df.loc[mask_score, 'decision'] = 'Decline'
        df.loc[mask_score, 'reason'] = 'High Model Score'
        
        # 5. AMY'S NEW RULE (Decision Tree)
        # Logic: Score > 500 AND Tenure < 1170 AND Failed Logins > 0.5
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

    # Run Simulation
    sim_df = df.copy()
    sim_df = run_strategy(sim_df, decline_thresh, strict_geo, use_dt_rule, target_action)
    
    # --- METRICS CALCULATION ---
    fraud_caught = sim_df[(sim_df['decision'].isin(['Decline', '2FA / Step-Up'])) & (sim_df['fraud_flag'] == 1)]['transaction_amount'].sum()
    total_fraud = sim_df[sim_df['fraud_flag'] == 1]['transaction_amount'].sum()
    
    # False Positives (Good customers impacted)
    fp_count = len(sim_df[(sim_df['decision'] != 'Approve') & (sim_df['fraud_flag'] == 0)])
    
    # Action Queue
    queue_counts = sim_df['decision'].value_counts()
    
    # --- DISPLAY METRICS ---
    m1, m2, m3 = st.columns(3)
    
    with m1:
        st.metric("💰 Fraud Volume Caught", f"${fraud_caught:,.0f}", 
                  f"{fraud_caught/total_fraud:.1%} of Total")
        
    with m2:
        st.metric("⚠️ False Positives (Friction)", f"{fp_count:,}", "Good Customers Impacted")
        
    with m3:
        step_up_count = queue_counts.get("2FA / Step-Up", 0)
        st.metric("📱 Sent to 2FA / Step-Up", f"{step_up_count:,}")

    # --- CHARTS ---
    c1, c2 = st.columns([2, 1])
    
    with c1:
        # Decision Distribution
        fig_dec = px.histogram(sim_df, x='decision', color='fraud_flag', 
                               title="Strategy Outcome: Where did the Fraud Go?",
                               color_discrete_map={0: 'lightgrey', 1: 'red'},
                               labels={'fraud_flag': 'Is Fraud?'})
        st.plotly_chart(fig_dec, use_container_width=True)
        
    with c2:
        # Reason Breakdown
        reason_counts = sim_df[sim_df['decision'] != 'Approve']['reason'].value_counts().reset_index()
        reason_counts.columns = ['Reason', 'Count']
        fig_reason = px.pie(reason_counts, values='Count', names='Reason', title="Why were they blocked?", hole=0.4)
        st.plotly_chart(fig_reason, use_container_width=True)

"""

with open("app.py", "w") as f:
    f.write(code)

print("app.py created successfully.")
