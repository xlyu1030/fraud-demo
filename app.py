# Overwrite app.py with 3-Group Comparative Charts
code = """
import streamlit as st
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
import numpy as np

# --- 1. SETUP ---
st.set_page_config(page_title="FinSecure Fraud Defense Platform", layout="wide", page_icon="🛡️")

# Custom CSS
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
    
    cols_to_numeric = ['model_score', 'time_on_file', 'failed_logins_24h', 'transaction_amount', 
                       'login_attempts_24h', 'transaction_attempts', 'failed_transactions']
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
    
    # --- SECTION 1: FINANCIAL IMPACT METRICS ---
    total_vol = df['transaction_amount'].sum()
    fraud_vol = df[df['fraud_flag'] == 1]['transaction_amount'].sum()
    fraud_vol_rate = (fraud_vol / total_vol) * 100
    
    total_count = len(df)
    fraud_count = len(df[df['fraud_flag'] == 1])
    fraud_rate = (fraud_count / total_count) * 100
    
    avg_fraud_ticket = df[df['fraud_flag'] == 1]['transaction_amount'].mean()
    avg_overall_ticket = df['transaction_amount'].mean()
    
    # % of Fraud that is $0
    zero_fraud_count = len(df[(df['fraud_flag'] == 1) & (df['transaction_amount'] == 0)])
    zero_fraud_pct = (zero_fraud_count / fraud_count) * 100
    
    st.markdown("#### 1. Financial Impact")
    r1c1, r1c2, r1c3, r1c4 = st.columns(4)
    r1c1.metric("Total Fraud Volume", f"${fraud_vol/1_000_000:.1f}M", f"{fraud_vol_rate:.1f}% of Volume")
    r1c2.metric("Fraud Sessions", f"{fraud_count/1000:.1f}K", f"{fraud_rate:.1f}% Rate")
    r1c3.metric("Avg Fraud Ticket", f"${avg_fraud_ticket:.0f}", f"vs ${avg_overall_ticket:.0f} Overall")
    r1c4.metric("$0 Fraud Rate", f"{zero_fraud_pct:.1f}%", "of All Fraud Attempts") 
    
    st.divider()

    # --- METRIC CALCULATIONS FOR VECTORS ---
    legit_df = df[df['fraud_flag'] == 0]
    zero_fraud_df = df[(df['fraud_flag'] == 1) & (df['transaction_amount'] == 0)]
    nonzero_fraud_df = df[(df['fraud_flag'] == 1) & (df['transaction_amount'] > 0)]
    
    def get_metrics(target_df, baseline_df):
        bot = target_df['failed_logins_24h'].mean()
        cb = (target_df['is_traveling'].sum() / len(target_df)) * 100
        nd = (target_df['new_device'].sum() / len(target_df)) * 100
        vel = (target_df['high_velocity_indicator'].sum() / len(target_df)) * 100
        
        base_bot = baseline_df['failed_logins_24h'].mean()
        base_cb = (baseline_df['is_traveling'].sum() / len(baseline_df)) * 100
        base_nd = (baseline_df['new_device'].sum() / len(baseline_df)) * 100
        base_vel = (baseline_df['high_velocity_indicator'].sum() / len(baseline_df)) * 100
        return (bot, base_bot), (cb, base_cb), (nd, base_nd), (vel, base_vel)

    zero_metrics = get_metrics(zero_fraud_df, legit_df)
    nonzero_metrics = get_metrics(nonzero_fraud_df, legit_df)

    # --- SECTION 2: CREDENTIAL STUFFING VECTORS ($0 FRAUD) ---
    st.markdown("#### 2. Credential Check Vectors ($0 Fraud)")
    r2c1, r2c2, r2c3, r2c4 = st.columns(4)
    (bot, b_bot), (cb, b_cb), (nd, b_nd), (vel, b_vel) = zero_metrics
    r2c1.metric("🤖 Bot Pressure", f"{bot:.1f} fails", f"vs {b_bot:.1f} (Legit)")
    r2c2.metric("🌍 Cross-Border", f"{cb:.1f}%", f"vs {b_cb:.1f}% (Legit)")
    r2c3.metric("📱 New Device", f"{nd:.1f}%", f"vs {b_nd:.1f}% (Legit)")
    r2c4.metric("🚀 High Velocity", f"{vel:.1f}%", f"vs {b_vel:.1f}% (Legit)")

    # --- SECTION 3: THEFT VECTORS (>$0 FRAUD) ---
    st.markdown("#### 3. Theft Vectors (>$0 Fraud)")
    r3c1, r3c2, r3c3, r3c4 = st.columns(4)
    (bot, b_bot), (cb, b_cb), (nd, b_nd), (vel, b_vel) = nonzero_metrics
    r3c1.metric("🤖 Bot Pressure", f"{bot:.1f} fails", f"vs {b_bot:.1f} (Legit)")
    r3c2.metric("🌍 Cross-Border", f"{cb:.1f}%", f"vs {b_cb:.1f}% (Legit)")
    r3c3.metric("📱 New Device", f"{nd:.1f}%", f"vs {b_nd:.1f}% (Legit)")
    r3c4.metric("🚀 High Velocity", f"{vel:.1f}%", f"vs {b_vel:.1f}% (Legit)")
    
    st.divider()
    
    # --- CHARTS: 3-WAY COMPARISON ---
    st.subheader("1. Detailed Distribution Comparison")
    st.markdown(\"\"\"
    **Objective:** Compare the behavior of **Credential Checks**, **Theft**, and **Legit Users** side-by-side.
    * **Credential Check ($0):** Automated bot behavior.
    * **Theft (>$0):** Human-like or sophisticated cash-out behavior.
    * **Legit:** Normal baseline behavior.
    \"\"\")
    
    # Helper for 3-Way Comparative Charts
    def plot_3way_comparison(zero_df, nonzero_df, legit_df, feature, title, bins=None):
        # Function to process one dataframe
        def process_group(df, group_name):
            if bins:
                counts = pd.cut(df[feature], bins=bins).value_counts(normalize=True).sort_index() * 100
                counts.index = counts.index.astype(str)
            else:
                # Use top N from the WHOLE dataset to ensure consistent X-axis
                top_n = pd.concat([zero_df[feature], nonzero_df[feature], legit_df[feature]]).value_counts().head(10).index
                counts = df[df[feature].isin(top_n)][feature].value_counts(normalize=True) * 100
            
            return pd.DataFrame({
                'Feature': counts.index.tolist(),
                'Percentage': counts.values.tolist(),
                'Group': [group_name] * len(counts)
            })

        # Process all 3 groups
        df1 = process_group(zero_df, 'Credential Check')
        df2 = process_group(nonzero_df, 'Theft')
        df3 = process_group(legit_df, 'Legit')
        
        # Combine
        plot_df = pd.concat([df1, df2, df3])
        
        fig = px.bar(plot_df, x='Feature', y='Percentage', color='Group', barmode='group',
                     title=title, 
                     color_discrete_map={'Credential Check': '#FF4B4B', 'Theft': '#FFA15A', 'Legit': '#1F77B4'},
                     labels={'Percentage': '% of Group'})
        return fig

    # Row 1: Country & OS
    c1, c2 = st.columns(2)
    with c1:
        st.plotly_chart(plot_3way_comparison(zero_fraud_df, nonzero_fraud_df, legit_df, 'ip_country', "IP Country Distribution"), use_container_width=True)
    with c2:
        st.plotly_chart(plot_3way_comparison(zero_fraud_df, nonzero_fraud_df, legit_df, 'os_version', "OS Version Distribution"), use_container_width=True)

    # Row 2: Login Behavior
    c3, c4 = st.columns(2)
    with c3:
        st.plotly_chart(plot_3way_comparison(zero_fraud_df, nonzero_fraud_df, legit_df, 'login_attempts_24h', "Login Attempts (24h)"), use_container_width=True)
    with c4:
        st.plotly_chart(plot_3way_comparison(zero_fraud_df, nonzero_fraud_df, legit_df, 'failed_logins_24h', "Failed Logins (24h)"), use_container_width=True)
        
    # Row 3: Transaction Behavior
    c5, c6 = st.columns(2)
    with c5:
        st.plotly_chart(plot_3way_comparison(zero_fraud_df, nonzero_fraud_df, legit_df, 'transaction_attempts', "Transaction Attempts"), use_container_width=True)
    with c6:
        st.plotly_chart(plot_3way_comparison(zero_fraud_df, nonzero_fraud_df, legit_df, 'failed_transactions', "Failed Transactions"), use_container_width=True)

    # Row 4: Risk Indicators
    c7, c8 = st.columns(2)
    with c7:
        st.plotly_chart(plot_3way_comparison(zero_fraud_df, nonzero_fraud_df, legit_df, 'high_velocity_indicator', "High Velocity Indicator"), use_container_width=True)
    with c8:
        # Bin Model Score for readability
        bins = [0, 200, 400, 600, 800, 1000]
        st.plotly_chart(plot_3way_comparison(zero_fraud_df, nonzero_fraud_df, legit_df, 'model_score', "Model Score Distribution", bins=bins), use_container_width=True)

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

print("app.py updated with 3-group comparative charts.")
