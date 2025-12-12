# Overwrite app.py with Fixed Checkbox Logic and Cleaned Report
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
    .stTabs [data-baseweb="tab-list"] { gap: 24px; }
    .stTabs [data-baseweb="tab"] { height: 50px; white-space: pre-wrap; background-color: #f0f2f6; border-radius: 4px; padding: 0 16px; font-weight: 600; }
    .stTabs [aria-selected="true"] { background-color: #e8f5e9; color: #2e7d32; }
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
    
    # Ensure numeric types
    cols_to_numeric = ['model_score', 'time_on_file', 'failed_logins_24h', 'transaction_amount', 
                       'login_attempts_24h', 'transaction_attempts', 'failed_transactions', 
                       'new_device', 'high_velocity_indicator']
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

# --- 3. HELPER FUNCTIONS ---
def calculate_cs_metrics(df, rule_mask):
    # Filter to $0 Population (Credential Stuffing Context)
    df_zero = df[df['transaction_amount'] == 0].copy()
    
    if len(df_zero) == 0:
        return 0, 0, 0.0
        
    fraud_zero = df_zero[df_zero['fraud_flag'] == 1]
    legit_zero = df_zero[df_zero['fraud_flag'] == 0]
    
    caught = fraud_zero[rule_mask[df_zero.index]].shape[0]
    missing = fraud_zero[~rule_mask[df_zero.index]].shape[0]
    
    fp_count = legit_zero[rule_mask[df_zero.index]].shape[0]
    total_legit = legit_zero.shape[0]
    fpr = (fp_count / total_legit * 100) if total_legit > 0 else 0.0
    
    return caught, missing, fpr

# --- 4. TABS SETUP ---
tab1, tab2, tab3 = st.tabs(["📊 Analyst Report (Insights)", "🤖 Credential Stuffing Lab", "🎛️ Manager Simulator"])

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
        def process_group(df, group_name):
            if bins:
                counts = pd.cut(df[feature], bins=bins).value_counts(normalize=True).sort_index() * 100
                counts.index = counts.index.astype(str)
            else:
                top_n = pd.concat([zero_df[feature], nonzero_df[feature], legit_df[feature]]).value_counts().head(10).index
                counts = df[df[feature].isin(top_n)][feature].value_counts(normalize=True) * 100
            return pd.DataFrame({
                'Feature': counts.index.tolist(), 
                'Percentage': counts.values.tolist(), 
                'Group': [group_name] * len(counts)
            })

        plot_df = pd.concat([
            process_group(zero_df, 'Credential Check'), 
            process_group(nonzero_df, 'Theft'), 
            process_group(legit_df, 'Legit')
        ])
        
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

    # NOTE: REMOVED "Proposed Decision Tree Logic" section as requested.

# ==============================================================================
# TAB 2: CREDENTIAL STUFFING LAB (UPDATED LAYOUT)
# ==============================================================================
with tab2:
    st.title("🤖 Credential Stuffing Rule Lab")
    st.markdown(\"\"\"
    **Context:** This lab focuses exclusively on the **$0 Transaction Population**. 
    Test specific rules to detect bots checking credentials while minimizing friction for legit users.
    \"\"\")
    
    # --- PART 1: PROPOSED RULES PERFORMANCE ---
    st.subheader("1. Proposed Rules Performance")
    
    cond1 = (df['login_attempts_24h'] >= 4)
    cond2 = (df['login_attempts_24h'] < 4)
    cond3 = (df['model_score'] >= 800)
    cond4 = (df['failed_logins_24h'] >= 2)
    cond5 = (df['transaction_attempts'] == 0)
    cond6 = (df['time_on_file'] < 1878)
    
    rule1_mask = cond1
    rule2_mask = cond2 & cond3 & cond4 & cond5 & cond6
    
    r1_caught, r1_miss, r1_fpr = calculate_cs_metrics(df, rule1_mask)
    r2_caught, r2_miss, r2_fpr = calculate_cs_metrics(df, rule2_mask)
    
    res_data = {
        "Rule Name": ["Rule 1 (Brute Force)", "Rule 2 (Complex Bot)"],
        "Logic": ["Login Attempts >= 4", "Login<4 & Score>=800 & Fail>=2 & Txn==0 & Time<1878"],
        "CS Caught": [f"{r1_caught:,}", f"{r2_caught:,}"],
        "CS Missing": [f"{r1_miss:,}", f"{r2_miss:,}"],
        "False Positive Rate ($0 Legit)": [f"{r1_fpr:.2f}%", f"{r2_fpr:.2f}%"]
    }
    st.table(pd.DataFrame(res_data))
    
    st.divider()
    
    # --- PART 2: INTERACTIVE RULE BUILDER (REORDERED) ---
    st.subheader("2. Interactive Rule Builder")
    st.markdown("Enable conditions and adjust thresholds to design a **New Custom Rule**.")
    
    col_settings, col_results = st.columns([1, 2])
    
    with col_settings:
        st.markdown("**1. Select Conditions (AND Logic)**")
        # Checkboxes FIRST (and defaulted to True)
        # We use static labels to prevent state reset when sliders move
        use_c1 = st.checkbox("Login Attempts (High)", value=True)
        use_c2 = st.checkbox("Login Attempts (Low)", value=True)
        use_c3 = st.checkbox("Model Score (High)", value=True)
        use_c4 = st.checkbox("Failed Logins (High)", value=True)
        use_c5 = st.checkbox("Transaction Attempts (Exact)", value=True)
        use_c6 = st.checkbox("Time on File (Low)", value=True)
        
        st.divider()
        
        st.markdown("**2. Adjust Cutoffs**")
        # Sliders SECOND
        p_login = st.slider("Login Attempts Threshold", 0, 20, 4)
        p_score = st.slider("Model Score Threshold", 0, 1000, 800)
        p_fail = st.slider("Failed Logins Threshold", 0, 10, 2)
        p_time = st.slider("Time on File Threshold (Days)", 0, 3000, 1878)
        p_txn = st.number_input("Transaction Attempts Value", value=0, min_value=0)

    with col_results:
        custom_mask = pd.Series([True] * len(df))
        conditions_selected = []
        
        # Apply Logic based on selections and slider values
        if use_c1: 
            custom_mask &= (df['login_attempts_24h'] >= p_login)
            conditions_selected.append(f"Login >= {p_login}")
        if use_c2: 
            custom_mask &= (df['login_attempts_24h'] < p_login)
            conditions_selected.append(f"Login < {p_login}")
        if use_c3: 
            custom_mask &= (df['model_score'] >= p_score)
            conditions_selected.append(f"Score >= {p_score}")
        if use_c4: 
            custom_mask &= (df['failed_logins_24h'] >= p_fail)
            conditions_selected.append(f"Fail >= {p_fail}")
        if use_c5: 
            custom_mask &= (df['transaction_attempts'] == p_txn)
            conditions_selected.append(f"Txn == {p_txn}")
        if use_c6: 
            custom_mask &= (df['time_on_file'] < p_time)
            conditions_selected.append(f"Time < {p_time}")
            
        if not any([use_c1, use_c2, use_c3, use_c4, use_c5, use_c6]):
            custom_mask = pd.Series([False] * len(df))
            st.warning("⚠️ No conditions selected. The rule is currently inactive.")
        else:
            logic_str = " AND ".join(conditions_selected)
            st.info(f"**Current Rule Logic:** {logic_str}")

        c_caught, c_miss, c_fpr = calculate_cs_metrics(df, custom_mask)
        
        m1, m2, m3 = st.columns(3)
        m1.metric("CS Caught", f"{c_caught:,}")
        m2.metric("CS Missing", f"{c_miss:,}")
        m3.metric("False Positive Rate", f"{c_fpr:.2f}%")
        
        # Pie Chart Visualization
        df_zero = df[df['transaction_amount'] == 0].copy()
        df_zero['Outcome'] = 'Legit Allowed'
        mask_caught = (df_zero['fraud_flag'] == 1) & (custom_mask[df_zero.index])
        df_zero.loc[mask_caught, 'Outcome'] = 'Fraud Caught'
        mask_missed = (df_zero['fraud_flag'] == 1) & (~custom_mask[df_zero.index])
        df_zero.loc[mask_missed, 'Outcome'] = 'Fraud Missed'
        mask_fp = (df_zero['fraud_flag'] == 0) & (custom_mask[df_zero.index])
        df_zero.loc[mask_fp, 'Outcome'] = 'False Positive'

        counts = df_zero['Outcome'].value_counts()
        fig = px.pie(values=counts.values, names=counts.index, title="Rule Impact on $0 Transactions",
                     color=counts.index,
                     color_discrete_map={'Fraud Caught': '#2ca02c', 'Fraud Missed': '#d62728', 'False Positive': '#ff7f0e', 'Legit Allowed': '#1f77b4'})
        st.plotly_chart(fig, use_container_width=True)

# ==============================================================================
# TAB 3: MANAGER SIMULATOR (Existing)
# ==============================================================================
with tab3:
    st.title("🎛️ Dynamic Fraud Strategy Simulator")
    
    st.sidebar.header("Manager Simulator Controls")
    decline_thresh = st.sidebar.slider("Auto-Decline Score Threshold", 500, 1000, 950)
    strict_geo = st.sidebar.checkbox("Strict Geo-Blocking (Travelers)", False)
    use_dt_rule = st.sidebar.checkbox("✅ Apply 'Amy's Decision Tree' Rule", value=True)
    target_action = st.sidebar.radio("Action for New Rule:", ["Manual Review", "2FA / Step-Up", "Decline"], index=1)

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
            mask_dt = (df['decision'] == 'Approve') & (df['model_score'] > 500) & (df['time_on_file'] < 1170) & (df['failed_logins_24h'] > 0.5)
            df.loc[mask_dt, 'decision'] = target_action
            df.loc[mask_dt, 'reason'] = "Amy's DT Rule"
            
        return df

    sim_df = df.copy()
    sim_df = run_strategy(sim_df, decline_thresh, strict_geo, use_dt_rule, target_action)
    
    fraud_caught = sim_df[(sim_df['decision'].isin(['Decline', '2FA / Step-Up'])) & (sim_df['fraud_flag'] == 1)]['transaction_amount'].sum()
    total_fraud = sim_df[sim_df['fraud_flag'] == 1]['transaction_amount'].sum()
    fp_count = len(sim_df[(sim_df['decision'] != 'Approve') & (sim_df['fraud_flag'] == 0)])
    
    m1, m2, m3 = st.columns(3)
    m1.metric("💰 Fraud Volume Caught", f"${fraud_caught:,.0f}", f"{fraud_caught/total_fraud:.1%} of Total")
    m2.metric("⚠️ False Positives", f"{fp_count:,}")
    
    fig_dec = px.histogram(sim_df, x='decision', color='fraud_flag', 
                           title="Strategy Outcome",
                           color_discrete_map={0: 'lightgrey', 1: 'red'})
    st.plotly_chart(fig_dec, use_container_width=True)
"""

with open("app.py", "w") as f:
    f.write(code)

print("app.py updated with fixed checkbox state logic.")
