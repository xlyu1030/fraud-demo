# Overwrite app.py with Strategy Simulator Updates
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
    
    /* Dark Tab Headers */
    .stTabs [data-baseweb="tab-list"] { gap: 24px; background-color: transparent; }
    .stTabs [data-baseweb="tab"] { 
        height: 50px; 
        white-space: pre-wrap; 
        background-color: #2E4053; 
        color: white; 
        border-radius: 4px; 
        padding: 0 16px; 
        font-weight: 600; 
    }
    .stTabs [aria-selected="true"] { 
        background-color: #17202A; 
        color: #00CC96; 
        border: 2px solid #00CC96;
    }
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
    df_zero = df[df['transaction_amount'] == 0].copy()
    if len(df_zero) == 0: return 0, 0, 0, 0.0, 0.0, 0.0, 0.0
    fraud_zero = df_zero[df_zero['fraud_flag'] == 1]
    legit_zero = df_zero[df_zero['fraud_flag'] == 0]
    caught = fraud_zero[rule_mask[df_zero.index]].shape[0]
    total_fraud = fraud_zero.shape[0]
    pct_caught = (caught / total_fraud * 100) if total_fraud > 0 else 0.0
    missing = fraud_zero[~rule_mask[df_zero.index]].shape[0]
    pct_missing = (missing / total_fraud * 100) if total_fraud > 0 else 0.0
    fp_count = legit_zero[rule_mask[df_zero.index]].shape[0]
    total_flagged = caught + fp_count
    fpr_user = (fp_count / total_flagged * 100) if total_flagged > 0 else 0.0
    tpr_user = (caught / total_flagged * 100) if total_flagged > 0 else 0.0
    return caught, missing, fp_count, pct_caught, pct_missing, fpr_user, tpr_user

def calculate_theft_metrics(df, rule_mask):
    df_theft = df[df['transaction_amount'] > 0].copy()
    if len(df_theft) == 0: return [0]*11
    
    fraud_theft = df_theft[df_theft['fraud_flag'] == 1]
    legit_theft = df_theft[df_theft['fraud_flag'] == 0]
    
    caught_df = fraud_theft[rule_mask[df_theft.index]]
    caught_count = caught_df.shape[0]
    caught_vol = caught_df['transaction_amount'].sum()
    
    total_fraud_count = fraud_theft.shape[0]
    total_fraud_vol = fraud_theft['transaction_amount'].sum()
    
    missing_df = fraud_theft[~rule_mask[df_theft.index]]
    missing_count = missing_df.shape[0]
    missing_vol = missing_df['transaction_amount'].sum()
    
    fp_df = legit_theft[rule_mask[df_theft.index]]
    fp_count = fp_df.shape[0]
    
    recall_count = (caught_count / total_fraud_count * 100) if total_fraud_count > 0 else 0.0
    recall_vol = (caught_vol / total_fraud_vol * 100) if total_fraud_vol > 0 else 0.0
    pct_missing_count = (missing_count / total_fraud_count * 100) if total_fraud_count > 0 else 0.0
    pct_missing_vol = (missing_vol / total_fraud_vol * 100) if total_fraud_vol > 0 else 0.0
    
    total_flagged = caught_count + fp_count
    precision = (caught_count / total_flagged * 100) if total_flagged > 0 else 0.0
    fpr_user = (fp_count / total_flagged * 100) if total_flagged > 0 else 0.0
    
    return [recall_count, recall_vol, pct_missing_count, pct_missing_vol, caught_count, caught_vol, missing_count, missing_vol, fp_count, precision, fpr_user]

# --- 4. TABS SETUP ---
tab1, tab2, tab3, tab4 = st.tabs(["📊 Analyst Report", "🤖 Credential Stuffing Lab", "💸 Theft Rule Lab", "🎛️ Strategy Simulator"])

# ==============================================================================
# TAB 1: ANALYST REPORT
# ==============================================================================
with tab1:
    st.title("🔎 ATO Fraud Analysis & Solution Proposal")
    st.markdown("### **Executive Summary**")
    total_vol = df['transaction_amount'].sum()
    fraud_vol = df[df['fraud_flag'] == 1]['transaction_amount'].sum()
    fraud_count = len(df[df['fraud_flag'] == 1])
    zero_fraud_count = len(df[(df['fraud_flag'] == 1) & (df['transaction_amount'] == 0)])
    zero_fraud_pct = (zero_fraud_count / fraud_count) * 100
    
    st.markdown("#### 1. Financial Impact")
    r1c1, r1c2, r1c3, r1c4 = st.columns(4)
    r1c1.metric("Total Fraud Volume", f"${fraud_vol/1_000_000:.1f}M")
    r1c2.metric("Fraud Sessions", f"{fraud_count/1000:.1f}K")
    r1c4.metric("$0 Fraud Rate", f"{zero_fraud_pct:.1f}%") 
    st.divider()
    
    st.markdown("#### 2. Credential Check Vectors ($0 Fraud)")
    st.info("See Tab 2 for detailed breakdown.")
    st.markdown("#### 3. Theft Vectors (>$0 Fraud)")
    st.info("See Tab 3 for detailed breakdown.")
    st.divider()
    
    st.subheader("2. Current Fraud Policies and Vulnerabilities")
    st.markdown("Summary of current system gaps based on audit:")
    policy_data = {
        "Current Policy": ["Fraud rule: login from new device...", "Two-factor authentication...", "Manual review..."],
        "Vulnerability / Impact": ["Low capture rate (31%).", "Covers only 15% of fraud.", "Transaction delay by hours/days."]
    }
    st.table(pd.DataFrame(policy_data))

# ==============================================================================
# TAB 2: CREDENTIAL STUFFING LAB
# ==============================================================================
with tab2:
    st.title("🤖 Credential Stuffing Rule Lab")
    
    st.subheader("1. Proposed Rules Performance")
    cond1 = (df['login_attempts_24h'] >= 4)
    cond2 = (df['login_attempts_24h'] < 4)
    cond3 = (df['model_score'] >= 800)
    cond4 = (df['failed_logins_24h'] >= 2)
    cond5 = (df['transaction_attempts'] == 0)
    cond6 = (df['time_on_file'] < 1878)
    
    rule1_mask = cond1
    rule2_mask = cond2 & cond3 & cond4 & cond5 & cond6
    
    r1_caught, r1_miss, r1_fp, r1_pct_caught, r1_pct_miss, r1_fpr, r1_tpr = calculate_cs_metrics(df, rule1_mask)
    r2_caught, r2_miss, r2_fp, r2_pct_caught, r2_pct_miss, r2_fpr, r2_tpr = calculate_cs_metrics(df, rule2_mask)
    
    st.table(pd.DataFrame({
        "Rule": ["Rule 1", "Rule 2"],
        "Precision (True CS Rate)": [f"{r1_tpr:.1f}%", f"{r2_tpr:.1f}%"],
        "% CS Caught (Recall)": [f"{r1_pct_caught:.1f}%", f"{r2_pct_caught:.1f}%"],
        "CS Caught Count": [f"{r1_caught:,}", f"{r2_caught:,}"],
        "Legit FP Count": [f"{r1_fp:,}", f"{r2_fp:,}"],
        "False Positive Rate": [f"{r1_fpr:.1f}%", f"{r2_fpr:.1f}%"]
    }))
    st.divider()
    
    # --- RULE 1 (Fixed: Removed Low Login) ---
    st.subheader("2. Rule 1 Playground")
    r1a, r1b = st.columns([1, 2])
    with r1a:
        st.info("**Ref:** Login >= 4")
        u1_c1 = st.checkbox("Login (High)", True, key="r1_c1")
        # u1_c2 Removed
        u1_c3 = st.checkbox("Score (High)", False, key="r1_c3")
        u1_c4 = st.checkbox("Fail Logins (High)", False, key="r1_c4")
        u1_c5 = st.checkbox("Txn == 0", False, key="r1_c5")
        u1_c6 = st.checkbox("Time (Low)", False, key="r1_c6")
        st.markdown("---")
        p1_login = st.slider("Login Cutoff", 0, 20, 4, key="r1s1")
    with r1b:
        mask1 = pd.Series([True]*len(df))
        if u1_c1: mask1 &= (df['login_attempts_24h'] >= p1_login)
        # ... apply others ...
        met1 = calculate_cs_metrics(df, mask1)
        st.metric("CS Caught", f"{met1[0]:,}")

    st.divider()

    # --- RULE 2 (Fixed: Removed High Login) ---
    st.subheader("3. Rule 2 Playground")
    r2a, r2b = st.columns([1, 2])
    with r2a:
        st.info("**Ref:** Login<4 & Score>=800...")
        # u2_c1 Removed
        u2_c2 = st.checkbox("Login (Low)", True, key="r2_c2")
        u2_c3 = st.checkbox("Score (High)", True, key="r2_c3")
        u2_c4 = st.checkbox("Fail Logins (High)", True, key="r2_c4")
        u2_c5 = st.checkbox("Txn == 0", True, key="r2_c5")
        u2_c6 = st.checkbox("Time (Low)", True, key="r2_c6")
        st.markdown("---")
        p2_login = st.slider("Login Cutoff", 0, 20, 4, key="r2s1")
        p2_score = st.slider("Score Cutoff", 0, 1000, 800, key="r2s2")
    with r2b:
        mask2 = pd.Series([True]*len(df))
        if u2_c2: mask2 &= (df['login_attempts_24h'] < p2_login)
        if u2_c3: mask2 &= (df['model_score'] >= p2_score)
        # ... apply others ...
        met2 = calculate_cs_metrics(df, mask2)
        st.metric("CS Caught", f"{met2[0]:,}")

# ==============================================================================
# TAB 3: THEFT RULE LAB
# ==============================================================================
with tab3:
    st.title("💸 Theft Rule Lab")
    st.markdown("**Context:** Transactions > $0.")
    
    # 1. Define Rules (Proposed Logic)
    t1_c1 = (df['model_score'] >= 500)
    t1_c2 = (df['time_on_file'] <= 1000)
    t1_c3 = (df['failed_logins_24h'] >= 1)
    t1_c4 = (df['failed_transactions'] >= 1)
    rule1_theft = t1_c1 & t1_c2 & t1_c3 & t1_c4
    
    t2_c1 = (df['model_score'] < 500)
    t2_c2 = (df['login_attempts_24h'] >= 4)
    rule2_theft = t2_c1 & t2_c2
    
    m1 = calculate_theft_metrics(df, rule1_theft)
    m2 = calculate_theft_metrics(df, rule2_theft)
    
    st.subheader("1. Proposed Theft Rules Performance")
    t_data = {
        "Rule": ["Rule 1 (High Score/Failures)", "Rule 2 (Low Score/High Login)"],
        "% Theft Caught (Recall)": [f"{m1[0]:.1f}%", f"{m2[0]:.1f}%"],
        "% Theft Vol Caught": [f"{m1[1]:.1f}%", f"{m2[1]:.1f}%"],
        "% Theft Missing": [f"{m1[2]:.1f}%", f"{m2[2]:.1f}%"],
        "% Theft Volume Missing": [f"{m1[3]:.1f}%", f"{m2[3]:.1f}%"],
        "Fraud Theft Caught": [f"{m1[4]:,}", f"{m2[4]:,}"],
        "Fraud Theft Vol Caught": [f"${m1[5]:,.0f}", f"${m2[5]:,.0f}"],
        "Fraud Theft Missing": [f"{m1[6]:,}", f"{m2[6]:,}"],
        "Fraud Theft Vol Missing": [f"${m1[7]:,.0f}", f"${m2[7]:,.0f}"],
        "Legit FP Count": [f"{m1[8]:,}", f"{m2[8]:,}"],
        "Precision (True Theft Rate)": [f"{m1[9]:.1f}%", f"{m2[9]:.1f}%"],
        "False Positive Rate": [f"{m1[10]:.1f}%", f"{m2[10]:.1f}%"]
    }
    st.dataframe(pd.DataFrame(t_data))
    
    st.divider()
    
    def show_theft_metrics(metrics):
        c1, c2, c3, c4 = st.columns(4)
        c1.metric("Fraud Caught", f"{metrics[4]:,}")
        c2.metric("Vol Caught", f"${metrics[5]:,.0f}")
        c3.metric("Fraud Missing", f"{metrics[6]:,}")
        c4.metric("Vol Missing", f"${metrics[7]:,.0f}")
        c5, c6, c7, c8 = st.columns(4)
        c5.metric("% Caught (Count)", f"{metrics[0]:.1f}%")
        c6.metric("% Caught (Vol)", f"{metrics[1]:.1f}%")
        c7.metric("Precision", f"{metrics[9]:.1f}%")
        c8.metric("FPR", f"{metrics[10]:.1f}%")

    st.subheader("2. Theft Rule 1 Playground")
    col_t1a, col_t1b = st.columns([1, 2])
    with col_t1a:
        st.info("**Ref:** Score>=500 & Time<=1000 & FailLog>=1 & FailTxn>=1")
        use_t1_c1 = st.checkbox("Score (High)", True, key="t1_c1")
        use_t1_c2 = st.checkbox("Time (Low)", True, key="t1_c2")
        use_t1_c3 = st.checkbox("Fail Log (High)", True, key="t1_c3")
        use_t1_c4 = st.checkbox("Fail Txn (High)", True, key="t1_c4")
        st.markdown("---")
        val_t1_score = st.slider("Score Cutoff", 0, 1000, 500, key="t1s_score")
        val_t1_time = st.slider("Time Cutoff", 0, 3000, 1000, key="t1s_time")
        val_t1_fail = st.slider("Fail Logins Cutoff", 0, 10, 1, key="t1s_fail")
        val_t1_ftxn = st.slider("Fail Txn Cutoff", 0, 10, 1, key="t1s_ftxn")
    
    with col_t1b:
        mask_t1 = pd.Series([True]*len(df))
        if use_t1_c1: mask_t1 &= (df['model_score'] >= val_t1_score)
        if use_t1_c2: mask_t1 &= (df['time_on_file'] <= val_t1_time)
        if use_t1_c3: mask_t1 &= (df['failed_logins_24h'] >= val_t1_fail)
        if use_t1_c4: mask_t1 &= (df['failed_transactions'] >= val_t1_ftxn)
        
        tm1 = calculate_theft_metrics(df, mask_t1)
        show_theft_metrics(tm1)
        
        df_t = df[df['transaction_amount'] > 0].copy()
        df_t['Outcome'] = 'Legit Allowed'
        df_t.loc[(df_t['fraud_flag']==1) & mask_t1[df_t.index], 'Outcome'] = 'Theft Caught'
        df_t.loc[(df_t['fraud_flag']==1) & ~mask_t1[df_t.index], 'Outcome'] = 'Theft Missed'
        df_t.loc[(df_t['fraud_flag']==0) & mask_t1[df_t.index], 'Outcome'] = 'False Positive'
        st.plotly_chart(px.pie(df_t, names='Outcome', color='Outcome', height=300, color_discrete_map={'Theft Caught':'#2ca02c', 'Theft Missed':'#d62728', 'False Positive':'#ff7f0e', 'Legit Allowed':'#1f77b4'}), use_container_width=True)

    st.divider()
    
    st.subheader("3. Theft Rule 2 Playground")
    col_t2a, col_t2b = st.columns([1, 2])
    with col_t2a:
        st.info("**Ref:** Score<500 & Login>=4")
        ut2_1 = st.checkbox("Score (Low)", True, key="t2c1")
        ut2_2 = st.checkbox("Login (High)", True, key="t2c2")
        st2_1 = st.slider("Score", 0, 1000, 500, key="t2s1")
        st2_2 = st.slider("Login", 0, 20, 4, key="t2s2")
    with c2:
        mask_t2 = pd.Series([True]*len(df))
        if ut2_1: mask_t2 &= (df['model_score'] < st2_1)
        if ut2_2: mask_t2 &= (df['login_attempts_24h'] >= st2_2)
        
        tm2 = calculate_theft_metrics(df, mask_t2)
        show_theft_metrics(tm2)
        
        df_t2 = df[df['transaction_amount'] > 0].copy()
        df_t2['Outcome'] = 'Legit Allowed'
        df_t2.loc[(df_t2['fraud_flag']==1) & mask_t2[df_t2.index], 'Outcome'] = 'Theft Caught'
        df_t2.loc[(df_t2['fraud_flag']==1) & ~mask_t2[df_t2.index], 'Outcome'] = 'Theft Missed'
        df_t2.loc[(df_t2['fraud_flag']==0) & mask_t2[df_t2.index], 'Outcome'] = 'False Positive'
        st.plotly_chart(px.pie(df_t2, names='Outcome', color='Outcome', height=300, color_discrete_map={'Theft Caught':'#2ca02c', 'Theft Missed':'#d62728', 'False Positive':'#ff7f0e', 'Legit Allowed':'#1f77b4'}), use_container_width=True)

# ==============================================================================
# TAB 4: STRATEGY SIMULATOR (RENAMED & UPDATED)
# ==============================================================================
with tab4:
    st.title("🎛️ Strategy Simulator")
    
    # --- NEW STRATEGY SECTIONS ---
    st.header("1. Credential Stuffing Strategy")
    
    col_strat1, col_strat2 = st.columns(2)
    with col_strat1:
        st.success("**Rule 1: Brute Force Attacks**")
        st.markdown("- **Action:** Email alerts for password change\n- **Action:** 2FA for next 3 logins")
    
    with col_strat2:
        st.success("**Rule 2: Complex Bots**")
        st.markdown("- **Action:** 2FA for next 3 logins")
    
    st.info("ℹ️ **Global Policy:** All detected accounts added to 'Activity Monitoring Dashboard' for 6 months (Login Location, Device, OS, Velocity).")
    
    st.divider()
    
    st.header("2. Theft Fraud Strategy")
    st.warning("🚧 **Strategy Definition in Progress** 🚧")
    st.markdown("This section will define actions for high-value theft detection (e.g., Immediate Account Freeze, Manual Review Queue).")
    
    st.divider()
    
    # --- EXISTING SIMULATOR (MOVED DOWN) ---
    st.header("3. General Portfolio Simulation")
    
    with st.expander("⚙️ **General Simulation Controls**", expanded=True):
        col_c1, col_c2, col_c3 = st.columns(3)
        with col_c1:
            decline_thresh = st.slider("Auto-Decline Score Threshold", 500, 1000, 950)
        with col_c2:
            strict_geo = st.checkbox("Strict Geo-Blocking (Travelers)", False)
            use_dt_rule = st.checkbox("✅ Apply 'Amy's Decision Tree' Rule", value=True)
        with col_c3:
            target_action = st.radio("Action for New Rule:", ["Manual Review", "2FA / Step-Up", "Decline"], index=1)

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
    # Explicitly define total_fraud here to avoid NameError
    total_fraud = sim_df[sim_df['fraud_flag'] == 1]['transaction_amount'].sum()
    fp_count = len(sim_df[(sim_df['decision'] != 'Approve') & (sim_df['fraud_flag'] == 0)])
    
    m1, m2, m3 = st.columns(3)
    if total_fraud > 0:
        m1.metric("💰 Fraud Volume Caught", f"${fraud_caught:,.0f}", f"{fraud_caught/total_fraud:.1%} of Total")
    else:
        m1.metric("💰 Fraud Volume Caught", f"${fraud_caught:,.0f}", "0% of Total")
    m2.metric("⚠️ False Positives", f"{fp_count:,}", "Good Customers Impacted")
    
    fig_dec = px.histogram(sim_df, x='decision', color='fraud_flag', 
                           title="Strategy Outcome",
                           color_discrete_map={0: 'lightgrey', 1: 'red'})
    st.plotly_chart(fig_dec, use_container_width=True)
"""

with open("app.py", "w") as f:
    f.write(code)

print("app.py updated: Strategy Simulator with CS strategies added.")
