# Overwrite app.py with Fixed Variable Scope
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
    # Local variable definition
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
    
    # Use distinct names to avoid global scope confusion
    total_fraud_cnt = fraud_theft.shape[0]
    total_fraud_vol = fraud_theft['transaction_amount'].sum()
    
    missing_df = fraud_theft[~rule_mask[df_theft.index]]
    missing_count = missing_df.shape[0]
    missing_vol = missing_df['transaction_amount'].sum()
    
    fp_df = legit_theft[rule_mask[df_theft.index]]
    fp_count = fp_df.shape[0]
    
    recall_count = (caught_count / total_fraud_cnt * 100) if total_fraud_cnt > 0 else 0.0
    recall_vol = (caught_vol / total_fraud_vol * 100) if total_fraud_vol > 0 else 0.0
    pct_missing_count = (missing_count / total_fraud_cnt * 100) if total_fraud_cnt > 0 else 0.0
    pct_missing_vol = (missing_vol / total_fraud_vol * 100) if total_fraud_vol > 0 else 0.0
    
    total_flagged = caught_count + fp_count
    precision = (caught_count / total_flagged * 100) if total_flagged > 0 else 0.0
    fpr_user = (fp_count / total_flagged * 100) if total_flagged > 0 else 0.0
    
    return [recall_count, recall_vol, pct_missing_count, pct_missing_vol, caught_count, caught_vol, missing_count, missing_vol, fp_count, precision, fpr_user]

# --- 4. TABS ---
tab1, tab2, tab3, tab4 = st.tabs(["📊 Analyst Report", "🤖 Credential Stuffing Lab", "💸 Theft Rule Lab", "🎛️ Manager Simulator"])

# ==============================================================================
# TAB 1
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
    c1, c2, c3, c4 = st.columns(4)
    c1.metric("Total Fraud Volume", f"${fraud_vol/1_000_000:.1f}M")
    c2.metric("Fraud Sessions", f"{fraud_count/1000:.1f}K")
    c4.metric("$0 Fraud Rate", f"{zero_fraud_pct:.1f}%") 
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
# TAB 2
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
    
    r1_caught, r1_miss, r1_fp, r1_pct_caught, r1_pct_miss, r1_fpr, r1_tpr = calculate_cs_metrics(df, cond1)
    r2_caught, r2_miss, r2_fp, r2_pct_caught, r2_pct_miss, r2_fpr, r2_tpr = calculate_cs_metrics(df, cond2 & cond3 & cond4 & cond5 & cond6)
    
    st.table(pd.DataFrame({
        "Rule": ["Rule 1", "Rule 2"],
        "Precision (True CS Rate)": [f"{r1_tpr:.1f}%", f"{r2_tpr:.1f}%"],
        "Recall": [f"{r1_pct_caught:.1f}%", f"{r2_pct_caught:.1f}%"],
        "Caught": [f"{r1_caught:,}", f"{r2_caught:,}"],
        "FP Count": [f"{r1_fp:,}", f"{r2_fp:,}"],
        "FPR": [f"{r1_fpr:.1f}%", f"{r2_fpr:.1f}%"]
    }))
    st.divider()
    
    st.subheader("2. Rule 1 Playground")
    c1, c2 = st.columns([1, 2])
    with c1:
        st.info("**Ref:** Login >= 4")
        u1 = st.checkbox("Login (High)", True, key="r1_c1")
        p1 = st.slider("Login Cutoff", 0, 20, 4, key="r1_s1")
    with c2:
        mask = (df['login_attempts_24h'] >= p1) if u1 else pd.Series([False]*len(df))
        res = calculate_cs_metrics(df, mask)
        
        m1, m2, m3, m4 = st.columns(4)
        m1.metric("Precision", f"{res[6]:.1f}%")
        m2.metric("Recall", f"{res[3]:.1f}%")
        m3.metric("Caught", f"{res[0]:,}")
        m4.metric("FP", f"{res[2]:,}")
        
        df_z = df[df['transaction_amount'] == 0].copy()
        df_z['Outcome'] = 'Legit Allowed'
        df_z.loc[(df_z['fraud_flag']==1) & mask[df_z.index], 'Outcome'] = 'Fraud Caught'
        df_z.loc[(df_z['fraud_flag']==1) & ~mask[df_z.index], 'Outcome'] = 'Fraud Missed'
        df_z.loc[(df_z['fraud_flag']==0) & mask[df_z.index], 'Outcome'] = 'False Positive'
        st.plotly_chart(px.pie(df_z, names='Outcome', color='Outcome', height=300, color_discrete_map={'Fraud Caught':'#2ca02c','Fraud Missed':'#d62728','False Positive':'#ff7f0e','Legit Allowed':'#1f77b4'}), use_container_width=True)

    st.divider()
    
    st.subheader("3. Rule 2 Playground")
    c1, c2 = st.columns([1, 2])
    with c1:
        st.info("**Ref:** Login<4 & Score>=800 & Fail>=2 & Txn==0 & Time<1878")
        u2 = st.checkbox("Login (Low)", True, key="r2_c2")
        u3 = st.checkbox("Score (High)", True, key="r2_c3")
        u4 = st.checkbox("Fail Logins (High)", True, key="r2_c4")
        u5 = st.checkbox("Txn == 0", True, key="r2_c5")
        u6 = st.checkbox("Time (Low)", True, key="r2_c6")
        p_log = st.slider("Login", 0, 20, 4, key="r2_s1")
        p_sc = st.slider("Score", 0, 1000, 800, key="r2_s2")
        p_fl = st.slider("Fail", 0, 10, 2, key="r2_s3")
        p_tm = st.slider("Time", 0, 3000, 1878, key="r2_s4")
    with c2:
        mask2 = pd.Series([True]*len(df))
        if u2: mask2 &= (df['login_attempts_24h'] < p_log)
        if u3: mask2 &= (df['model_score'] >= p_sc)
        if u4: mask2 &= (df['failed_logins_24h'] >= p_fl)
        if u5: mask2 &= (df['transaction_attempts'] == 0)
        if u6: mask2 &= (df['time_on_file'] < p_tm)
        
        if not any([u2,u3,u4,u5,u6]): mask2 = pd.Series([False]*len(df))
        
        res2 = calculate_cs_metrics(df, mask2)
        m1, m2, m3, m4 = st.columns(4)
        m1.metric("Precision", f"{res2[6]:.1f}%")
        m2.metric("Recall", f"{res2[3]:.1f}%")
        m3.metric("Caught", f"{res2[0]:,}")
        m4.metric("FP", f"{res2[2]:,}")
        
        df_z2 = df[df['transaction_amount'] == 0].copy()
        df_z2['Outcome'] = 'Legit Allowed'
        df_z2.loc[(df_z2['fraud_flag']==1) & mask2[df_z2.index], 'Outcome'] = 'Fraud Caught'
        df_z2.loc[(df_z2['fraud_flag']==1) & ~mask2[df_z2.index], 'Outcome'] = 'Fraud Missed'
        df_z2.loc[(df_z2['fraud_flag']==0) & mask2[df_z2.index], 'Outcome'] = 'False Positive'
        st.plotly_chart(px.pie(df_z2, names='Outcome', color='Outcome', height=300, color_discrete_map={'Fraud Caught':'#2ca02c','Fraud Missed':'#d62728','False Positive':'#ff7f0e','Legit Allowed':'#1f77b4'}), use_container_width=True)

# ==============================================================================
# TAB 3: THEFT LAB
# ==============================================================================
with tab3:
    st.title("💸 Theft Rule Lab")
    
    t1_c1 = (df['model_score'] >= 500)
    t1_c2 = (df['time_on_file'] <= 1000)
    t1_c3 = (df['failed_logins_24h'] >= 1)
    t1_c4 = (df['failed_transactions'] >= 1)
    
    t2_c1 = (df['model_score'] < 500)
    t2_c2 = (df['login_attempts_24h'] >= 4)
    
    m1 = calculate_theft_metrics(df, t1_c1 & t1_c2 & t1_c3 & t1_c4)
    m2 = calculate_theft_metrics(df, t2_c1 & t2_c2)
    
    st.subheader("1. Proposed Rules")
    st.dataframe(pd.DataFrame({
        "Rule": ["Rule 1", "Rule 2"],
        "Recall (Count)": [f"{m1[0]:.1f}%", f"{m2[0]:.1f}%"],
        "Precision": [f"{m1[9]:.1f}%", f"{m2[9]:.1f}%"],
        "Caught Vol": [f"${m1[5]:,.0f}", f"${m2[5]:,.0f}"]
    }))
    st.divider()
    
    st.subheader("2. Theft Rule 1 Playground")
    c1, c2 = st.columns([1, 2])
    with c1:
        st.info("**Ref:** Score>=500 & Time<=1000 & FailLog>=1 & FailTxn>=1")
        ut1 = st.checkbox("Score (High)", True, key="t1c1")
        ut2 = st.checkbox("Time (Low)", True, key="t1c2")
        ut3 = st.checkbox("Fail Log (High)", True, key="t1c3")
        ut4 = st.checkbox("Fail Txn (High)", True, key="t1c4")
        st1 = st.slider("Score", 0, 1000, 500, key="ts1")
        st2 = st.slider("Time", 0, 3000, 1000, key="ts2")
        st3 = st.slider("Fail Log", 0, 10, 1, key="ts3")
        st4 = st.slider("Fail Txn", 0, 10, 1, key="ts4")
    with c2:
        mask = pd.Series([True]*len(df))
        if ut1: mask &= (df['model_score'] >= st1)
        if ut2: mask &= (df['time_on_file'] <= st2)
        if ut3: mask &= (df['failed_logins_24h'] >= st3)
        if ut4: mask &= (df['failed_transactions'] >= st4)
        
        tm = calculate_theft_metrics(df, mask)
        k1, k2, k3 = st.columns(3)
        k1.metric("Recall", f"{tm[0]:.1f}%")
        k2.metric("Precision", f"{tm[9]:.1f}%")
        k3.metric("Caught Vol", f"${tm[5]:,.0f}")
        
        df_t = df[df['transaction_amount'] > 0].copy()
        df_t['Outcome'] = 'Legit Allowed'
        df_t.loc[(df_t['fraud_flag']==1) & mask[df_t.index], 'Outcome'] = 'Theft Caught'
        df_t.loc[(df_t['fraud_flag']==1) & ~mask[df_t.index], 'Outcome'] = 'Theft Missed'
        df_t.loc[(df_t['fraud_flag']==0) & mask[df_t.index], 'Outcome'] = 'False Positive'
        st.plotly_chart(px.pie(df_t, names='Outcome', color='Outcome', height=300, color_discrete_map={'Theft Caught':'#2ca02c','Theft Missed':'#d62728','False Positive':'#ff7f0e','Legit Allowed':'#1f77b4'}), use_container_width=True)

    st.divider()
    
    st.subheader("3. Theft Rule 2 Playground")
    c1, c2 = st.columns([1, 2])
    with c1:
        st.info("**Ref:** Score<500 & Login>=4")
        ut2_1 = st.checkbox("Score (Low)", True, key="t2c1")
        ut2_2 = st.checkbox("Login (High)", True, key="t2c2")
        st2_1 = st.slider("Score", 0, 1000, 500, key="t2s1")
        st2_2 = st.slider("Login", 0, 20, 4, key="t2s2")
    with c2:
        mask2 = pd.Series([True]*len(df))
        if ut2_1: mask2 &= (df['model_score'] < st2_1)
        if ut2_2: mask2 &= (df['login_attempts_24h'] >= st2_2)
        
        tm2 = calculate_theft_metrics(df, mask2)
        k1, k2, k3 = st.columns(3)
        k1.metric("Recall", f"{tm2[0]:.1f}%")
        k2.metric("Precision", f"{tm2[9]:.1f}%")
        k3.metric("Caught Vol", f"${tm2[5]:,.0f}")
        
        df_t2 = df[df['transaction_amount'] > 0].copy()
        df_t2['Outcome'] = 'Legit Allowed'
        df_t2.loc[(df_t2['fraud_flag']==1) & mask2[df_t2.index], 'Outcome'] = 'Theft Caught'
        df_t2.loc[(df_t2['fraud_flag']==1) & ~mask2[df_t2.index], 'Outcome'] = 'Theft Missed'
        df_t2.loc[(df_t2['fraud_flag']==0) & mask2[df_t2.index], 'Outcome'] = 'False Positive'
        st.plotly_chart(px.pie(df_t2, names='Outcome', color='Outcome', height=300, color_discrete_map={'Theft Caught':'#2ca02c','Theft Missed':'#d62728','False Positive':'#ff7f0e','Legit Allowed':'#1f77b4'}), use_container_width=True)

# ==============================================================================
# TAB 4: MANAGER SIMULATOR
# ==============================================================================
with tab4:
    st.title("🎛️ Dynamic Fraud Strategy Simulator")
    
    with st.expander("⚙️ **Strategy Controls**", expanded=True):
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

print("app.py updated with fixed NameError.")
