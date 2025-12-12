# Overwrite app.py with New Theft Lab and Updated Checkboxes
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
    # Filter to $0 Population (Credential Stuffing)
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
    # Filter to >$0 Population (Theft)
    df_theft = df[df['transaction_amount'] > 0].copy()
    if len(df_theft) == 0: return [0]*11
    
    fraud_theft = df_theft[df_theft['fraud_flag'] == 1]
    legit_theft = df_theft[df_theft['fraud_flag'] == 0]
    
    # 1. Caught Counts & Volume
    caught_df = fraud_theft[rule_mask[df_theft.index]]
    caught_count = caught_df.shape[0]
    caught_vol = caught_df['transaction_amount'].sum()
    
    # 2. Total Fraud
    total_fraud_count = fraud_theft.shape[0]
    total_fraud_vol = fraud_theft['transaction_amount'].sum()
    
    # 3. Missing
    missing_df = fraud_theft[~rule_mask[df_theft.index]]
    missing_count = missing_df.shape[0]
    missing_vol = missing_df['transaction_amount'].sum()
    
    # 4. False Positives
    fp_df = legit_theft[rule_mask[df_theft.index]]
    fp_count = fp_df.shape[0]
    
    # 5. Rates
    recall_count = (caught_count / total_fraud_count * 100) if total_fraud_count > 0 else 0.0
    recall_vol = (caught_vol / total_fraud_vol * 100) if total_fraud_vol > 0 else 0.0
    
    total_flagged = caught_count + fp_count
    precision = (caught_count / total_flagged * 100) if total_flagged > 0 else 0.0
    
    # FPR (FP / Total Legit) -- or User Definition (FP / Flagged)?
    # Standard FPR is FP / Total Legit. User previously asked for FP/Flagged in Tab 2.
    # The prompt asks for "False Positive Rate" without re-definition, usually assumes standard or previous context.
    # Let's stick to the Tab 2 definition (Precision Inverse) to be consistent unless specified.
    fpr_user = (fp_count / total_flagged * 100) if total_flagged > 0 else 0.0
    
    return [recall_count, recall_vol, missing_count, missing_vol, caught_count, caught_vol, missing_count, missing_vol, fp_count, precision, fpr_user]


# --- 4. TABS SETUP ---
tab1, tab2, tab3, tab4 = st.tabs(["📊 Analyst Report", "🤖 Credential Stuffing Lab", "💸 Theft Rule Lab", "🎛️ Manager Simulator"])

# ==============================================================================
# TAB 1: ANALYST REPORT
# ==============================================================================
with tab1:
    st.title("🔎 ATO Fraud Analysis & Solution Proposal")
    st.markdown("### **Executive Summary**")
    
    total_vol = df['transaction_amount'].sum()
    fraud_vol = df[df['fraud_flag'] == 1]['transaction_amount'].sum()
    fraud_vol_rate = (fraud_vol / total_vol) * 100
    total_count = len(df)
    fraud_count = len(df[df['fraud_flag'] == 1])
    fraud_rate = (fraud_count / total_count) * 100
    avg_fraud_ticket = df[df['fraud_flag'] == 1]['transaction_amount'].mean()
    avg_overall_ticket = df['transaction_amount'].mean()
    zero_fraud_count = len(df[(df['fraud_flag'] == 1) & (df['transaction_amount'] == 0)])
    zero_fraud_pct = (zero_fraud_count / fraud_count) * 100
    
    st.markdown("#### 1. Financial Impact")
    r1c1, r1c2, r1c3, r1c4 = st.columns(4)
    r1c1.metric("Total Fraud Volume", f"${fraud_vol/1_000_000:.1f}M", f"{fraud_vol_rate:.1f}% of Volume")
    r1c2.metric("Fraud Sessions", f"{fraud_count/1000:.1f}K", f"{fraud_rate:.1f}% Rate")
    r1c3.metric("Avg Fraud Ticket", f"${avg_fraud_ticket:.0f}", f"vs ${avg_overall_ticket:.0f} Overall")
    r1c4.metric("$0 Fraud Rate", f"{zero_fraud_pct:.1f}%", "of All Fraud Attempts") 
    
    st.divider()

    # Metrics Calc
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

    st.markdown("#### 2. Credential Check Vectors ($0 Fraud)")
    r2c1, r2c2, r2c3, r2c4 = st.columns(4)
    (bot, b_bot), (cb, b_cb), (nd, b_nd), (vel, b_vel) = zero_metrics
    r2c1.metric("🤖 Bot Pressure", f"{bot:.1f} fails", f"vs {b_bot:.1f} (Legit)")
    r2c2.metric("🌍 Cross-Border", f"{cb:.1f}%", f"vs {b_cb:.1f}% (Legit)")
    r2c3.metric("📱 New Device", f"{nd:.1f}%", f"vs {b_nd:.1f}% (Legit)")
    r2c4.metric("🚀 High Velocity", f"{vel:.1f}%", f"vs {b_vel:.1f}% (Legit)")

    st.markdown("#### 3. Theft Vectors (>$0 Fraud)")
    r3c1, r3c2, r3c3, r3c4 = st.columns(4)
    (bot, b_bot), (cb, b_cb), (nd, b_nd), (vel, b_vel) = nonzero_metrics
    r3c1.metric("🤖 Bot Pressure", f"{bot:.1f} fails", f"vs {b_bot:.1f} (Legit)")
    r3c2.metric("🌍 Cross-Border", f"{cb:.1f}%", f"vs {b_cb:.1f}% (Legit)")
    r3c3.metric("📱 New Device", f"{nd:.1f}%", f"vs {b_nd:.1f}% (Legit)")
    r3c4.metric("🚀 High Velocity", f"{vel:.1f}%", f"vs {b_vel:.1f}% (Legit)")
    
    st.divider()
    
    st.subheader("1. Detailed Distribution Comparison")
    st.markdown(\"\"\"
    **Objective:** Compare the behavior of **Credential Checks**, **Theft**, and **Legit Users** side-by-side.
    \"\"\")
    
    def plot_3way_comparison(zero_df, nonzero_df, legit_df, feature, title, bins=None):
        def process_group(df, group_name):
            if bins:
                counts = pd.cut(df[feature], bins=bins).value_counts(normalize=True).sort_index() * 100
                counts.index = counts.index.astype(str)
            else:
                top_n = pd.concat([zero_df[feature], nonzero_df[feature], legit_df[feature]]).value_counts().head(10).index
                counts = df[df[feature].isin(top_n)][feature].value_counts(normalize=True) * 100
            return pd.DataFrame({'Feature': counts.index.tolist(), 'Percentage': counts.values.tolist(), 'Group': [group_name] * len(counts)})

        plot_df = pd.concat([process_group(zero_df, 'Credential Check'), process_group(nonzero_df, 'Theft'), process_group(legit_df, 'Legit')])
        fig = px.bar(plot_df, x='Feature', y='Percentage', color='Group', barmode='group',
                     title=title, color_discrete_map={'Credential Check': '#FF4B4B', 'Theft': '#FFA15A', 'Legit': '#1F77B4'},
                     labels={'Percentage': '% of Group'})
        return fig

    c1, c2 = st.columns(2)
    with c1: st.plotly_chart(plot_3way_comparison(zero_fraud_df, nonzero_fraud_df, legit_df, 'ip_country', "IP Country Distribution"), use_container_width=True)
    with c2: st.plotly_chart(plot_3way_comparison(zero_fraud_df, nonzero_fraud_df, legit_df, 'os_version', "OS Version Distribution"), use_container_width=True)

    c3, c4 = st.columns(2)
    with c3: st.plotly_chart(plot_3way_comparison(zero_fraud_df, nonzero_fraud_df, legit_df, 'login_attempts_24h', "Login Attempts (24h)"), use_container_width=True)
    with c4: st.plotly_chart(plot_3way_comparison(zero_fraud_df, nonzero_fraud_df, legit_df, 'failed_logins_24h', "Failed Logins (24h)"), use_container_width=True)
        
    c5, c6 = st.columns(2)
    with c5: st.plotly_chart(plot_3way_comparison(zero_fraud_df, nonzero_fraud_df, legit_df, 'transaction_attempts', "Transaction Attempts"), use_container_width=True)
    with c6: st.plotly_chart(plot_3way_comparison(zero_fraud_df, nonzero_fraud_df, legit_df, 'failed_transactions', "Failed Transactions"), use_container_width=True)

    c7, c8 = st.columns(2)
    with c7: st.plotly_chart(plot_3way_comparison(zero_fraud_df, nonzero_fraud_df, legit_df, 'high_velocity_indicator', "High Velocity Indicator"), use_container_width=True)
    with c8: st.plotly_chart(plot_3way_comparison(zero_fraud_df, nonzero_fraud_df, legit_df, 'model_score', "Model Score Distribution", bins=[0, 200, 400, 600, 800, 1000]), use_container_width=True)

    st.divider()
    
    st.subheader("2. Current Fraud Policies and Vulnerabilities")
    st.markdown("Summary of current system gaps based on audit:")
    policy_data = {
        "Current Policy": [
            "Fraud rule: login from new device, unusual transaction amount",
            "Two-factor authentication for high-value transactions",
            "Manual review of flagged activities by the security operations team"
        ],
        "Vulnerability / Impact": [
            "Low capture rate (31% based on simulation).",
            "Covers only 15% of fraud. (Covers 36% sessions, 85% volume).",
            "Transaction delay by hours/days, impacting user experience and transaction rate."
        ]
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
    
    res_data = {
        "Rule Name": ["Rule 1 (Brute Force)", "Rule 2 (Complex Bot)"],
        "Logic": ["Login Attempts >= 4", "Login<4 & Score>=800 & Fail>=2 & Txn==0 & Time<1878"],
        "% CS Caught (Recall)": [f"{r1_pct_caught:.1f}%", f"{r2_pct_caught:.1f}%"],
        "CS Caught Count": [f"{r1_caught:,}", f"{r2_caught:,}"],
        "CS Missing Count": [f"{r1_miss:,}", f"{r2_miss:,}"],
        "% CS Missing": [f"{r1_pct_miss:.1f}%", f"{r2_pct_miss:.1f}%"],
        "Legit FP Count": [f"{r1_fp:,}", f"{r2_fp:,}"],
        "Precision (True CS Rate)": [f"{r1_tpr:.1f}%", f"{r2_tpr:.1f}%"],
        "False Positive Rate": [f"{r1_fpr:.2f}%", f"{r2_fpr:.2f}%"]
    }
    st.table(pd.DataFrame(res_data))
    
    st.divider()
    
    # --- RULE 1 BUILDER ---
    st.subheader("2. Rule 1 Playground (Brute Force Logic)")
    r1_sets, r1_res = st.columns([1, 2])
    with r1_sets:
        st.info("**Suggested Reference:** Login Attempts >= 4")
        st.markdown("**1. Select Conditions**")
        u1_c1 = st.checkbox("Login Attempts (High)", value=True, key="r1_c1")
        # Removed exclusive condition
        u1_c3 = st.checkbox("Model Score (High)", value=False, key="r1_c3")
        u1_c4 = st.checkbox("Failed Logins (High)", value=False, key="r1_c4")
        u1_c5 = st.checkbox("Transaction Attempts (Exact)", value=False, key="r1_c5")
        u1_c6 = st.checkbox("Time on File (Low)", value=False, key="r1_c6")
        st.divider()
        st.markdown("**2. Adjust Cutoffs**")
        p1_login = st.slider("Login Cutoff", 0, 20, 4, key="r1_sl_login")
        p1_score = st.slider("Score Cutoff", 0, 1000, 800, key="r1_sl_score")
        p1_fail = st.slider("Fail Cutoff", 0, 10, 2, key="r1_sl_fail")
        p1_time = st.slider("Time Cutoff", 0, 3000, 1878, key="r1_sl_time")
        p1_txn = st.number_input("Txn Attempts", 0, key="r1_ni_txn")

    with r1_res:
        mask1 = pd.Series([True] * len(df))
        conds1 = []
        if u1_c1: mask1 &= (df['login_attempts_24h'] >= p1_login); conds1.append(f"Login>={p1_login}")
        # u1_c2 removed
        if u1_c3: mask1 &= (df['model_score'] >= p1_score); conds1.append(f"Score>={p1_score}")
        if u1_c4: mask1 &= (df['failed_logins_24h'] >= p1_fail); conds1.append(f"Fail>={p1_fail}")
        if u1_c5: mask1 &= (df['transaction_attempts'] == p1_txn); conds1.append(f"Txn=={p1_txn}")
        if u1_c6: mask1 &= (df['time_on_file'] < p1_time); conds1.append(f"Time<{p1_time}")
        
        if not any([u1_c1, u1_c3, u1_c4, u1_c5, u1_c6]): mask1 = pd.Series([False]*len(df))
        else: st.info(f"**Logic:** {' AND '.join(conds1)}")
            
        c1, m1, fp1, pc1, pm1, fpr1, tpr1 = calculate_cs_metrics(df, mask1)
        
        st.markdown("**Performance Metrics**")
        m_a, m_b, m_c, m_d = st.columns(4)
        m_a.metric("Precision (True CS Rate)", f"{tpr1:.1f}%")
        m_b.metric("% CS Caught (Recall)", f"{pc1:.1f}%")
        m_c.metric("Caught Count", f"{c1:,}")
        m_d.metric("Missing Count", f"{m1:,}")
        
        m_e, m_f = st.columns(2)
        m_e.metric("Legit False Positives", f"{fp1:,}")
        m_f.metric("False Positive Rate", f"{fpr1:.2f}%")
        
        df_z = df[df['transaction_amount'] == 0].copy()
        df_z['Outcome'] = 'Legit Allowed'
        df_z.loc[(df_z['fraud_flag']==1) & mask1[df_z.index], 'Outcome'] = 'Fraud Caught'
        df_z.loc[(df_z['fraud_flag']==1) & ~mask1[df_z.index], 'Outcome'] = 'Fraud Missed'
        df_z.loc[(df_z['fraud_flag']==0) & mask1[df_z.index], 'Outcome'] = 'False Positive'
        counts = df_z['Outcome'].value_counts()
        fig = px.pie(values=counts.values, names=counts.index, height=300, color=counts.index, color_discrete_map={'Fraud Caught':'#2ca02c','Fraud Missed':'#d62728','False Positive':'#ff7f0e','Legit Allowed':'#1f77b4'})
        st.plotly_chart(fig, use_container_width=True)

    st.divider()

    # --- RULE 2 BUILDER ---
    st.subheader("3. Rule 2 Playground (Complex Bot Logic)")
    r2_sets, r2_res = st.columns([1, 2])
    with r2_sets:
        st.info("**Suggested Reference:** Login<4 & Score>=800 & Fail>=2 & Txn==0 & Time<1878")
        st.markdown("**1. Select Conditions**")
        # Removed exclusive condition
        u2_c2 = st.checkbox("Login Attempts (Low)", value=True, key="r2_c2")
        u2_c3 = st.checkbox("Model Score (High)", value=True, key="r2_c3")
        u2_c4 = st.checkbox("Failed Logins (High)", value=True, key="r2_c4")
        u2_c5 = st.checkbox("Transaction Attempts (Exact)", value=True, key="r2_c5")
        u2_c6 = st.checkbox("Time on File (Low)", value=True, key="r2_c6")
        st.divider()
        st.markdown("**2. Adjust Cutoffs**")
        p2_login = st.slider("Login Cutoff", 0, 20, 4, key="r2_sl_login")
        p2_score = st.slider("Score Cutoff", 0, 1000, 800, key="r2_sl_score")
        p2_fail = st.slider("Fail Cutoff", 0, 10, 2, key="r2_sl_fail")
        p2_time = st.slider("Time Cutoff", 0, 3000, 1878, key="r2_sl_time")
        p2_txn = st.number_input("Txn Attempts", 0, key="r2_ni_txn")

    with r2_res:
        mask2 = pd.Series([True] * len(df))
        conds2 = []
        # u2_c1 removed
        if u2_c2: mask2 &= (df['login_attempts_24h'] < p2_login); conds2.append(f"Login<{p2_login}")
        if u2_c3: mask2 &= (df['model_score'] >= p2_score); conds2.append(f"Score>={p2_score}")
        if u2_c4: mask2 &= (df['failed_logins_24h'] >= p2_fail); conds2.append(f"Fail>={p2_fail}")
        if u2_c5: mask2 &= (df['transaction_attempts'] == p2_txn); conds2.append(f"Txn=={p2_txn}")
        if u2_c6: mask2 &= (df['time_on_file'] < p2_time); conds2.append(f"Time<{p2_time}")
        
        if not any([u2_c2, u2_c3, u2_c4, u2_c5, u2_c6]): mask2 = pd.Series([False]*len(df))
        else: st.info(f"**Logic:** {' AND '.join(conds2)}")
            
        c2_c, m2_c, fp2, pc2, pm2, fpr2, tpr2 = calculate_cs_metrics(df, mask2)
        
        st.markdown("**Performance Metrics**")
        n_a, n_b, n_c, n_d = st.columns(4)
        n_a.metric("Precision (True CS Rate)", f"{tpr2:.1f}%")
        n_b.metric("% CS Caught (Recall)", f"{pc2:.1f}%")
        n_c.metric("Caught Count", f"{c2_c:,}")
        n_d.metric("Missing Count", f"{m2_c:,}")
        
        n_e, n_f = st.columns(2)
        n_e.metric("Legit False Positives", f"{fp2:,}")
        n_f.metric("False Positive Rate", f"{fpr2:.2f}%")
        
        df_z2 = df[df['transaction_amount'] == 0].copy()
        df_z2['Outcome'] = 'Legit Allowed'
        df_z2.loc[(df_z2['fraud_flag']==1) & mask2[df_z2.index], 'Outcome'] = 'Fraud Caught'
        df_z2.loc[(df_z2['fraud_flag']==1) & ~mask2[df_z2.index], 'Outcome'] = 'Fraud Missed'
        df_z2.loc[(df_z2['fraud_flag']==0) & mask2[df_z2.index], 'Outcome'] = 'False Positive'
        counts2 = df_z2['Outcome'].value_counts()
        fig2 = px.pie(values=counts2.values, names=counts2.index, height=300, color=counts2.index, color_discrete_map={'Fraud Caught':'#2ca02c','Fraud Missed':'#d62728','False Positive':'#ff7f0e','Legit Allowed':'#1f77b4'})
        st.plotly_chart(fig2, use_container_width=True)

# ==============================================================================
# TAB 3: THEFT RULE LAB (NEW)
# ==============================================================================
with tab3:
    st.title("💸 Theft Rule Lab")
    st.markdown("**Context:** Focusing on transactions where **Amount > $0**.")
    
    # Define Conditions
    # Rule 1: Score>=500, Time<=1000, FailLog<1, FailTxn<1
    t1_c1 = (df['model_score'] >= 500)
    t1_c2 = (df['time_on_file'] <= 1000)
    t1_c3 = (df['failed_logins_24h'] < 1)
    t1_c4 = (df['failed_transactions'] < 1)
    rule1_theft = t1_c1 & t1_c2 & t1_c3 & t1_c4
    
    # Rule 2: Score<500, Login>=4
    t2_c1 = (df['model_score'] < 500) # ~Theft_condition1
    t2_c2 = (df['login_attempts_24h'] >= 4) # Theft_condition5
    rule2_theft = t2_c1 & t2_c2
    
    # Calculate Metrics
    m1 = calculate_theft_metrics(df, rule1_theft)
    m2 = calculate_theft_metrics(df, rule2_theft)
    
    # Display Table
    st.subheader("1. Proposed Theft Rules Performance")
    theft_data = {
        "Rule": ["Rule 1 (High Score/New)", "Rule 2 (Low Score/High Login)"],
        "% Theft Caught (Recall)": [f"{m1[0]:.1f}%", f"{m2[0]:.1f}%"],
        "% Theft Vol Caught": [f"{m1[1]:.1f}%", f"{m2[1]:.1f}%"],
        "% Theft Missing": [f"{(m1[2]/max(1,m1[2]+m1[4])*100):.1f}%", f"{(m2[2]/max(1,m2[2]+m2[4])*100):.1f}%"], # Approx calc from counts
        "Caught Count": [f"{m1[4]:,}", f"{m2[4]:,}"],
        "Caught Volume": [f"${m1[5]:,.0f}", f"${m2[5]:,.0f}"],
        "Missing Count": [f"{m1[6]:,}", f"{m2[6]:,}"],
        "Missing Volume": [f"${m1[7]:,.0f}", f"${m2[7]:,.0f}"],
        "Legit FP Count": [f"{m1[8]:,}", f"{m2[8]:,}"],
        "Precision (True Theft Rate)": [f"{m1[9]:.1f}%", f"{m2[9]:.1f}%"],
        "False Positive Rate": [f"{m1[10]:.1f}%", f"{m2[10]:.1f}%"]
    }
    st.table(pd.DataFrame(theft_data))
    
    st.divider()
    
    # --- RULE 1 PLAYGROUND ---
    st.subheader("2. Theft Rule 1 Playground")
    col_t1a, col_t1b = st.columns([1, 2])
    with col_t1a:
        st.info("**Ref:** Score>=500 & Time<=1000 & FailLog<1 & FailTxn<1")
        use_t1_c1 = st.checkbox("Score (High)", True, key="t1_c1")
        use_t1_c2 = st.checkbox("Time (Low)", True, key="t1_c2")
        use_t1_c3 = st.checkbox("Fail Logins (Low)", True, key="t1_c3")
        use_t1_c4 = st.checkbox("Fail Txn (Low)", True, key="t1_c4")
        st.markdown("---")
        val_t1_score = st.slider("Score Cutoff", 0, 1000, 500, key="t1s_score")
        val_t1_time = st.slider("Time Cutoff", 0, 3000, 1000, key="t1s_time")
        val_t1_fail = st.slider("Fail Logins Cutoff", 0, 10, 1, key="t1s_fail")
        val_t1_ftxn = st.slider("Fail Txn Cutoff", 0, 10, 1, key="t1s_ftxn")
        
    with col_t1b:
        mask_t1 = pd.Series([True]*len(df))
        if use_t1_c1: mask_t1 &= (df['model_score'] >= val_t1_score)
        if use_t1_c2: mask_t1 &= (df['time_on_file'] <= val_t1_time)
        if use_t1_c3: mask_t1 &= (df['failed_logins_24h'] < val_t1_fail)
        if use_t1_c4: mask_t1 &= (df['failed_transactions'] < val_t1_ftxn)
        
        tm1 = calculate_theft_metrics(df, mask_t1)
        
        c1, c2, c3 = st.columns(3)
        c1.metric("% Caught (Count)", f"{tm1[0]:.1f}%")
        c2.metric("Caught Volume", f"${tm1[5]:,.0f}")
        c3.metric("Precision", f"{tm1[9]:.1f}%")
        
        # Pie Chart
        df_t = df[df['transaction_amount'] > 0].copy()
        df_t['Outcome'] = 'Legit Allowed'
        df_t.loc[(df_t['fraud_flag']==1) & mask_t1[df_t.index], 'Outcome'] = 'Theft Caught'
        df_t.loc[(df_t['fraud_flag']==1) & ~mask_t1[df_t.index], 'Outcome'] = 'Theft Missed'
        df_t.loc[(df_t['fraud_flag']==0) & mask_t1[df_t.index], 'Outcome'] = 'False Positive'
        
        fig_t1 = px.pie(df_t, names='Outcome', title="Rule 1 Impact", color='Outcome', 
                        color_discrete_map={'Theft Caught':'#2ca02c', 'Theft Missed':'#d62728', 'False Positive':'#ff7f0e', 'Legit Allowed':'#1f77b4'})
        st.plotly_chart(fig_t1, use_container_width=True)

    st.divider()
    
    # --- RULE 2 PLAYGROUND ---
    st.subheader("3. Theft Rule 2 Playground")
    col_t2a, col_t2b = st.columns([1, 2])
    with col_t2a:
        st.info("**Ref:** Score<500 & Login>=4")
        use_t2_c1 = st.checkbox("Score (Low)", True, key="t2_c1")
        use_t2_c2 = st.checkbox("Login (High)", True, key="t2_c2")
        st.markdown("---")
        val_t2_score = st.slider("Score Cutoff", 0, 1000, 500, key="t2s_score")
        val_t2_login = st.slider("Login Cutoff", 0, 20, 4, key="t2s_login")
        
    with col_t2b:
        mask_t2 = pd.Series([True]*len(df))
        if use_t2_c1: mask_t2 &= (df['model_score'] < val_t2_score)
        if use_t2_c2: mask_t2 &= (df['login_attempts_24h'] >= val_t2_login)
        
        tm2 = calculate_theft_metrics(df, mask_t2)
        
        c1, c2, c3 = st.columns(3)
        c1.metric("% Caught (Count)", f"{tm2[0]:.1f}%")
        c2.metric("Caught Volume", f"${tm2[5]:,.0f}")
        c3.metric("Precision", f"{tm2[9]:.1f}%")
        
        # Pie Chart
        df_t2 = df[df['transaction_amount'] > 0].copy()
        df_t2['Outcome'] = 'Legit Allowed'
        df_t2.loc[(df_t2['fraud_flag']==1) & mask_t2[df_t2.index], 'Outcome'] = 'Theft Caught'
        df_t2.loc[(df_t2['fraud_flag']==1) & ~mask_t2[df_t2.index], 'Outcome'] = 'Theft Missed'
        df_t2.loc[(df_t2['fraud_flag']==0) & mask_t2[df_t2.index], 'Outcome'] = 'False Positive'
        
        fig_t2 = px.pie(df_t2, names='Outcome', title="Rule 2 Impact", color='Outcome', 
                        color_discrete_map={'Theft Caught':'#2ca02c', 'Theft Missed':'#d62728', 'False Positive':'#ff7f0e', 'Legit Allowed':'#1f77b4'})
        st.plotly_chart(fig_t2, use_container_width=True)

# ==============================================================================
# TAB 4: MANAGER SIMULATOR (MOVED)
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
    total_fraud = sim_df[sim_df['fraud_flag'] == 1]['transaction_amount'].sum()
    fp_count = len(sim_df[(sim_df['decision'] != 'Approve') & (sim_df['fraud_flag'] == 0)])
    
    m1, m2, m3 = st.columns(3)
    m1.metric("💰 Fraud Volume Caught", f"${fraud_caught:,.0f}", f"{fraud_caught/total_fraud:.1%} of Total")
    m2.metric("⚠️ False Positives", f"{fp_count:,}", "Good Customers Impacted")
    
    fig_dec = px.histogram(sim_df, x='decision', color='fraud_flag', 
                           title="Strategy Outcome",
                           color_discrete_map={0: 'lightgrey', 1: 'red'})
    st.plotly_chart(fig_dec, use_container_width=True)
"""

with open("app.py", "w") as f:
    f.write(code)

print("app.py updated with Tab 3 Theft Lab and fixed Tab 2 sliders.")
