import streamlit as st
import pandas as pd
import plotly.express as px

# --- LOAD DATA ---
@st.cache_data
def load_data():
    # Make sure DS_interview.csv is uploaded to the Colab files!
    df = pd.read_csv("DS_interview.csv")
    df['is_traveling'] = df['user_country'] != df['ip_country']
    df['is_loyal'] = df['time_on_file'] > 365
    return df

try:
    df = load_data()
except Exception as e:
    st.error(f"Error loading data: {e}. Did you upload DS_interview.csv?")
    st.stop()

# --- SIDEBAR & LOGIC ---
st.title("🛡️ Avant Fraud Strategy Command Center")

# Sidebar Controls
st.sidebar.header("Strategy Rules")
vip_threshold = st.sidebar.slider("VIP Approval Score (Under)", 500, 1000, 950)
strict_geo = st.sidebar.checkbox("Strict Geo-Blocking?", False)

# Simple Logic Engine
def run_strategy(df):
    decisions = []
    for i, row in df.iterrows():
        d = "Approve"
        if row['high_velocity_indicator'] == 1: d = "Decline"
        elif strict_geo and row['is_traveling']: d = "Decline"
        elif row['engagement_segment'] == 'HIGH' and row['model_score'] < vip_threshold: d = "Approve" # VIP override
        elif row['new_device'] == 1: d = "Manual Review"
        decisions.append(d)
    return decisions

df['decision'] = run_strategy(df)

# --- VISUALS ---
kpi1, kpi2 = st.columns(2)
fraud_caught = df[(df['decision'] == 'Decline') & (df['fraud_flag'] == 1)]['transaction_amount'].sum()
kpi1.metric("Fraud Savings", f"${fraud_caught:,.0f}")
kpi2.metric("Review Queue", len(df[df['decision'] == 'Manual Review']))

st.subheader("Decision Breakdown")
fig = px.histogram(df, x="decision", color="engagement_segment", barmode="group")
st.plotly_chart(fig)
