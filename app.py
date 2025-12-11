import streamlit as st
import pandas as pd
import plotly.express as px

# --- 1. SETUP ---
st.set_page_config(page_title="🛡️ Avant Fraud Demo", layout="wide")

# --- 2. FAST DATA LOADING ---
@st.cache_data
def load_data():
    df = pd.read_csv("DS_interview.csv")
    
    # Pre-calculate flags
    df['is_traveling'] = df['user_country'] != df['ip_country']
    df['is_loyal'] = df['time_on_file'] > 365
    
    # Ensure model_score is numeric
    df['model_score'] = pd.to_numeric(df['model_score'], errors='coerce').fillna(0)
    
    return df

try:
    df = load_data()
except Exception as e:
    st.error(f"Error: {e}")
    st.stop()

# --- 3. SIDEBAR CONTROLS ---
st.sidebar.title("⚡ Strategy Controls")

st.sidebar.subheader("1. General Risk Policy")
# THIS IS THE NEW SLIDER THAT MAKES NUMBERS MOVE
decline_threshold = st.sidebar.slider(
    "Auto-Decline Score Threshold (>)", 
    min_value=700, max_value=1000, value=980, step=10,
    help="Transactions with a score higher than this are Declined."
)

st.sidebar.subheader("2. VIP Exceptions")
# This slider saves VIPs from the Review Queue
vip_save_threshold = st.sidebar.slider(
    "VIP 'Green Lane' Score (<)", 
    min_value=700, max_value=1000, value=950, step=10,
    help="VIPs below this score bypass Manual Review."
)

st.sidebar.subheader("3. Hard Blocks")
strict_geo = st.sidebar.checkbox("Strict Geo-Blocking (Travelers)", False)

# --- 4. VECTORIZED STRATEGY ---
def run_dynamic_strategy(df, decline_thresh, vip_thresh, strict_geo):
    # 1. Start with everything as "Approve"
    df['decision'] = 'Approve'
    
    # --- LAYER 1: HARD DECLINES (Static) ---
    # Velocity is always bad
    df.loc[df['high_velocity_indicator'] == 1, 'decision'] = 'Decline'
    
    # Strict Geo (Optional Toggle)
    if strict_geo:
        df.loc[df['is_traveling'] == True, 'decision'] = 'Decline'
        
    # --- LAYER 2: SCORE BASED DECLINES (Dynamic!) ---
    # This is what makes the numbers change when you move the first slider
    # Apply only if not already declined
    mask_high_risk = (df['decision'] == 'Approve') & (df['model_score'] > decline_thresh)
    df.loc[mask_high_risk, 'decision'] = 'Decline'
    
    # --- LAYER 3: MANUAL REVIEW (Grey Zone) ---
    # New Device + Not already Declined
    mask_review = (df['decision'] == 'Approve') & (df['new_device'] == 1)
    df.loc[mask_review, 'decision'] = 'Manual Review'
    
    # --- LAYER 4: VIP OVERRIDE (Retention Strategy) ---
    # VIPs get to bypass "Manual Review" if their score is safe(ish)
    mask_vip = (df['engagement_segment'] == 'HIGH') & (df['model_score'] < vip_thresh)
    
    # Logic: If it was "Manual Review", set to "Approve"
    mask_vip_save = (df['decision'] == 'Manual Review') & mask_vip
    df.loc[mask_vip_save, 'decision'] = 'Approve'
    
    return df

# Run Strategy
df = run_dynamic_strategy(df, decline_threshold, vip_save_threshold, strict_geo)

# --- 5. METRICS ---
st.title("🛡️ Avant Fraud Strategy Command Center")

# Fast Calculation
decline_mask = df['decision'] == 'Decline'
fraud_mask = df['fraud_flag'] == 1

# KPI 1: Fraud Savings (Fraudsters we Declined)
fraud_caught = df.loc[decline_mask & fraud_mask, 'transaction_amount'].sum()

# KPI 2: False Declines (Good people we Declined)
false_declines = df.loc[decline_mask & (~fraud_mask)].shape[0]

# KPI 3: Review Queue
review_count = (df['decision'] == 'Manual Review').sum()

# Display Metrics
kpi1, kpi2, kpi3 = st.columns(3)
kpi1.metric("💰 Fraud Savings", f"${fraud_caught:,.0f}", delta="Higher is Better")
kpi2.metric("⚠️ False Declines", f"{false_declines:,}", delta="Lower is Better", delta_color="inverse")
kpi3.metric("👀 Review Queue", f"{review_count:,}", delta="Operational Cost", delta_color="off")

# --- 6. VISUALS ---
st.subheader("Decision Impact Analysis")
# Group by for speed
chart_data = df.groupby(['decision', 'engagement_segment']).size().reset_index(name='count')
fig = px.bar(
    chart_data, x="decision", y="count", color="engagement_segment", 
    color_discrete_map={"HIGH": "#00CC96", "MID": "#AB63FA", "LOW": "#EF553B"},
    title="How your logic affects different customer segments"
)
st.plotly_chart(fig, use_container_width=True)
