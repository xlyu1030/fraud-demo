import streamlit as st
import pandas as pd
import plotly.express as px

# --- 1. SETUP ---
st.set_page_config(page_title="🛡️ Avant Fraud Demo", layout="wide")

# --- 2. FAST DATA LOADING ---
@st.cache_data
def load_data():
    # Load data
    df = pd.read_csv("DS_interview.csv")
    
    # Pre-calculate static flags (Done once, not every slider move)
    df['is_traveling'] = df['user_country'] != df['ip_country']
    df['is_loyal'] = df['time_on_file'] > 365
    
    # OPTIONAL: Sample down to 50k rows if it's still too heavy for the server
    # (Uncomment the next line if it's still slow)
    # df = df.sample(50000, random_state=42)
    
    return df

try:
    df = load_data()
except Exception as e:
    st.error(f"Error: {e}")
    st.stop()

# --- 3. SIDEBAR CONTROLS ---
st.sidebar.title("⚡ Fast Strategy Controls")
vip_threshold = st.sidebar.slider("VIP Approval Score (<)", 500, 1000, 950)
strict_geo = st.sidebar.checkbox("Strict Geo-Blocking?", False)

# --- 4. VECTORIZED STRATEGY (The Speed Fix) ---
def run_fast_strategy(df, vip_thresh, strict_geo):
    # 1. Start with everything as "Approve"
    # We create a new column 'decision' and fill it with 'Approve'
    df['decision'] = 'Approve'
    
    # 2. Vectorized Rules (This runs instantly on all rows)
    
    # Rule A: High Velocity -> Decline
    # df.loc[condition, column] = value
    df.loc[df['high_velocity_indicator'] == 1, 'decision'] = 'Decline'
    
    # Rule B: Strict Geo -> Decline (if enabled)
    if strict_geo:
        df.loc[df['is_traveling'] == True, 'decision'] = 'Decline'
        
    # Rule C: New Device -> Manual Review
    # Only apply if it wasn't already declined (masking)
    mask_review = (df['decision'] == 'Approve') & (df['new_device'] == 1)
    df.loc[mask_review, 'decision'] = 'Manual Review'
    
    # Rule D: VIP Override (The Green Lane)
    # If High Engagement AND Score is low enough, Approve it (even if it was Review)
    mask_vip = (df['engagement_segment'] == 'HIGH') & (df['model_score'] < vip_thresh)
    # We allow VIPs to bypass "Manual Review", but NOT "Decline" (safety first)
    mask_vip_apply = (df['decision'] == 'Manual Review') & mask_vip
    df.loc[mask_vip_apply, 'decision'] = 'Approve'
    
    return df

# Run the fast function
df = run_fast_strategy(df, vip_threshold, strict_geo)

# --- 5. METRICS & CHARTS ---
st.title("🛡️ Avant Fraud Strategy (Optimized)")

# Calculate KPIs using vectorized sums (Fast)
fraud_caught = df.loc[(df['decision'] == 'Decline') & (df['fraud_flag'] == 1), 'transaction_amount'].sum()
review_count = (df['decision'] == 'Manual Review').sum()
false_positives = ((df['decision'] == 'Decline') & (df['fraud_flag'] == 0)).sum()

col1, col2, col3 = st.columns(3)
col1.metric("💰 Fraud Savings", f"${fraud_caught:,.0f}")
col2.metric("👀 Review Queue", f"{review_count:,}")
col3.metric("⚠️ False Declines", f"{false_positives:,}")

# Charts
# We aggregate data first to make plotting faster (don't plot 700k points)
chart_data = df.groupby(['decision', 'engagement_segment']).size().reset_index(name='count')
fig = px.bar(chart_data, x="decision", y="count", color="engagement_segment", title="Decision Impact")
st.plotly_chart(fig, use_container_width=True)
