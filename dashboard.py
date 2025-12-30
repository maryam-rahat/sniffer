import streamlit as st
import pandas as pd
import plotly.express as px
from streamlit_autorefresh import st_autorefresh
import os

# ================= CONFIG =================
WINDOW_SECONDS = 60
REFRESH_MS = 1500

# ================= PAGE SETUP =================
st.set_page_config(
    page_title="Network Traffic Analyzer",
    layout="wide",
)

# ================= DARK ENTERPRISE THEME =================
st.markdown("""
<style>

/* -------- Global -------- */
html, body, [class*="css"] {
    background-color: #0d1117;
    color: #c9d1d9;
    font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
}

/* -------- Headers -------- */
h1, h2, h3 {
    color: #e6edf3;
    font-weight: 600;
}

/* -------- Metrics -------- */
[data-testid="metric-container"] {
    background-color: #161b22;
    border: 1px solid #30363d;
    border-radius: 8px;
    padding: 14px;
}

/* -------- Sidebar -------- */
section[data-testid="stSidebar"] {
    background-color: #0d1117;
    border-right: 1px solid #30363d;
}

/* -------- Tabs -------- */
button[data-baseweb="tab"] {
    background-color: #0d1117;
    border: 1px solid #30363d;
    color: #8b949e;
}

button[data-baseweb="tab"][aria-selected="true"] {
    background-color: #161b22;
    border-bottom: 2px solid #58a6ff;
    color: #e6edf3;
    font-weight: 600;
}

/* -------- Alerts -------- */
.stAlert {
    background-color: #161b22;
    border-left: 4px solid #f85149;
}

/* -------- Tables -------- */
[data-testid="stDataFrame"] {
    background-color: #161b22;
    border: 1px solid #30363d;
    border-radius: 6px;
}

/* -------- Scrollbar -------- */
::-webkit-scrollbar {
    width: 6px;
}
::-webkit-scrollbar-thumb {
    background: #30363d;
    border-radius: 3px;
}
::-webkit-scrollbar-track {
    background: #0d1117;
}

</style>
""", unsafe_allow_html=True)

# ================= SIDEBAR =================
st.sidebar.header("Controls")
live_mode = st.sidebar.toggle("Live Mode", value=True)

if live_mode:
    st_autorefresh(interval=REFRESH_MS, key="live_refresh")

st.sidebar.markdown("---")
st.sidebar.caption("Network Monitoring Dashboard")

# ================= TITLE =================
st.markdown("## Network Traffic Analyzer")
st.caption("Real-time packet capture, protocol classification, and traffic analysis")

# ================= FILE CHECK =================
if not os.path.exists("traffic_log.csv"):
    st.warning("traffic_log.csv not found. Run sniffer.py first.")
    st.stop()

df = pd.read_csv("traffic_log.csv")

REQUIRED_COLS = {
    "timestamp",
    "transport_protocol",
    "application_protocol",
    "security_type",
    "src_ip",
    "dst_ip",
    "packet_size"
}

missing = REQUIRED_COLS - set(df.columns)
if missing:
    st.error(f"Missing columns in CSV: {missing}")
    st.stop()

if df.empty:
    st.info("Waiting for traffic...")
    st.stop()

# ================= CLEAN =================
df["timestamp"] = pd.to_datetime(df["timestamp"], errors="coerce")
df = df.dropna(subset=["timestamp"])
df["application_protocol"] = df["application_protocol"].fillna("Other").replace("", "Other")

# ================= METRICS =================
m1, m2, m3, m4, m5 = st.columns(5)

m1.metric("Total Packets", len(df))
m2.metric("Unique Sources", df["src_ip"].nunique())
m3.metric("Unique Destinations", df["dst_ip"].nunique())
m4.metric("Transport Protocols", ", ".join(sorted(df["transport_protocol"].unique())))
m5.metric("Encrypted Traffic (%)", f"{(df['security_type']=='Encrypted').mean()*100:.1f}%")

# ================= TABS =================
tab_live, tab_details = st.tabs(["Live Dashboard", "Details"])

# ======================================================
# LIVE DASHBOARD
# ======================================================
with tab_live:

    st.subheader("Traffic Rate")

    rate_df = (
        df.set_index("timestamp")
        .resample("1S")
        .size()
        .reset_index(name="packets_per_sec")
    )

    cutoff = rate_df["timestamp"].max() - pd.Timedelta(seconds=WINDOW_SECONDS)
    rate_df = rate_df[rate_df["timestamp"] >= cutoff]

    rate_fig = px.line(
        rate_df,
        x="timestamp",
        y="packets_per_sec",
        labels={"packets_per_sec": "Packets/sec"},
        title=f"Last {WINDOW_SECONDS} seconds"
    )

    rate_fig.update_layout(
        paper_bgcolor="#161b22",
        plot_bgcolor="#161b22",
        font=dict(color="#c9d1d9"),
        xaxis=dict(gridcolor="#30363d"),
        yaxis=dict(gridcolor="#30363d")
    )

    st.plotly_chart(rate_fig, use_container_width=True, key="traffic_rate")

    c1, c2 = st.columns(2)

    with c1:
        proto_fig = px.pie(
            df,
            names="transport_protocol",
            hole=0.45,
            title="Transport Protocol Distribution"
        )
        proto_fig.update_layout(
            paper_bgcolor="#161b22",
            font=dict(color="#c9d1d9")
        )
        st.plotly_chart(proto_fig, use_container_width=True, key="transport_pie")

    with c2:
        size_fig = px.histogram(
            df,
            x="packet_size",
            nbins=50,
            title="Packet Size Distribution"
        )
        size_fig.update_layout(
            paper_bgcolor="#161b22",
            plot_bgcolor="#161b22",
            font=dict(color="#c9d1d9"),
            xaxis=dict(gridcolor="#30363d"),
            yaxis=dict(gridcolor="#30363d")
        )
        st.plotly_chart(size_fig, use_container_width=True, key="packet_size")

    st.subheader("Application Protocols")

    app_counts = df["application_protocol"].value_counts().head(6).reset_index()
    app_counts.columns = ["Application Protocol", "Packets"]

    app_fig = px.bar(
        app_counts,
        x="Packets",
        y="Application Protocol",
        orientation="h",
        title="Top Application Protocols"
    )
    app_fig.update_layout(
        paper_bgcolor="#161b22",
        plot_bgcolor="#161b22",
        font=dict(color="#c9d1d9"),
        xaxis=dict(gridcolor="#30363d"),
        yaxis=dict(gridcolor="#30363d")
    )
    st.plotly_chart(app_fig, use_container_width=True, key="application_protocols")

    st.subheader("Security Classification")

    security_fig = px.pie(
        df,
        names="security_type",
        hole=0.45,
        title="Encrypted vs Unencrypted Traffic"
    )
    security_fig.update_layout(
        paper_bgcolor="#161b22",
        font=dict(color="#c9d1d9")
    )
    st.plotly_chart(security_fig, use_container_width=True, key="security_class")

# ======================================================
# DETAILS
# ======================================================
with tab_details:

    with st.expander("Top Source IPs", expanded=True):
        top_ips = df["src_ip"].value_counts().head(10).reset_index()
        top_ips.columns = ["IP Address", "Packets"]
        st.dataframe(top_ips, use_container_width=True)

    with st.expander("Top Application Services", expanded=False):
        svc_counts = df["application_protocol"].value_counts().reset_index()
        svc_counts.columns = ["Service", "Packets"]
        st.dataframe(svc_counts, use_container_width=True)

    with st.expander("Raw Traffic Logs", expanded=False):
        st.dataframe(df, use_container_width=True)

    st.caption("Disable Live Mode to inspect data without automatic refresh.")
