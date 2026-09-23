import json
import sys
from pathlib import Path

import pandas as pd
import streamlit as st


# NIDAS project root
PROJECT_ROOT = Path(__file__).resolve().parent.parent

# Allow imports from the project root
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))


from storage.alert_store import get_alerts, update_alert_status


DATABASE_PATH = PROJECT_ROOT / "data" / "nidas.db"


DATABASE_PATH = Path("data/nidas.db")


st.set_page_config(
    page_title="NIDAS Security Dashboard",
    page_icon="🛡️",
    layout="wide"
)


st.title("NIDAS")
st.subheader("Network Intrusion Detection & Alert System")

st.caption(
    "Security monitoring dashboard for network-based "
    "detection and analyst triage."
)


# --------------------------------------------------
# Load alerts
# --------------------------------------------------

alerts = get_alerts(DATABASE_PATH)

if not alerts:
    st.info(
        "No security alerts are currently stored."
    )
    st.stop()


df = pd.DataFrame(alerts)

df["timestamp"] = pd.to_datetime(
    df["timestamp"]
)


# --------------------------------------------------
# Sidebar filters
# --------------------------------------------------

st.sidebar.header("Alert Filters")


severity_options = sorted(
    df["severity"].dropna().unique()
)

selected_severities = st.sidebar.multiselect(
    "Severity",
    severity_options,
    default=severity_options
)


rule_options = sorted(
    df["rule_name"].dropna().unique()
)

selected_rules = st.sidebar.multiselect(
    "Detection Rule",
    rule_options,
    default=rule_options
)


source_options = sorted(
    df["source_ip"].dropna().unique()
)

selected_sources = st.sidebar.multiselect(
    "Source IP",
    source_options,
    default=source_options
)


filtered_df = df[
    df["severity"].isin(selected_severities)
    & df["rule_name"].isin(selected_rules)
    & df["source_ip"].isin(selected_sources)
]


# --------------------------------------------------
# Metrics
# --------------------------------------------------

total_alerts = len(filtered_df)

high_alerts = len(
    filtered_df[
        filtered_df["severity"] == "high"
    ]
)

medium_alerts = len(
    filtered_df[
        filtered_df["severity"] == "medium"
    ]
)

unique_sources = (
    filtered_df["source_ip"]
    .dropna()
    .nunique()
)


metric1, metric2, metric3, metric4 = st.columns(4)

metric1.metric(
    "Total Alerts",
    total_alerts
)

metric2.metric(
    "High Severity",
    high_alerts
)

metric3.metric(
    "Medium Severity",
    medium_alerts
)

metric4.metric(
    "Unique Sources",
    unique_sources
)


st.divider()


# --------------------------------------------------
# Charts
# --------------------------------------------------

chart1, chart2 = st.columns(2)


with chart1:

    st.subheader(
        "Alerts by Severity"
    )

    severity_counts = (
        filtered_df["severity"]
        .value_counts()
    )

    st.bar_chart(
        severity_counts
    )


with chart2:

    st.subheader(
        "Alerts by Detection"
    )

    rule_counts = (
        filtered_df["rule_name"]
        .value_counts()
    )

    st.bar_chart(
        rule_counts
    )


st.divider()


# --------------------------------------------------
# Alert table
# --------------------------------------------------

st.subheader(
    "Security Alerts"
)


display_columns = [
    "timestamp",
    "severity",
    "status",
    "rule_id",
    "rule_name",
    "source_ip",
    "destination_ip",
    "protocol"
]


st.dataframe(
    filtered_df[display_columns],
    use_container_width=True,
    hide_index=True
)


st.divider()


# --------------------------------------------------
# Analyst triage
# --------------------------------------------------

st.subheader(
    "Alert Investigation"
)


if filtered_df.empty:

    st.info(
        "No alerts match the selected filters."
    )

else:

    alert_choices = {}

    for _, row in filtered_df.iterrows():

        label = (
            f"{row['alert_id']} | "
            f"{row['severity'].upper()} | "
            f"{row['rule_name']} | "
            f"{row['source_ip']}"
        )

        alert_choices[label] = row


    selected_alert_label = st.selectbox(
        "Select an alert",
        list(alert_choices.keys())
    )


    selected_alert = alert_choices[
        selected_alert_label
    ]


    detail1, detail2 = st.columns(2)


    with detail1:

        st.write(
            "**Alert ID:**",
            selected_alert["alert_id"]
        )

        st.write(
            "**Rule:**",
            selected_alert["rule_id"]
        )

        st.write(
            "**Severity:**",
            selected_alert["severity"].upper()
        )

        st.write(
            "**Protocol:**",
            selected_alert["protocol"]
        )


    with detail2:

        st.write(
            "**Source IP:**",
            selected_alert["source_ip"]
        )

        st.write(
            "**Destination IP:**",
            selected_alert["destination_ip"]
        )

        st.write(
            "**Tactic:**",
            selected_alert["tactic"]
        )

        st.write(
            "**Technique:**",
            selected_alert["technique"]
        )


    st.write(
        "**Description:**"
    )

    st.write(
        selected_alert["description"]
    )


    st.write(
        "**Detection Evidence:**"
    )

    evidence = selected_alert["evidence"]

    if isinstance(evidence, str):

        try:
            evidence = json.loads(
                evidence
            )

        except json.JSONDecodeError:
            pass


    st.write("**Analyst Status:**")

status_options = [
    "New",
    "Investigating",
    "Resolved"
]

current_status = selected_alert["status"]

current_index = status_options.index(
    current_status
)

new_status = st.selectbox(
    "Update status",
    status_options,
    index=current_index
)

if st.button("Save Status"):

    update_alert_status(
        selected_alert["alert_id"],
        new_status,
        DATABASE_PATH
    )

    st.success(
        f"Alert status updated to {new_status}."
    )

    st.rerun()