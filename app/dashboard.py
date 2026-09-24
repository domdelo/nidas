import json
import sys
from datetime import datetime
from pathlib import Path

import pandas as pd
import streamlit as st


# --------------------------------------------------
# Project setup
# --------------------------------------------------

PROJECT_ROOT = Path(
    __file__
).resolve().parent.parent

if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(
        0,
        str(PROJECT_ROOT)
    )


from storage.alert_store import (
    get_alerts,
    update_alert_status
)


DATABASE_PATH = (
    PROJECT_ROOT
    / "data"
    / "nidas.db"
)


# --------------------------------------------------
# Page configuration
# --------------------------------------------------

st.set_page_config(
    page_title=(
        "NIDAS Security Dashboard"
    ),
    page_icon="🛡️",
    layout="wide"
)


# --------------------------------------------------
# Header
# --------------------------------------------------

st.title(
    "🛡️ NIDAS"
)

st.subheader(
    "Network Intrusion Detection "
    "& Alert System"
)

st.caption(
    "Security operations dashboard for "
    "network-based threat detection, "
    "monitoring, and analyst triage."
)


# --------------------------------------------------
# Dashboard controls
# --------------------------------------------------

control1, control2 = st.columns(
    [1, 3]
)


with control1:

    auto_refresh = st.toggle(
        "Live Refresh",
        value=False
    )


with control2:

    if auto_refresh:

        st.success(
            "Live dashboard refresh enabled "
            "— updating every 5 seconds."
        )

    else:

        st.info(
            "Live dashboard refresh disabled."
        )


# --------------------------------------------------
# Main monitoring dashboard
# --------------------------------------------------

@st.fragment(
    run_every=5
    if auto_refresh
    else None
)
def monitoring_dashboard():

    # ----------------------------------------------
    # Load alerts
    # ----------------------------------------------

    alerts = get_alerts(
        DATABASE_PATH
    )

    refresh_time = (
        datetime.now().strftime(
            "%Y-%m-%d %H:%M:%S"
        )
    )

    st.caption(
        f"Last dashboard refresh: "
        f"{refresh_time}"
    )


    if not alerts:

        st.info(
            "No security alerts are "
            "currently stored."
        )

        return


    df = pd.DataFrame(
        alerts
    )

    df["timestamp"] = (
        pd.to_datetime(
            df["timestamp"]
        )
    )


    # ----------------------------------------------
    # Sidebar
    # ----------------------------------------------

    st.sidebar.header(
        "NIDAS Controls"
    )

    st.sidebar.caption(
        "Filter stored security alerts "
        "for analyst investigation."
    )

    st.sidebar.divider()


    # ----------------------------------------------
    # Severity filter
    # ----------------------------------------------

    severity_options = sorted(
        df["severity"]
        .dropna()
        .unique()
    )

    selected_severities = (
        st.sidebar.multiselect(
            "Severity",
            severity_options,
            default=severity_options,
            key="severity_filter"
        )
    )


    # ----------------------------------------------
    # Status filter
    # ----------------------------------------------

    status_options = [
        "New",
        "Investigating",
        "Resolved"
    ]

    available_statuses = []

    for status in status_options:

        if status in (
            df["status"]
            .dropna()
            .unique()
        ):

            available_statuses.append(
                status
            )


    selected_statuses = (
        st.sidebar.multiselect(
            "Analyst Status",
            available_statuses,
            default=available_statuses,
            key="status_filter"
        )
    )


    # ----------------------------------------------
    # Detection rule filter
    # ----------------------------------------------

    rule_options = sorted(
        df["rule_name"]
        .dropna()
        .unique()
    )

    selected_rules = (
        st.sidebar.multiselect(
            "Detection Rule",
            rule_options,
            default=rule_options,
            key="rule_filter"
        )
    )


    # ----------------------------------------------
    # Source IP filter
    # ----------------------------------------------

    source_options = sorted(
        df["source_ip"]
        .dropna()
        .unique()
    )

    selected_sources = (
        st.sidebar.multiselect(
            "Source IP",
            source_options,
            default=source_options,
            key="source_filter"
        )
    )


    # ----------------------------------------------
    # Alert source filter
    # ----------------------------------------------

    alert_source_options = sorted(
        df["alert_source"]
        .dropna()
        .unique()
    )

    selected_alert_sources = (
        st.sidebar.multiselect(
            "Alert Source",
            alert_source_options,
            default=alert_source_options,
            key="alert_source_filter"
        )
    )


    # ----------------------------------------------
    # Apply filters
    # ----------------------------------------------

    filtered_df = df[
        df["severity"].isin(
            selected_severities
        )
        & df["status"].isin(
            selected_statuses
        )
        & df["rule_name"].isin(
            selected_rules
        )
        & df["source_ip"].isin(
            selected_sources
        )
        & df["alert_source"].isin(
            selected_alert_sources
        )
    ].copy()


    # ----------------------------------------------
    # Dashboard overview
    # ----------------------------------------------

    st.subheader(
        "Security Overview"
    )


    total_alerts = len(
        filtered_df
    )


    high_alerts = len(
        filtered_df[
            filtered_df["severity"]
            == "high"
        ]
    )


    open_alerts = len(
        filtered_df[
            filtered_df["status"]
            != "Resolved"
        ]
    )


    unique_sources = (
        filtered_df["source_ip"]
        .dropna()
        .nunique()
    )


    metric1, metric2, metric3, metric4 = (
        st.columns(4)
    )


    metric1.metric(
        "Total Alerts",
        total_alerts
    )


    metric2.metric(
        "High Severity",
        high_alerts
    )


    metric3.metric(
        "Open Alerts",
        open_alerts
    )


    metric4.metric(
        "Unique Sources",
        unique_sources
    )


    st.divider()


    # ----------------------------------------------
    # Detection analytics
    # ----------------------------------------------

    st.subheader(
        "Detection Analytics"
    )


    chart1, chart2 = st.columns(
        2
    )


    # ----------------------------------------------
    # Severity chart
    # ----------------------------------------------

    with chart1:

        st.write(
            "**Alerts by Severity**"
        )

        if filtered_df.empty:

            st.info(
                "No severity data available "
                "for the selected filters."
            )

        else:

            severity_counts = (
                filtered_df[
                    "severity"
                ]
                .str.upper()
                .value_counts()
            )

            st.bar_chart(
                severity_counts,
                horizontal=True
            )


    # ----------------------------------------------
    # Rule chart
    # ----------------------------------------------

    with chart2:

        st.write(
            "**Alerts by Detection Rule**"
        )

        if filtered_df.empty:

            st.info(
                "No detection data available "
                "for the selected filters."
            )

        else:

            rule_counts = (
                filtered_df[
                    "rule_id"
                ]
                .value_counts()
            )

            st.bar_chart(
                rule_counts,
                horizontal=True
            )


    st.divider()


    # ----------------------------------------------
    # Alert status overview
    # ----------------------------------------------

    st.subheader(
        "Analyst Workflow"
    )


    if filtered_df.empty:

        st.info(
            "No analyst status data available "
            "for the selected filters."
        )

    else:

        workflow1, workflow2 = (
            st.columns(
                [1, 2]
            )
        )


        with workflow1:

            status_counts = (
                filtered_df[
                    "status"
                ]
                .value_counts()
            )

            st.write(
                "**Alerts by Status**"
            )

            st.bar_chart(
                status_counts,
                horizontal=True
            )


        with workflow2:

            new_count = len(
                filtered_df[
                    filtered_df["status"]
                    == "New"
                ]
            )

            investigating_count = len(
                filtered_df[
                    filtered_df["status"]
                    == "Investigating"
                ]
            )

            resolved_count = len(
                filtered_df[
                    filtered_df["status"]
                    == "Resolved"
                ]
            )


            status1, status2, status3 = (
                st.columns(3)
            )


            status1.metric(
                "New",
                new_count
            )

            status2.metric(
                "Investigating",
                investigating_count
            )

            status3.metric(
                "Resolved",
                resolved_count
            )


    st.divider()


    # ----------------------------------------------
    # Alert table
    # ----------------------------------------------

    st.subheader(
        "Security Alerts"
    )

    st.caption(
        f"Showing {len(filtered_df)} "
        f"of {len(df)} stored alerts."
    )


    if filtered_df.empty:

        st.info(
            "No alerts match the "
            "selected filters."
        )

    else:

        display_df = (
            filtered_df.copy()
        )

        display_df = (
            display_df.sort_values(
                "timestamp",
                ascending=False
            )
        )

        display_df[
            "timestamp"
        ] = (
            display_df[
                "timestamp"
            ].dt.strftime(
                "%Y-%m-%d %H:%M:%S"
            )
        )


        display_columns = [
            "timestamp",
            "severity",
            "status",
            "alert_source",
            "rule_id",
            "rule_name",
            "source_ip",
            "destination_ip",
            "protocol"
        ]


        st.dataframe(
            display_df[
                display_columns
            ],
            use_container_width=True,
            hide_index=True,
            column_config={
                "timestamp": (
                    "Timestamp"
                ),
                "severity": (
                    "Severity"
                ),
                "status": (
                    "Status"
                ),
                "alert_source": (
                    "Source"
                ),
                "rule_id": (
                    "Rule ID"
                ),
                "rule_name": (
                    "Detection"
                ),
                "source_ip": (
                    "Source IP"
                ),
                "destination_ip": (
                    "Destination IP"
                ),
                "protocol": (
                    "Protocol"
                )
            }
        )


    st.divider()


    # ----------------------------------------------
    # Alert investigation
    # ----------------------------------------------

    st.subheader(
        "Alert Investigation"
    )

    st.caption(
        "Select an alert to review its "
        "detection evidence and update "
        "the analyst investigation status."
    )


    if filtered_df.empty:

        st.info(
            "Select different filters "
            "to investigate alerts."
        )

        return


    # ----------------------------------------------
    # Build alert selection menu
    # ----------------------------------------------

    investigation_df = (
        filtered_df.sort_values(
            "timestamp",
            ascending=False
        )
    )


    alert_choices = {}


    for _, row in (
        investigation_df.iterrows()
    ):

        label = (
            f"{row['rule_id']} | "
            f"{row['severity'].upper()} | "
            f"{row['status']} | "
            f"{row['source_ip']} | "
            f"{row['timestamp'].strftime('%H:%M:%S')}"
        )

        alert_choices[
            label
        ] = row


    selected_alert_label = (
        st.selectbox(
            "Select an alert",
            list(
                alert_choices.keys()
            ),
            key="alert_selection"
        )
    )


    selected_alert = (
        alert_choices[
            selected_alert_label
        ]
    )


    # ----------------------------------------------
    # Selected alert summary
    # ----------------------------------------------

    st.write(
        f"### {selected_alert['rule_name']}"
    )


    summary1, summary2, summary3 = (
        st.columns(3)
    )


    summary1.metric(
        "Severity",
        selected_alert[
            "severity"
        ].upper()
    )


    summary2.metric(
        "Status",
        selected_alert[
            "status"
        ]
    )


    summary3.metric(
        "Alert Source",
        selected_alert[
            "alert_source"
        ]
    )


    # ----------------------------------------------
    # Alert details
    # ----------------------------------------------

    detail1, detail2 = st.columns(
        2
    )


    with detail1:

        st.write(
            "**Alert ID:**",
            selected_alert[
                "alert_id"
            ]
        )

        st.write(
            "**Timestamp:**",
            selected_alert[
                "timestamp"
            ].strftime(
                "%Y-%m-%d %H:%M:%S"
            )
        )

        st.write(
            "**Rule ID:**",
            selected_alert[
                "rule_id"
            ]
        )

        st.write(
            "**Protocol:**",
            selected_alert[
                "protocol"
            ]
        )


    with detail2:

        st.write(
            "**Source IP:**",
            selected_alert[
                "source_ip"
            ]
        )

        st.write(
            "**Destination IP:**",
            selected_alert[
                "destination_ip"
            ]
        )

        st.write(
            "**Tactic:**",
            selected_alert[
                "tactic"
            ]
        )

        st.write(
            "**Technique:**",
            selected_alert[
                "technique"
            ]
        )

        st.write(
            "**Technique ID:**",
            selected_alert[
                "technique_id"
            ]
        )


    # ----------------------------------------------
    # Description
    # ----------------------------------------------

    st.write(
        "**Description:**"
    )

    st.write(
        selected_alert[
            "description"
        ]
    )


    # ----------------------------------------------
    # Detection evidence
    # ----------------------------------------------

    st.write(
        "**Detection Evidence:**"
    )


    evidence = selected_alert[
        "evidence"
    ]


    if isinstance(
        evidence,
        str
    ):

        try:

            evidence = json.loads(
                evidence
            )

        except json.JSONDecodeError:

            pass


    if isinstance(
        evidence,
        dict
    ):

        st.json(
            evidence
        )

    else:

        st.write(
            evidence
        )


    # ----------------------------------------------
    # Analyst status
    # ----------------------------------------------

    st.divider()

    st.write(
        "### Analyst Triage"
    )


    analyst_status_options = [
        "New",
        "Investigating",
        "Resolved"
    ]


    current_status = (
        selected_alert[
            "status"
        ]
    )


    if (
        current_status
        not in analyst_status_options
    ):

        current_status = "New"


    current_index = (
        analyst_status_options.index(
            current_status
        )
    )


    status_column, button_column = (
        st.columns(
            [2, 1]
        )
    )


    with status_column:

        new_status = (
            st.selectbox(
                "Investigation Status",
                analyst_status_options,
                index=current_index,
                key=(
                    "status_"
                    + selected_alert[
                        "alert_id"
                    ]
                )
            )
        )


    with button_column:

        st.write("")

        st.write("")

        save_status = st.button(
            "Save Status",
            key=(
                "save_"
                + selected_alert[
                    "alert_id"
                ]
            ),
            use_container_width=True
        )


    if save_status:

        update_alert_status(
            selected_alert[
                "alert_id"
            ],
            new_status,
            DATABASE_PATH
        )

        st.success(
            f"Alert status updated "
            f"to {new_status}."
        )

        st.rerun()


# --------------------------------------------------
# Run dashboard
# --------------------------------------------------

monitoring_dashboard()