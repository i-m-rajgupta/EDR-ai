
import json
import pandas as pd
import streamlit as st

from app.parser import parse_log_text
from app.analyzer import analyze_events
from app.shap_explainer import explain_event
from app.llm import explain_findings


# --------------------------------------------------
# PAGE CONFIGURATION
# --------------------------------------------------
st.set_page_config(
    page_title="EDR AI Log Intelligence",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

# --------------------------------------------------
# CUSTOM UI STYLING
# --------------------------------------------------
st.markdown(
    """
    <style>
    .block-container {
        padding-top: 1.5rem;
        padding-bottom: 2rem;
    }

    .hero {
        padding: 1.5rem;
        border-radius: 16px;
        background: linear-gradient(120deg, #10243a, #173e58);
        color: white;
        margin-bottom: 1.2rem;
    }

    .hero h1 {
        color: white;
        margin-bottom: 0.3rem;
    }

    .hero p {
        color: #d5e5f0;
        margin-bottom: 0;
    }

    .section-note {
        color: #7d8795;
        font-size: 0.9rem;
    }

    div[data-testid="stMetric"] {
        border: 1px solid rgba(128, 128, 128, 0.25);
        padding: 14px;
        border-radius: 12px;
    }

    div.stButton > button {
        border-radius: 9px;
        min-height: 42px;
    }
    </style>
    """,
    unsafe_allow_html=True,
)


# --------------------------------------------------
# HEADER
# --------------------------------------------------
st.markdown(
    """
    <div class="hero">
        <h1>🛡️ EDR AI Log Intelligence</h1>
        <p>
            Endpoint telemetry analysis · Threat triage ·
            Explainable risk scoring · Investigation support
        </p>
    </div>
    """,
    unsafe_allow_html=True,
)


# --------------------------------------------------
# SIDEBAR
# --------------------------------------------------
with st.sidebar:
    st.title("Investigation Workspace")
    st.caption("Upload and inspect endpoint security logs.")

    uploaded_file = st.file_uploader(
        "Upload EDR log",
        type=["log", "txt"],
        accept_multiple_files=False,
        help="The uploaded file is analyzed in memory; this dashboard "
             "does not modify the original file.",
    )

    st.divider()

    st.subheader("Analysis Modules")

    st.markdown(
        """
        - Log parsing
        - Rule-based detection
        - SHAP risk explanations
        - AI investigation assistance
        - Event export
        """
    )

    st.divider()

    st.caption(
        "Read-only analysis interface. Findings require human verification."
    )


# --------------------------------------------------
# EMPTY STATE
# --------------------------------------------------
if uploaded_file is None:
    st.subheader("Security Operations Overview")

    st.write(
        "Start an investigation by uploading an endpoint log file "
        "from the sidebar."
    )

    col1, col2, col3 = st.columns(3)

    with col1:
        st.info("**01 · Ingest**\n\nParse JSON and plain-text log entries.")

    with col2:
        st.info("**02 · Investigate**\n\nReview rule-based findings and event evidence.")

    with col3:
        st.info("**03 · Explain**\n\nExplore risk contributions and investigation guidance.")

    st.warning(
        "No data is displayed until a log file has been uploaded."
    )

    st.stop()


# --------------------------------------------------
# PARSE LOG FILE
# --------------------------------------------------
log_text = uploaded_file.getvalue().decode(
    "utf-8",
    errors="replace",
)

try:
    events = parse_log_text(log_text)
except Exception as exc:
    st.error(f"Could not parse this file: {exc}")
    st.stop()

if not events:
    st.warning("No events were parsed from the uploaded file.")
    st.stop()

events_df = pd.DataFrame(events)

try:
    findings = analyze_events(events)
except Exception as exc:
    st.error(f"Security analysis failed: {exc}")
    st.stop()

findings_df = pd.DataFrame(findings)

# Ensure optional columns exist for consistent filtering and display.
if "severity" not in events_df.columns:
    events_df["severity"] = "UNKNOWN"

if "event_type" not in events_df.columns:
    events_df["event_type"] = "UNKNOWN"

if "severity" not in findings_df.columns:
    findings_df["severity"] = "UNKNOWN"

if "event_type" not in findings_df.columns:
    findings_df["event_type"] = "UNKNOWN"


# --------------------------------------------------
# OVERVIEW METRICS
# --------------------------------------------------
st.caption(f"Loaded file: {uploaded_file.name}")

total_events = len(events_df)
total_findings = len(findings_df)

critical_count = (
    findings_df["severity"]
    .astype(str)
    .str.upper()
    .isin(["CRITICAL", "FATAL"])
    .sum()
)

unique_types = events_df["event_type"].nunique()

metric1, metric2, metric3, metric4 = st.columns(4)

metric1.metric("Total Events", f"{total_events:,}")
metric2.metric("Security Findings", f"{total_findings:,}")
metric3.metric("Critical Findings", f"{critical_count:,}")
metric4.metric("Event Types", f"{unique_types:,}")

st.divider()


# --------------------------------------------------
# INTERACTIVE TABS
# --------------------------------------------------
overview_tab, findings_tab, shap_tab, ai_tab, raw_tab = st.tabs(
    [
        "📊 Overview",
        "🚨 Security Findings",
        "🧠 SHAP Explainability",
        "🤖 AI Assistant",
        "📄 Raw Events & Export",
    ]
)


# ==================================================
# TAB 1: OVERVIEW
# ==================================================
with overview_tab:
    st.subheader("Security Overview")
    st.caption(
        "Explore the distribution of events and detection severity."
    )

    left, right = st.columns(2)

    with left:
        st.markdown("#### Events by Type")

        type_counts = (
            events_df["event_type"]
            .fillna("UNKNOWN")
            .astype(str)
            .value_counts()
            .head(12)
        )

        if not type_counts.empty:
            st.bar_chart(type_counts)
        else:
            st.info("No event type information is available.")

    with right:
        st.markdown("#### Events by Severity")

        severity_counts = (
            events_df["severity"]
            .fillna("UNKNOWN")
            .astype(str)
            .str.upper()
            .value_counts()
        )

        if not severity_counts.empty:
            st.bar_chart(severity_counts)
        else:
            st.info("No severity information is available.")

    st.markdown("#### Investigation Summary")

    if total_findings:
        st.write(
            f"The configured detection rules identified "
            f"**{total_findings} finding(s)** across "
            f"**{total_events} parsed event(s)**."
        )

        st.caption(
            "A finding is a triage signal, not proof of compromise."
        )
    else:
        st.success(
            "No events matched the current detection rules. "
            "This does not guarantee that the log is threat-free."
        )


# ==================================================
# TAB 2: SECURITY FINDINGS
# ==================================================
with findings_tab:
    st.subheader("Security Findings")
    st.write(
        "Filter the findings and inspect the evidence behind each alert."
    )

    if findings_df.empty:
        st.success("No findings matched the current detection rules.")

    else:
        filter1, filter2 = st.columns(2)

        severity_values = sorted(
            findings_df["severity"]
            .fillna("UNKNOWN")
            .astype(str)
            .str.upper()
            .unique()
            .tolist()
        )

        with filter1:
            selected_severity = st.selectbox(
                "Filter by severity",
                ["ALL"] + severity_values,
            )

        event_type_values = sorted(
            findings_df["event_type"]
            .fillna("UNKNOWN")
            .astype(str)
            .unique()
            .tolist()
        )

        with filter2:
            selected_type = st.selectbox(
                "Filter by event type",
                ["ALL"] + event_type_values,
            )

        filtered_findings = findings_df.copy()

        if selected_severity != "ALL":
            filtered_findings = filtered_findings[
                filtered_findings["severity"]
                .fillna("UNKNOWN")
                .astype(str)
                .str.upper()
                == selected_severity
            ]

        if selected_type != "ALL":
            filtered_findings = filtered_findings[
                filtered_findings["event_type"]
                .fillna("UNKNOWN")
                .astype(str)
                == selected_type
            ]

        st.caption(
            f"Showing {len(filtered_findings)} of {total_findings} findings."
        )

        st.dataframe(
            filtered_findings,
            width="stretch",
            hide_index=True,
            selection_mode="single-row",
            on_select="rerun",
        )

        if not filtered_findings.empty:
            st.markdown("#### Finding Details")

            finding_options = list(range(len(filtered_findings)))

            selected_finding_index = st.selectbox(
                "Choose a finding",
                finding_options,
                format_func=lambda i: (
                    f"Line {filtered_findings.iloc[i].get('line', '?')} · "
                    f"{filtered_findings.iloc[i].get('event_type', 'UNKNOWN')} · "
                    f"{filtered_findings.iloc[i].get('severity', 'UNKNOWN')}"
                ),
                key="finding_detail_selector",
            )

            selected_finding = filtered_findings.iloc[
                selected_finding_index
            ].to_dict()

            st.json(selected_finding)


# ==================================================
# TAB 3: SHAP EXPLAINABILITY
# ==================================================
with shap_tab:
    st.subheader("Explainable Risk Assessment")

    st.write(
        "Select a detected event to inspect its contributing features."
    )

    if findings_df.empty:
        st.info(
            "No findings are available to explain. "
            "Try a log containing events that match your detection rules."
        )

    else:
        shap_options = list(range(len(findings_df)))

        shap_index = st.selectbox(
            "Select event for explanation",
            shap_options,
            format_func=lambda i: (
                f"Line {findings_df.iloc[i].get('line', '?')} · "
                f"{findings_df.iloc[i].get('event_type', 'UNKNOWN')}"
            ),
            key="shap_selector",
        )

        selected_finding = findings_df.iloc[shap_index].to_dict()

        selected_event = next(
            (
                event for event in events
                if str(event.get("_line"))
                == str(selected_finding.get("line"))
            ),
            None,
        )

        if selected_event is None:
            st.warning(
                "Could not match this finding to its original event."
            )

        else:
            try:
                result = explain_event(selected_event)

                st.metric(
                    "Illustrative Risk Score",
                    f"{result['risk_score']:.1f}/100",
                )

                st.caption(
                    "This heuristic score is not a calibrated probability "
                    "of malware or compromise."
                )

                explanation_df = result["explanation"]

                chart_col, detail_col = st.columns([3, 2])

                with chart_col:
                    st.markdown("#### Feature Contributions")

                    chart_df = explanation_df.set_index(
                        "Feature"
                    )[["SHAP Value"]]

                    st.bar_chart(
                        chart_df,
                        horizontal=True,
                    )

                with detail_col:
                    st.markdown("#### Explanation Details")

                    st.dataframe(
                        explanation_df,
                        width="stretch",
                        hide_index=True,
                    )

            except Exception as exc:
                st.error(f"Could not generate the explanation: {exc}")


# ==================================================
# TAB 4: AI INVESTIGATION ASSISTANT
# ==================================================
with ai_tab:
    st.subheader("AI Investigation Assistant")

    st.write(
        "Generate an investigation summary from the detected findings. "
        "If the API is unavailable, your configured local fallback can "
        "provide a rule-based report."
    )

    if findings_df.empty:
        st.info("No findings are available for investigation.")

    else:
        st.warning(
            "Review sensitive log data before sending any findings to "
            "an external API. AI-generated conclusions require verification."
        )

        if st.button(
            "Generate Investigation Report",
            type="primary",
            key="generate_ai_report",
        ):
            with st.spinner("Preparing investigation report..."):
                try:
                    report = explain_findings(findings)
                    st.session_state["edr_investigation_report"] = report
                except Exception as exc:
                    st.error(f"Report generation failed: {exc}")

        report = st.session_state.get("edr_investigation_report")

        if report:
            st.markdown("### Investigation Report")
            st.markdown(report)

            st.download_button(
                "Download Investigation Report",
                data=report,
                file_name="edr_investigation_report.md",
                mime="text/markdown",
            )


# ==================================================
# TAB 5: RAW EVENTS AND EXPORT
# ==================================================
with raw_tab:
    st.subheader("Parsed Events")
    st.write(
        "Search the parsed records and export the data for further analysis."
    )

    search_term = st.text_input(
        "Search events",
        placeholder="Search process names, messages, severity, paths...",
        key="raw_event_search",
    )

    displayed_events = events_df.copy()

    if search_term.strip():
        mask = displayed_events.astype(str).apply(
            lambda column: column.str.contains(
                search_term,
                case=False,
                regex=False,
                na=False,
            )
        ).any(axis=1)

        displayed_events = displayed_events[mask]

    st.caption(
        f"Showing {len(displayed_events)} of {len(events_df)} events."
    )

    st.dataframe(
        displayed_events,
        width="stretch",
        hide_index=True,
    )

    export_col1, export_col2 = st.columns(2)

    with export_col1:
        st.download_button(
            "Download Parsed Events (CSV)",
            data=events_df.to_csv(index=False).encode("utf-8"),
            file_name="edr_parsed_events.csv",
            mime="text/csv",
        )

    with export_col2:
        st.download_button(
            "Download Parsed Events (JSON)",
            data=json.dumps(
                events,
                indent=2,
                ensure_ascii=False,
                default=str,
            ),
            file_name="edr_parsed_events.json",
            mime="application/json",
        )


# --------------------------------------------------
# FOOTER
# --------------------------------------------------
st.divider()

st.caption(
    "EDR AI Log Intelligence · Read-only log analysis · "
    "Rule-based detections and heuristic risk scoring · "
    "Human verification required"
)
