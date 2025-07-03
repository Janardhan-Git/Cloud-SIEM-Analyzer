# streamlit_app.py
import streamlit as st
import pandas as pd
import requests
import boto3
import gzip
import json
from io import BytesIO
from datetime import datetime, timedelta
from sklearn.ensemble import IsolationForest
from email.message import EmailMessage
import smtplib
import os
from dotenv import load_dotenv
from elasticsearch import Elasticsearch
import openai
from fpdf import FPDF
import numpy as np

# --- Load Secrets from .env ---
load_dotenv()
AWS_REGION = os.getenv("AWS_REGION", "us-east-1")
SLACK_WEBHOOK_URL = os.getenv("SLACK_WEBHOOK_URL")
EMAIL_ALERT_TO = os.getenv("EMAIL_ALERT_TO")
EMAIL_SENDER = os.getenv("EMAIL_SENDER")
EMAIL_PASSWORD = os.getenv("EMAIL_PASSWORD")
ELK_URL = os.getenv("ELK_URL")
openai.api_key = os.getenv("OPENAI_API_KEY")

# --- Utility Functions ---
def get_country(ip):
    try:
        res = requests.get(f"https://ipinfo.io/{ip}/json")
        return res.json().get("country", "Unknown")
    except:
        return "Unknown"

def send_slack_alert(msg):
    if SLACK_WEBHOOK_URL:
        requests.post(SLACK_WEBHOOK_URL, json={"text": msg})

def send_email_alert(subject, body):
    if EMAIL_SENDER and EMAIL_PASSWORD:
        msg = EmailMessage()
        msg.set_content(body)
        msg["Subject"] = subject
        msg["From"] = EMAIL_SENDER
        msg["To"] = EMAIL_ALERT_TO
        with smtplib.SMTP("smtp.gmail.com", 587) as smtp:
            smtp.starttls()
            smtp.login(EMAIL_SENDER, EMAIL_PASSWORD)
            smtp.send_message(msg)

def fetch_cloudtrail_logs(bucket, prefix):
    s3 = boto3.client("s3", region_name=AWS_REGION)
    logs = []
    response = s3.list_objects_v2(Bucket=bucket, Prefix=prefix)
    for obj in response.get("Contents", []):
        file_obj = s3.get_object(Bucket=bucket, Key=obj["Key"])
        with gzip.GzipFile(fileobj=BytesIO(file_obj["Body"].read())) as f:
            data = json.loads(f.read().decode("utf-8"))
            logs.extend(data.get("Records", []))
    return logs

def fetch_elk_logs(index, query):
    if not ELK_URL:
        return []
    es = Elasticsearch(ELK_URL)
    try:
        result = es.search(index=index, body=query)
        return [hit["_source"] for hit in result["hits"]["hits"]]
    except Exception as e:
        return []

def fetch_cloudwatch_logs(log_group, start_time, end_time):
    logs = boto3.client("logs", region_name=AWS_REGION)
    response = logs.filter_log_events(
        logGroupName=log_group,
        startTime=int(start_time.timestamp() * 1000),
        endTime=int(end_time.timestamp() * 1000),
    )
    return [event["message"] for event in response["events"]]

def parse_logs(logs):
    df = pd.json_normalize(logs)
    df["eventTime"] = pd.to_datetime(df["eventTime"], errors='coerce')
    if "sourceIPAddress" in df:
        df["country"] = df["sourceIPAddress"].apply(get_country)
    return df

def detect_anomalies(df):
    df_hourly = df.groupby(df["eventTime"].dt.floor("H")).size().reset_index(name="eventCount")
    model = IsolationForest(contamination=0.05)
    df_hourly["anomaly"] = model.fit_predict(df_hourly[["eventCount"]])
    spikes = df_hourly[df_hourly["anomaly"] == -1]
    return spikes

def explain_with_openai(event):
    try:
        prompt = f"Explain this log entry: {safe_json_dumps(event)}"
        response = openai.ChatCompletion.create(
            model="gpt-3.5-turbo",
            messages=[
                {"role": "system", "content": "You are a cybersecurity analyst assistant."},
                {"role": "user", "content": prompt}
            ],
            max_tokens=150
        )
        return response.choices[0].message.content.strip()
    except Exception as e:
        return "LLM explanation failed."

def generate_pdf_report(df):
    pdf = FPDF()
    pdf.add_page()
    pdf.set_font("Arial", size=12)
    pdf.cell(200, 10, txt="SIEM Agent Log Summary", ln=True, align="C")
    for index, row in df.head(10).iterrows():
        pdf.multi_cell(0, 10, txt=safe_json_dumps(row.to_dict()))
    return pdf.output(dest='S').encode('latin1')

def safe_json_dumps(record):
    def safe_val(v):
        if isinstance(v, pd.Timestamp):
            return v.isoformat() if not pd.isna(v) else None
        if isinstance(v, float) and pd.isna(v):
            return None
        if isinstance(v, (np.datetime64, pd.NaT.__class__)):
            return None
        return v
    return json.dumps({k: safe_val(v) for k, v in record.items()}, indent=2)

# --- Streamlit UI ---
st.set_page_config(page_title="SIEM Assistant", layout="wide",
                   page_icon="🛡️")
st.title("🔍 Real-Time SIEM Assistant")

with st.sidebar:
    st.header("Log Source")
    source_type = st.selectbox("Choose Log Source", ["S3 (CloudTrail)", "ELK", "CloudWatch", "Local File"])
    use_llm = st.checkbox("Explain logs with OpenAI", value=False)

    if source_type == "S3 (CloudTrail)":
        bucket = st.text_input("S3 Bucket")
        prefix = st.text_input("Prefix Path", value="AWSLogs/")
        fetch_logs = st.button("Fetch Logs")
        if fetch_logs:
            logs = fetch_cloudtrail_logs(bucket, prefix)
            df_logs = parse_logs(logs)
            st.session_state["logs_df"] = df_logs

    elif source_type == "ELK":
        elk_index = st.text_input("ELK Index", value="cloudtrail")
        elk_query = st.text_area("ELK Query (JSON)", value='{"query": {"match_all": {}}}')
        fetch_logs = st.button("Fetch Logs")
        if fetch_logs:
            logs = fetch_elk_logs(elk_index, json.loads(elk_query))
            df_logs = parse_logs(logs)
            st.session_state["logs_df"] = df_logs

    elif source_type == "CloudWatch":
        log_group = st.text_input("Log Group Name")
        start_time = st.date_input("Start Date", datetime.utcnow() - timedelta(days=1))
        end_time = st.date_input("End Date", datetime.utcnow())
        fetch_logs = st.button("Fetch Logs")
        if fetch_logs:
            logs = fetch_cloudwatch_logs(log_group, start_time, end_time)
            logs = [{"eventTime": datetime.utcnow().isoformat(), "message": l} for l in logs]
            df_logs = parse_logs(logs)
            st.session_state["logs_df"] = df_logs

    elif source_type == "Local File":
        uploaded_file = st.file_uploader("Upload JSON Log File", type="json")
        if uploaded_file is not None:
            logs = json.load(uploaded_file)
            df_logs = parse_logs(logs)
            st.session_state["logs_df"] = df_logs

if "logs_df" in st.session_state:
    df = st.session_state["logs_df"]
    st.subheader("📈 Metrics")
    col1, col2, col3 = st.columns(3)
    col1.metric("Events", len(df))
    col2.metric("Unique Users", df.get("userIdentity.userName", pd.Series()).nunique())
    col3.metric("Countries", df.get("country", pd.Series()).nunique())

    if "country" in df:
        st.subheader("🌍 Events by Country")
        st.bar_chart(df["country"].value_counts())

    st.subheader("⏱️ Time-Series Events")
    time_counts = df["eventTime"].dt.floor("H").value_counts().sort_index()
    st.line_chart(time_counts)

    st.subheader("🚨 Anomaly Detection")
    spikes = detect_anomalies(df)
    st.dataframe(spikes)
    if not spikes.empty:
        send_slack_alert("🚨 SIEM Agent detected anomalies!")
        send_email_alert("SIEM Alert", f"Anomalies detected:\n{spikes.to_string()}")

    if use_llm:
        st.subheader("🤖 Log Explanations with OpenAI")
        for _, row in df.head(5).iterrows():
            st.markdown(f"**Event:** `{row.get('eventName', 'N/A')}`")
            st.code(safe_json_dumps(row.to_dict()))
            explanation = explain_with_openai(row.to_dict())
            st.success(explanation)

    st.subheader("📄 Download Report")
    pdf_bytes = generate_pdf_report(df)
    st.download_button(
        label="Download Summary as PDF",
        data=pdf_bytes,
        file_name="SIEM_Report.pdf",
        mime="application/pdf"
    )
else:
    st.info("👈 Select a log source and fetch logs to begin.")