# 🔍 Log Analysis Agent (Streamlit Version)

This is a simple, LLM-powered SIEM log analysis tool that:
- Uploads AWS-style JSON log files
- Detects suspicious log events
- Uses OpenAI GPT to explain them in plain English

## 🚀 How to Run

1. Install dependencies:
```bash
pip install -r requirements.txt
```

2. Run the Streamlit app:
```bash
streamlit run streamlit_app.py
```

3. Upload a `.json` log file, paste your OpenAI API key, and view the results.

## 🧪 Sample Log File

Check `sample_logs.json` for a ready-to-use test log.

## 🌐 Deploy to Streamlit Cloud

- Push this folder to GitHub
- Connect repo at https://streamlit.io/cloud