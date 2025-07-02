import pandas as pd
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.ensemble import IsolationForest
import joblib
import os

df = pd.read_csv("data/sample_logs.csv")
vectorizer = TfidfVectorizer()
X = vectorizer.fit_transform(df["message"])

model = IsolationForest(contamination=0.25)
model.fit(X)

df["anomaly"] = model.predict(X)
df["anomaly"] = df["anomaly"].map({1: "Normal", -1: "Anomaly"})

print(df[["timestamp", "message", "anomaly"]])

os.makedirs("model", exist_ok=True)
joblib.dump(model, "model/log_model.pkl")
joblib.dump(vectorizer, "model/tfidf.pkl")
