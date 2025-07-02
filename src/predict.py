import pandas as pd
import joblib

def predict_log(message):
    model = joblib.load("model/log_model.pkl")
    vectorizer = joblib.load("model/tfidf.pkl")
    vec = vectorizer.transform([message])
    result = model.predict(vec)
    return "Anomaly" if result[0] == -1 else "Normal"

if __name__ == "__main__":
    msg = input("Enter log message: ")
    print("Prediction:", predict_log(msg))
