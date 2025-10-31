# 🦠 Phishing URL Detector

An end-to-end machine learning-powered web application for real-time phishing URL detection.  
Combines semantic (TF-IDF), heuristic (SSL, domain age, brand similarity, keyword patterns, etc.), and real-time blacklist signals with an XGBoost classifier for robust URL risk assessment.  
Features an interactive UI built in Streamlit and a backend REST API powered by Flask.

---

## 🚀 Features

- Detects phishing and benign URLs using ML + expert heuristics
- Built with Python, Flask (REST API), and Streamlit (UI)
- Real-time detection with instant risk explanation and ML probability
- Incorporates custom features: SSL, redirect chains, suspicious keywords, shortener usage, domain age, brand similarity, and external blacklist feeds

---

## 📦 Tech Stack

- Python 3.x
- Scikit-learn & XGBoost (model training and inference)
- Pandas, NumPy
- Flask (API server)
- Streamlit (frontend UI)
- Requests, joblib

## 🛠️ Installation

1. **Clone the repo**
   git clone https://github.com/avantikatripath1/phishing-url-detector.git
    cd phishing-url-detector

2. **Install dependencies**  
pip install -r requirements.txt

*(or individually: flask, streamlit, scikit-learn, xgboost, pandas, numpy, joblib, requests, tldextract, whois)*

3. **Prepare your dataset**  
- Update your `urls.csv` (never include any real keys/secrets!)

4. **Train the ML model**
python ml_model/train_model.py
*(Model artifacts saved in `ml_model/phish_model_artifacts.pkl`)*

5. **Run the Flask backend**
python app.py

6. **Run the Streamlit UI**
streamlit run ui.py

---

## ⚡ Usage

- Enter any URL in the UI to check for phishing risk.
- Displays risk level, reasons, ML score, and key signals.
- API endpoint available at `/check_url` (POST JSON with `{"url": "<url>"}`).

---

## 📋 Example

{
"url": "http://suspicious-site.example/login",
"risk_level": "HIGH",
"risk_reasons": [
"Listed on phishing blacklist.",
"Invalid/missing SSL.",
"Contains suspicious keyword: login."
],
"ml_prediction": "Phishing",
"ml_probability": 0.97
}

---

## 👨‍💻 Author

- AVANTIKA TRIPATHI(https://github.com/avantikatripath1)

---

## ⭐ Contributing

Contributions, issues, and feature requests are welcome!

Give a ⭐️ if you like this project!

---

## 🛡️ License

This project is released under the MIT License.
