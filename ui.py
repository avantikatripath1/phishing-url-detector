import streamlit as st
import requests

st.set_page_config(page_title="Phishing Detector", page_icon="🦠", layout="centered")

st.markdown("""
    <style>
      .reportview-container {
        background: linear-gradient(120deg,#a3e6f8,#e4e2e2);
      }
      .result-card {
        padding: 2em;
        border-radius: 20px;
        box-shadow: 0 2px 12px rgba(0,0,0,0.1);
        margin-top:2em;
        animation: fadein 1s;
        background: #fff;
      }
      @keyframes fadein {
        from {opacity:0;}
        to {opacity:1;}
      }
    </style>
    """, unsafe_allow_html=True)

st.title("🦠 Phishing URL Detector")

url = st.text_input("Enter URL to check:")
if st.button("Check URL"):
    with st.spinner("Assessing..."):
        try:
            r = requests.post("http://127.0.0.1:5000/check_url", json={'url': url})
            data = r.json()
            level = data['risk_level']
            color = "#fa7a7a" if level == "HIGH" else "#f7f06e" if level == "MEDIUM" else "#6ef788"
            icon  = "❌" if level == "HIGH" else "⚠️" if level == "MEDIUM" else "✅"
            reasons = data.get('risk_reasons', [])
            ml_pred = data.get('ml_prediction', '')
            ml_prob = data.get('ml_probability', '')
            # Clear summary phrase
            summary = (
                "⚠️ Strong signs of phishing! Do not trust this URL." if level == "HIGH"
                else "⚠️ This link has some risky signs. Be cautious." if level == "MEDIUM"
                else "✅ No major phishing signals detected."
            )
            st.markdown(
                f"""
                <div style="border:4px solid {color}; border-radius:24px; background:#fff; padding: 2em; margin-top:2em; box-shadow:0 2px 12px rgba(0,0,0,0.14)">
                  <h2 style="color:{color};">{icon} Risk Level: <b>{level}</b></h2>
                  <h4 style="color:#222; margin-bottom: 1em;">{summary}</h4>
                  <b>Why?</b>
                  <ul>
                    {''.join(f'<li style=\"margin-bottom:6px\">{r}</li>' for r in reasons)}
                  </ul>
                  <hr style="margin:1em 0;">
                  <b>ML Prediction:</b> {ml_pred}<br>
                  <b>ML Probability:</b> {ml_prob}
                  <hr>
                  <b>Technical Details:</b>
                  <ul>
                    <li><b>Final URL:</b> {data['final_url']}</li>
                    <li><b>Domain Age (days):</b> {data['domain_age_days']}</li>
                    <li><b>SSL Valid:</b> {data['ssl'].get('valid', '')}</li>
                    <li><b>Blacklisted:</b> {data['blacklist'].get('listed', '')}</li>
                    <li><b>Redirects:</b> {data['redirects']}</li>
                    <li><b>Shortener Used:</b> {data['shortener_info'].get('shortener_detected', '')}</li>
                  </ul>
                </div>
                """, unsafe_allow_html=True
            )
        except Exception as e:
            st.error(f"Error: {e}")
