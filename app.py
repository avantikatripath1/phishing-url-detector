from flask import Flask, request, jsonify
from urllib.parse import urlparse
import re, requests, socket, ssl, difflib, time, datetime, os
import joblib
import pandas as pd

# Optional imports
try:
    import whois
    WHOIS_AVAILABLE = True
except ImportError:
    WHOIS_AVAILABLE = False

try:
    import tldextract
    TLD_AVAILABLE = True
except ImportError:
    TLD_AVAILABLE = False

app = Flask(__name__)

# Configurations
BLACKLIST_URL = "https://openphish.com/feed.txt"
BLACKLIST_TTL = 10 * 60  # 10 minutes
REQUEST_TIMEOUT = 6
KNOWN_BRANDS = [
    "paypal","google","amazon","facebook","gmail","netflix",
    "linkedin","apple","microsoft","chase","wellsfargo","bank",
    "hdfc","icici","sbi","paytm","axis"
]
SHORTENER_DOMAINS = {
    "bit.ly","tinyurl.com","t.co","goo.gl","buff.ly","cutt.ly",
    "is.gd","ow.ly","rebrand.ly","shorte.st","lnkd.in"
}
_blacklist_cache = {"timestamp": 0, "data": set()}

# Load ML model artifacts (tfidf and classifier)
ML_ARTIFACT_PATH = os.path.join("ml_model", "phish_model_artifacts.pkl")
ml_tfidf = None
ml_clf = None
if os.path.exists(ML_ARTIFACT_PATH):
    try:
        ml_tfidf, ml_clf = joblib.load(ML_ARTIFACT_PATH)
        print("✅ Loaded ML artifacts (tfidf + classifier).")
    except Exception as e:
        print("⚠️ Failed to load ML artifacts:", e)
else:
    print("⚠️ ML artifacts not found. Run train_model.py to create ml_model/phish_model_artifacts.pkl")

# Helper functions
def normalize_url(url):
    url = str(url).strip()
    if not re.match(r"^https?://", url, re.I):
        url = "http://" + url
    return url

def fetch_blacklist():
    now = time.time()
    if now - _blacklist_cache["timestamp"] < BLACKLIST_TTL and _blacklist_cache["data"]:
        return _blacklist_cache["data"]
    try:
        r = requests.get(BLACKLIST_URL, timeout=REQUEST_TIMEOUT)
        r.raise_for_status()
        lines = [line.strip() for line in r.text.splitlines() if line.strip()]
        _blacklist_cache["timestamp"] = now
        _blacklist_cache["data"] = set(lines)
        return _blacklist_cache["data"]
    except Exception:
        return _blacklist_cache.get("data", set())

def expand_url(url):
    try:
        r = requests.get(url, allow_redirects=True, timeout=REQUEST_TIMEOUT, stream=True)
        final = r.url
        redirects = len(r.history) if r.history else 0
        r.close()
        return final, redirects
    except Exception:
        return url, 0

def extract_domain(url):
    parsed = urlparse(url)
    net = parsed.netloc.lower()
    if "@" in net:
        net = net.split("@")[-1]
    if ":" in net:
        net = net.split(":")[0]
    return net

def get_sld(domain):
    if TLD_AVAILABLE:
        ext = tldextract.extract(domain)
        return ext.domain
    else:
        parts = domain.split(".")
        return parts[-2] if len(parts) >= 2 else domain

def check_ssl_certificate(domain):
    result = {"valid": False, "days_left": None, "issuer": None, "error": None}
    try:
        ctx = ssl.create_default_context()
        with ctx.wrap_socket(socket.socket(), server_hostname=domain) as s:
            s.settimeout(REQUEST_TIMEOUT)
            s.connect((domain, 443))
            cert = s.getpeercert()
            not_after = cert.get("notAfter")
            issuer = cert.get("issuer")
            issuer_str = None
            if issuer:
                try:
                    issuer_str = ", ".join("=".join(x) for tup in issuer for x in (tup if isinstance(tup, tuple) else (tup,)))
                except Exception:
                    issuer_str = str(issuer)
            result["issuer"] = issuer_str
            if not_after:
                try:
                    dt = datetime.datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z")
                    days_left = (dt - datetime.datetime.utcnow()).days
                    result["days_left"] = days_left
                    result["valid"] = days_left >= 0
                except Exception:
                    result["error"] = "Could not parse cert expiry"
                    result["valid"] = True
            else:
                result["valid"] = True
        return result
    except Exception as e:
        result["error"] = str(e)
    return result

def whois_age_days(domain):
    if not WHOIS_AVAILABLE:
        return None
    try:
        w = whois.whois(domain)
        creation = w.creation_date
        if isinstance(creation, list):
            creation = creation[0]
        if isinstance(creation, datetime.datetime):
            return (datetime.datetime.utcnow() - creation).days
        return None
    except Exception:
        return None

def check_blacklist_entry(url, domain):
    feed = fetch_blacklist()
    if not feed:
        return {"listed": False, "reason": "Blacklist feed unavailable"}
    if url in feed:
        return {"listed": True, "reason": "Exact URL in OpenPhish feed"}
    if domain in feed:
        return {"listed": True, "reason": "Domain appears in OpenPhish feed"}
    return {"listed": False, "reason": "Not listed"}

def fuzzy_brand_similarity(sld):
    s = sld.lower()
    suspicious_matches = []
    for brand in KNOWN_BRANDS:
        ratio = difflib.SequenceMatcher(None, s, brand).ratio()
        if ratio >= 0.8 and s != brand:
            suspicious_matches.append({"brand": brand, "similarity": round(ratio, 2)})
    return suspicious_matches

def check_url_patterns(url, domain):
    reasons = []
    if "@" in url:
        reasons.append("Contains '@' symbol (often used to hide real destination).")
    if re.match(r"^\d{1,3}(\.\d{1,3}){3}$", domain):
        reasons.append("Uses IP address instead of a domain.")
    if "-" in domain:
        reasons.append("Hyphenated domain (commonly used in phishing typosquatting).")
    digits = sum(c.isdigit() for c in domain)
    if digits >= 3:
        reasons.append("Many digits in domain (suspicious).")
    suspicious_keywords = ["login", "verify", "update", "secure", "bank", "confirm", "account", "signin", "reset", "password"]
    if any(kw in url.lower() for kw in suspicious_keywords):
        reasons.append("Contains suspicious keywords often used in phishing.")
    if domain.count(".") > 3:
        reasons.append("Too many subdomains (attempt to mask real domain).")
    if len(url) > 90:
        reasons.append("URL is unusually long.")
    if any(len(seg) > 25 for seg in domain.split(".")):
        reasons.append("Very long domain segment (suspicious).")
    return reasons

def detect_shortener(domain, original, final):
    shortener = domain in SHORTENER_DOMAINS
    redirected = (original != final)
    return {"shortener_detected": shortener, "redirected": redirected}

def compute_risk_score(signals):
    score = 0
    reasons = []
    if signals.get("blacklist"):
        score += 70
        reasons.append("Listed on phishing blacklist.")
    ssl = signals.get("ssl", {})
    if not ssl.get("valid", False):
        score += 20
        reasons.append("Invalid/missing SSL.")
    patterns = signals.get("patterns", [])
    if patterns:
        score += 10 * len(patterns)
        reasons.append(f"{len(patterns)} heuristic pattern(s) flagged.")
    if signals.get("redirects", 0) > 2:
        score += 10
        reasons.append("Many redirects.")
    age = signals.get("domain_age_days")
    if isinstance(age, int) and age >= 0 and age < 30:
        score += 20
        reasons.append("Very recently created domain.")
    if signals.get("fuzzy_brand"):
        score += 25
        reasons.append("Domain looks similar to a major brand (possible typosquat).")
    if signals.get("shortener", {}).get("shortener_detected"):
        score += 15
        reasons.append("Known shortener used.")
    if signals.get("shortener", {}).get("redirected"):
        score += 10
        reasons.append("Redirect detected.")
    score = min(score, 100)
    if score >= 60:
        level = "HIGH"
    elif score >= 30:
        level = "MEDIUM"
    else:
        level = "LOW"
    return {"score": score, "level": level, "summary_reasons": reasons}

# Flask route
@app.route("/check_url", methods=["POST"])
def check_url_route():
    payload = request.get_json(silent=True)
    if not payload or "url" not in payload:
        return jsonify({"error": "No URL provided in JSON body (key: 'url')"}), 400

    raw_url = payload["url"]
    url = normalize_url(raw_url)

    final_url, redirects = expand_url(url)
    domain = extract_domain(final_url)
    sld = get_sld(domain)

    blacklist_info = check_blacklist_entry(final_url, domain)
    ssl_info = check_ssl_certificate(domain)
    patterns = check_url_patterns(final_url, domain)
    fuzzy = fuzzy_brand_similarity(sld)
    domain_age = whois_age_days(domain) if WHOIS_AVAILABLE else None
    shortener = detect_shortener(domain, raw_url, final_url)

    signals = {
        "blacklist": blacklist_info.get("listed", False),
        "blacklist_reason": blacklist_info.get("reason"),
        "ssl": ssl_info,
        "patterns": patterns,
        "redirects": redirects,
        "fuzzy_brand": fuzzy,
        "domain_age_days": domain_age,
        "shortener": shortener
    }

    risk = compute_risk_score(signals)

    # ML Prediction if available
    ml_prediction = None
    ml_probability = None

    if ml_tfidf is not None and ml_clf is not None:
        try:
            url_for_model = re.sub(r"^https?://", "", final_url.strip().lower()).rstrip('/')
            X_tfidf = ml_tfidf.transform([url_for_model])

            def numeric_features_from_url_single(u):
                if u is None:
                    return [0, 0, 0, 0, 0, 0, 0]
                u = str(u)
                url_clean = re.sub(r"^https?://", "", u.strip().lower())
                domain_local = url_clean.split("/")[0] if "/" in url_clean else url_clean
                url_len = len(u)
                num_dots = u.count(".")
                num_hyphens = u.count("-")
                num_digits = sum(c.isdigit() for c in u)
                has_ip = 1 if re.match(r"^\d{1,3}(\.\d{1,3}){3}$", domain_local) else 0
                has_at = 1 if "@" in u else 0
                num_slashes = u.count("/")
                return [url_len, num_dots, num_hyphens, num_digits, has_ip, has_at, num_slashes]

            import numpy as np
            from scipy.sparse import csr_matrix, hstack

            X_num = np.array([numeric_features_from_url_single(final_url)])
            X_combined = hstack([X_tfidf, csr_matrix(X_num)], format="csr")

            try:
                ml_probability = float(ml_clf.predict_proba(X_combined)[0][1])
                ml_prediction = "Phishing" if ml_probability > 0.5 else "Legitimate"
            except AttributeError:
                pred = ml_clf.predict(X_combined)[0]
                ml_probability = None
                ml_prediction = "Phishing" if pred == 1 else "Legitimate"
        except Exception as e:
            ml_prediction = f"Error during ML evaluation: {e}"
            ml_probability = None

    response = {
        "original_url": raw_url,
        "final_url": final_url,
        "domain": domain,
        "sld": sld,
        "blacklist": blacklist_info,
        "ssl": ssl_info,
        "patterns": patterns,
        "redirects": redirects,
        "fuzzy_brand_similarity": fuzzy,
        "domain_age_days": domain_age,
        "shortener_info": shortener,
        "risk_score": risk["score"],
        "risk_level": risk["level"],
        "risk_reasons": risk["summary_reasons"],
        "ml_prediction": ml_prediction,
        "ml_probability": round(float(ml_probability), 3) if ml_probability is not None else None,
    }

    try:
        heur_score = risk["score"] / 100.0
        ml_score = ml_probability if ml_probability is not None else 0.0
        combined = 0.5 * heur_score + 0.5 * ml_score
        response["combined_score"] = int(combined * 100)
        response["combined_level"] = (
            "HIGH" if response["combined_score"] >= 60
            else "MEDIUM" if response["combined_score"] >= 30
            else "LOW"
        )
    except Exception:
        response["combined_score"] = response["risk_score"]
        response["combined_level"] = response["risk_level"]

    return jsonify(response), 200


if __name__ == "__main__":
    app.run(debug=True)
