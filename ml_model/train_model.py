import os
import re
import numpy as np
import pandas as pd
from scipy.sparse import hstack, csr_matrix
from sklearn.model_selection import train_test_split
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import classification_report, roc_auc_score, confusion_matrix
import joblib
from xgboost import XGBClassifier

from custom_transformers import FeatureUnionTransformer

def normalize_url_text(url):
    if not isinstance(url, str):
        return ""
    url = url.strip().lower()
    url = re.sub(r"^https?://", "", url)
    if url.endswith("/"):
        url = url[:-1]
    return url

def numeric_features_from_url(urls):
    out = []
    for u in urls:
        u = "" if pd.isna(u) else str(u)
        s = normalize_url_text(u)
        domain = s.split("/")[0] if "/" in s else s
        url_len = len(u)
        num_dots = u.count(".")
        num_hyphens = u.count("-")
        num_digits = sum(c.isdigit() for c in u)
        has_ip = 1 if re.match(r"^\d{1,3}(\.\d{1,3}){3}$", domain) else 0
        has_at = 1 if "@" in u else 0
        num_slashes = u.count("/")
        has_https = 1 if u.startswith("https://") else 0
        contains_login = 1 if "login" in u else 0
        contains_verify = 1 if "verify" in u else 0
        contains_bank = 1 if "bank" in u else 0
        contains_secure = 1 if "secure" in u else 0
        features = [url_len, num_dots, num_hyphens, num_digits, has_ip, has_at, num_slashes,
        has_https, contains_login, contains_verify, contains_bank, contains_secure]
        features = [url_len, num_dots, num_hyphens, num_digits, has_ip, has_at, num_slashes]
        out.append(features)
    return np.array(out)

# Load dataset
print("Loading dataset urls.csv ...")
df = pd.read_csv("urls.csv", encoding="latin1").dropna(subset=["url", "label"])
df['label_bin'] = df['label'].astype(str).str.lower().map(
    lambda x: 1 if x.startswith('phish') or x in ['malicious', '1', 'phishing'] else 0
)
df['url_norm'] = df['url'].apply(normalize_url_text)

X_text = df['url_norm'].values.reshape(-1, 1)
y = df['label_bin'].values

# Split train/test
X_train, X_test, y_train, y_test = train_test_split(
    X_text, y, test_size=0.2, random_state=42, stratify=y
)

# Build TF-IDF and transformer
tfidf = TfidfVectorizer(analyzer='char_wb', ngram_range=(3,5), max_features=2000)
feature_union = FeatureUnionTransformer(tfidf_vectorizer=tfidf)

print("Fitting TF-IDF...")
tfidf.fit(X_train.ravel())
X_train_tfidf = tfidf.transform(X_train.ravel())
X_test_tfidf = tfidf.transform(X_test.ravel())

print("Building numeric features...")
X_train_num = numeric_features_from_url(X_train.ravel())
X_test_num = numeric_features_from_url(X_test.ravel())

X_train_combined = hstack([X_train_tfidf, csr_matrix(X_train_num)], format='csr')
X_test_combined = hstack([X_test_tfidf, csr_matrix(X_test_num)], format='csr')

print("Training classifier (Logistic Regression)...")
clf = XGBClassifier(
    n_estimators=300,
    learning_rate=0.1,
    max_depth=6,
    subsample=0.9,
    colsample_bytree=0.9,
    objective='binary:logistic',
    eval_metric='logloss',
    use_label_encoder=False,
    n_jobs=-1
)

print("Training XGBoost classifier...")
clf.fit(X_train_combined.toarray(), y_train)

print("Evaluating...")
y_pred = clf.predict(X_test_combined)
y_proba = clf.predict_proba(X_test_combined)[:, 1]
print(classification_report(y_test, y_pred))
try:
    print("ROC AUC:", roc_auc_score(y_test, y_proba))
except Exception:
    pass
print("Confusion matrix:\n", confusion_matrix(y_test, y_pred))

# Save model artifacts
os.makedirs("ml_model", exist_ok=True)
model_artifact_path = os.path.join("ml_model", "phish_model_artifacts.pkl")
print(f"Saving model artifacts to {model_artifact_path} ...")
joblib.dump((tfidf, clf), model_artifact_path)
print("Saved model artifacts.")
