import streamlit as st
import joblib
import tldextract
import numpy as np
import requests
import whois
import ipaddress
import socket
import re
import math
from datetime import datetime
from urllib.parse import urlparse
import dns.resolver
from dotenv import load_dotenv
import os
import virustotal_python
from base64 import urlsafe_b64encode
import diskcache as dc
import pandas as pd

# Load environment variables
load_dotenv()

# Initialize cache
cache = dc.Cache('./cache')

# Load model and scaler
model = joblib.load('phishing_model.pkl')
scaler = joblib.load('scaler.pkl')

# Filepath for the dataset
DATASET_FILE = './data/final_data.csv'

# Legit domains
LEGIT_DOMAINS_FILE = './data/legit_domains.txt'
def load_legit_domains(filepath):
    try:
        with open(filepath, 'r') as f:
            return set(line.strip().lower().replace('https://', '').replace('http://', '') for line in f if line.strip())
    except Exception:
        return set()
LEGIT_DOMAINS = load_legit_domains(LEGIT_DOMAINS_FILE)

def is_legit_domain(domain):
    return domain.lower() in LEGIT_DOMAINS

# List of high-risk TLDs and abused platforms
HIGH_RISK_TLDS = [
    'xyz', 'top', 'club', 'site', 'online', 'rest', 'icu', 'work', 'click', 'fit', 'gq', 'tk', 'ml', 'cf', 'ga',
    'men', 'loan', 'download', 'stream', 'party', 'cam', 'win', 'bid', 'review', 'trade', 'accountant', 'science',
    'date', 'faith', 'racing', 'zip', 'cricket', 'host', 'press', 'space', 'pw', 'buzz', 'mom', 'bar', 'uno',
    'kim', 'country', 'support', 'webcam', 'rocks', 'info', 'biz', 'pro', 'link', 'pics', 'help', 'ooo',
    'asia', 'today', 'live', 'lol', 'surf', 'fun', 'run', 'cyou', 'monster', 'store'
]
SUSPICIOUS_PATTERNS = r'\d{6,}|[a-z]{2,}\d{3,}|\d+[a-z]+\d+'

def domain_entropy(domain):
    """Calculate Shannon entropy of the domain part."""
    prob = [float(domain.count(c)) / len(domain) for c in set(domain)]
    return -sum([p * math.log(p, 2) for p in prob])

def cache_analysis_results(url, analysis_results):
    cache[url] = analysis_results

def get_cached_analysis_results(url):
    return cache.get(url)

def cache_virustotal_results(url, vt_results):
    cache[f"vt_{url}"] = vt_results

def get_cached_virustotal_results(url):
    return cache.get(f"vt_{url}")

def check_url_with_virustotal(url):
    api_key = os.environ.get("VT_API_KEY")
    if not api_key:
        return {"error": "VirusTotal API key not configured"}
    with virustotal_python.Virustotal(api_key) as vtotal:
        url_id = urlsafe_b64encode(url.encode()).decode().strip("=")
        try:
            report = vtotal.request(f"urls/{url_id}")
            data = report.json()
            if "data" in data:
                stats = data["data"]["attributes"]["last_analysis_stats"]
                return {
                    "found": True,
                    "malicious": stats.get("malicious", 0),
                    "suspicious": stats.get("suspicious", 0),
                    "total_scans": sum(stats.values()),
                    "scan_date": data["data"]["attributes"].get("last_analysis_date")
                }
            else:
                return {"found": False, "message": "URL not found in VirusTotal database"}
        except Exception as e:
            if hasattr(e, "response") and e.response is not None and e.response.status_code == 404:
                return {"found": False, "message": "URL not found in VirusTotal database"}
            else:
                return {"error": str(e)}

def extract_features(url):
    parsed = urlparse(url)
    domain = parsed.netloc.split(':')[0].replace('www.', '')
    tld_extract = tldextract.extract(url)
    domain_name = f"{tld_extract.domain}.{tld_extract.suffix}"
    # Extract all basic character counts
    url_length = len(url)
    n_slash = url.count('/')
    n_questionmark = url.count('?')
    n_equal = url.count('=')
    n_at = url.count('@')
    n_and = url.count('&')
    n_exclamation = url.count('!')
    n_asterisk = url.count('*')
    n_hastag = url.count('#')
    n_percent = url.count('%')
    dots_per_length = url.count('.') / (url_length + 1)
    hyphens_per_length = url.count('-') / (url_length + 1)
    is_long_url = 1 if url_length > 200 else 0
    has_many_dots = 1 if url.count('.') > 4 else 0
    special_char_density = (
        n_slash + n_questionmark + n_equal + n_at + n_and +
        n_exclamation + n_asterisk + n_hastag + n_percent
    ) / (url_length + 1)
    has_ssl = 1 if url.startswith('https') else 0
    is_cloudflare_protected = is_using_cloudflare(url)
    suspicious_tld_risk = 1 if tld_extract.suffix in HIGH_RISK_TLDS else 0
    n_redirection = get_redirection_count(url)
    domain_age = get_domain_age(domain_name) or 0
    risk_score = (
        is_long_url * 2 +
        has_many_dots * 1.5 +
        special_char_density * 2 +
        n_redirection * 3 -
        has_ssl * 2 -
        is_cloudflare_protected * 5 -
        (domain_age / 365)
    )
    url_complexity = (
        url_length * 0.01 +
        n_slash * 0.5 +
        n_questionmark * 0.7 +
        n_equal * 0.7 +
        n_at * 2
    )
    features = [
        url_length, n_slash, n_questionmark, n_equal, n_at, n_and,
        n_exclamation, n_asterisk, n_hastag, n_percent,
        dots_per_length, hyphens_per_length, is_long_url, has_many_dots,
        has_ssl, is_cloudflare_protected, special_char_density,
        suspicious_tld_risk, n_redirection, risk_score, url_complexity
    ]
    return features, domain_name

def get_redirection_count(url):
    count = 0
    try:
        for _ in range(5):
            response = requests.head(
                url,
                allow_redirects=False,
                timeout=3,
                headers={'User-Agent': 'Mozilla/5.0'}
            )
            if 300 <= response.status_code < 400:
                url = response.headers.get('Location', url)
                count += 1
            else:
                break
    except Exception:
        pass
    return count

def is_using_cloudflare(url):
    try:
        response = requests.head(url, timeout=3)
        headers = response.headers
        return (
            headers.get('Server', '').startswith('cloudflare') or
            'CF-RAY' in headers or
            'CF-Cache-Status' in headers
        )
    except:
        return False

def get_domain_age(domain):
    try:
        domain_info = whois.whois(domain)
        creation_date = domain_info.creation_date
        if isinstance(creation_date, list):
            creation_date = creation_date[0]
        return (datetime.now() - creation_date).days
    except:
        return None

def is_ip_address(url):
    try:
        parsed = urlparse(url)
        netloc = parsed.netloc.split(':')[0]
        ipaddress.ip_address(netloc)
        return True
    except:
        return False

# Streamlit UI
st.title('Phishing URL Detector')
st.write("Check if a website URL is legitimate, or a phishing attempt.")
url = st.text_input("Enter URL to analyze:", placeholder="https://example.com")

if st.button("Analyze URL"):
    if url:
        url = url.strip()
        try:
            if not url.startswith(('http://', 'https://')):
                url = 'http://' + url

            cached_results = get_cached_analysis_results(url)
            if cached_results:
                st.info("Loaded results from cache.")
                analysis_results, vt_results = cached_results
            else:
                with st.spinner("Analyzing URL..."):
                    features, domain = extract_features(url)
                    domain_age = get_domain_age(domain)
                    scaled_features = scaler.transform([features])
                    prediction = model.predict(scaled_features)[0]
                    probabilities = model.predict_proba(scaled_features)[0]
                    is_ip = is_ip_address(url)
                    confidence = np.max(probabilities)
                    conf_threshold = 0.6

                    # Boost confidence if domain is in legit_domains.txt
                    if is_legit_domain(domain):
                        confidence = min(confidence + 0.5, 1.0)

                    vt_results = get_cached_virustotal_results(url)
                    if not vt_results:
                        vt_results = check_url_with_virustotal(url)
                        cache_virustotal_results(url, vt_results)

                    if confidence < conf_threshold:
                        if vt_results and vt_results.get("found", False):
                            if vt_results.get("malicious", 0) > 0 or vt_results.get("suspicious", 0) > 0:
                                verdict = "Phishing ⚠️"
                                verdict_message = "VirusTotal flagged this URL as malicious or suspicious."
                                verdict_color = "red"
                            else:
                                verdict = "Likely Legitimate ✔️"
                                verdict_message = "VirusTotal found no issues, but model is not entirely confident."
                                verdict_color = "green"
                        else:
                            verdict = "Unknown ❔"
                            verdict_message = "There is not enough data to analyse. The model is not entirely confident and VirusTotal has no report."
                            verdict_color = "yellow"
                    elif prediction == 1:
                        verdict = "Phishing ⚠️"
                        verdict_message = "This URL shows characteristics commonly associated with phishing attempts."
                        verdict_color = "red"
                    else:
                        verdict = "Legitimate ✔️"
                        verdict_message = "This URL appears to be legitimate based on the analysis."
                        verdict_color = "green"

                    analysis_results = {
                        "features": features,
                        "domain": domain,
                        "domain_age": domain_age,
                        "confidence": confidence,
                        "verdict": verdict,
                        "verdict_message": verdict_message,
                        "verdict_color": verdict_color,
                        "is_ip": is_ip
                    }
                    cache_analysis_results(url, (analysis_results, vt_results))

            # Save to dataset
            try:
                def to_int_bool(val):
                    if isinstance(val, bool):
                        return int(val)
                    return val

                new_data = {
                    "url_length": analysis_results["features"][0],
                    "n_slash": analysis_results["features"][1],
                    "n_questionmark": analysis_results["features"][2],
                    "n_equal": analysis_results["features"][3],
                    "n_at": analysis_results["features"][4],
                    "n_and": analysis_results["features"][5],
                    "n_exclamation": analysis_results["features"][6],
                    "n_asterisk": analysis_results["features"][7],
                    "n_hastag": analysis_results["features"][8],
                    "n_percent": analysis_results["features"][9],
                    "dots_per_length": analysis_results["features"][10],
                    "hyphens_per_length": analysis_results["features"][11],
                    "is_long_url": to_int_bool(analysis_results["features"][12]),
                    "has_many_dots": to_int_bool(analysis_results["features"][13]),
                    "has_ssl": to_int_bool(analysis_results["features"][14]),
                    "is_cloudflare_protected": to_int_bool(analysis_results["features"][15]),
                    "special_char_density": analysis_results["features"][16],
                    "suspicious_tld_risk": analysis_results["features"][17],
                    "n_redirection": analysis_results["features"][18],
                    "risk_score": analysis_results["features"][19],
                    "url_complexity": analysis_results["features"][20],
                    "phishing": 1 if analysis_results["verdict"] == "Phishing ⚠️" else 0
                }
                new_data_df = pd.DataFrame([new_data])
                if not os.path.exists(DATASET_FILE):
                    new_data_df.to_csv(DATASET_FILE, index=False)
                else:
                    new_data_df.to_csv(DATASET_FILE, mode='a', header=False, index=False)
                st.success("Scanned data has been saved to the dataset.")
            except Exception as e:
                st.error(f"Error saving data to dataset: {str(e)}")

            # Display results
            analysis_results, vt_results = cached_results or (analysis_results, vt_results)
            st.subheader("Analysis Results:")
            col1, col2 = st.columns(2)
            with col1:
                st.write(f"**Domain:** {analysis_results['domain']}")
                st.write(f"**SSL Enabled:** {'✅' if url.startswith('https') else '❌'}")
                st.write(f"**Cloudflare Protected:** {'✅' if analysis_results['features'][15] else '❌'}")
                if analysis_results['domain_age']:
                    st.write(f"**Domain Age:** {analysis_results['domain_age']} days")
                else:
                    st.write("**Domain Age:** Unknown")
                st.write(f"**Confidence:** {analysis_results['confidence']*100:.1f}%")
                st.write(f"**Verdict:** {analysis_results['verdict']}")
            with col2:
                st.write("**Feature Highlights:**")
                st.write(f"URL Length: {analysis_results['features'][0]}")
                st.write(f"Special Characters: {sum(analysis_results['features'][1:9])}")
                st.write(f"Risk Score: {analysis_results['features'][20]:.2f}")

            # Verdict
            if is_legit_domain(analysis_results['domain']):
                st.success("This domain was found in the trusted (legit) domains list.")
            if analysis_results['verdict'] == "Unknown ❔":
                st.info(analysis_results['verdict_message'])
            elif analysis_results['verdict_color'] == "red":
                st.error(analysis_results['verdict_message'])
            else:
                st.success(analysis_results['verdict_message'])

            # Show risk factors
            risk_factors = []
            if analysis_results['is_ip']:
                risk_factors.append("URL contains IP address instead of domain name")
            if analysis_results['features'][18] > 0:  # suspicious_tld_risk
                risk_factors.append("Domain uses a high-risk TLD or suspicious platform")
            if analysis_results['features'][19]:  # n_redirection
                risk_factors.append("URL contains redirects")
            if analysis_results['features'][12]:  # is_long_url
                risk_factors.append("Unusually long URL")
            if analysis_results['features'][17] > 0.05:  # special_char_density
                risk_factors.append("URL contains a high density of special characters")
            if not analysis_results['features'][14]:  # has_ssl
                risk_factors.append("No SSL/HTTPS protection")

            if risk_factors:
                st.subheader("Risk Factors:")
                for factor in risk_factors:
                    st.warning(factor)

            # Show VirusTotal results
            st.subheader("VirusTotal Analysis:")
            if "error" in vt_results:
                st.warning(f"VirusTotal check failed: {vt_results['error']}")
            elif not vt_results.get("found", False):
                st.info("URL not found in VirusTotal database. No report available.")
            else:
                st.write(f"**Malicious Detections:** {vt_results['malicious']}/{vt_results['total_scans']}")
                st.write(f"**Suspicious Detections:** {vt_results['suspicious']}")
                st.write(f"**Last Scan Date:** {vt_results['scan_date']}")
                if vt_results['malicious'] > 0:
                    st.warning(f"URL flagged by {vt_results['malicious']} security vendors on VirusTotal")
        except Exception as e:
            st.error(f"Error analyzing URL: {str(e)}")
    else:
        st.warning("Please enter a URL to analyze")