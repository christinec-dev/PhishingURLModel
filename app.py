import streamlit as st
import joblib
import tldextract
import numpy as np
import requests
import whois
import ipaddress
import socket
import re
from datetime import datetime
from urllib.parse import urlparse
import dns.resolver
from dotenv import load_dotenv
import os
import virustotal_python
from base64 import urlsafe_b64encode

# Add this at the beginning of your script or function
load_dotenv()

# Load model and scaler
model = joblib.load('phishing_model.pkl')
scaler = joblib.load('scaler.pkl')
load_dotenv()

# List of high-risk TLDs and abused platforms
HIGH_RISK_TLDS = ['xyz', 'top', 'club', 'site', 'online', 'rest', 'icu']
ABUSED_PLATFORMS = [
    'webflow', 'wixsite', 'wordpress', 'weebly', 'google', 'microsoft',
    'sites.google', 'docs.google', 'drive.google', 'forms.google', 
    'sharepoint', 'onedrive', 'office', 'bit.ly', 'tinyurl'
]
SUSPICIOUS_PATTERNS = r'\d{6,}|[a-z]{2,}\d{3,}|\d+[a-z]+\d+'

# Check url using virustotal
def check_url_with_virustotal(url):
    """Check if URL already exists on VirusTotal (do NOT submit if missing)"""
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
    """Extract all required features for the model"""
    # Basic URL properties
    parsed = urlparse(url)
    domain = parsed.netloc.split(':')[0]
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
    n_dots = url.count('.')
    n_hypens = url.count('-')
    
    # SSL check
    has_ssl = int(url.startswith('https'))
    
    # Advanced features
    cloudflare_protected = int(is_using_cloudflare(url))
    digit_count = sum(c.isdigit() for c in url)
    redirects = get_redirection_count(url)
    has_redirects = int(redirects > 0)
    
    # Calculate derived features
    dots_per_length = n_dots / (url_length + 1e-10)
    hyphens_per_length = n_hypens / (url_length + 1e-10)
    is_long_url = int(url_length > 75)
    has_many_dots = int(n_dots > 4)
    
    # Special character density
    special_chars = (n_slash + n_questionmark + n_equal + n_at + n_and +
                    n_exclamation + n_asterisk + n_hastag + n_percent +
                    n_dots + n_hypens)
    special_char_density = special_chars / (url_length + 1e-10)
    
    # TLD risk
    tld = tld_extract.suffix
    suspicious_tld_risk = 0
    if tld in HIGH_RISK_TLDS:
        suspicious_tld_risk += 2
    if any(platform in domain.lower() for platform in ABUSED_PLATFORMS):
        suspicious_tld_risk += 1
    if re.search(SUSPICIOUS_PATTERNS, domain):
        suspicious_tld_risk += 1
    
    # Risk score calculation
    risk_score = (
        is_long_url * 2 +
        has_many_dots * 1.5 +
        special_char_density * 10 +
        has_redirects * 3 -
        has_ssl * 2 -
        cloudflare_protected * 2 +
        suspicious_tld_risk * 1.5
    )
    
    # URL complexity score
    url_complexity = (
        url_length * 0.01 +
        n_dots * 0.5 +
        n_hypens * 0.3 +
        n_questionmark * 0.7 +
        n_equal * 0.7 +
        n_at * 2
    )
    
    # Assemble final feature vector (matching your model's expected features)
    features = [
        url_length, n_slash, n_questionmark, n_equal, n_at, n_and,
        n_exclamation, n_asterisk, n_hastag, n_percent,
        dots_per_length, hyphens_per_length, is_long_url, has_many_dots,
        has_ssl, cloudflare_protected, digit_count,
        special_char_density, suspicious_tld_risk, has_redirects,
        risk_score, url_complexity
    ]
    return features, domain_name

def get_redirection_count(url):
    """Check number of redirects with timeout protection"""
    count = 0
    try:
        for _ in range(5):  # Max 5 redirects to avoid timeouts
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
    """Check if site is protected by Cloudflare"""
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
    """Get domain age in days"""
    try:
        domain_info = whois.whois(domain)
        creation_date = domain_info.creation_date
        if isinstance(creation_date, list):
            creation_date = creation_date[0]
        return (datetime.now() - creation_date).days
    except:
        return None

def is_ip_address(url):
    """Check if URL uses IP address instead of domain"""
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
        try:
            # Add http:// if missing
            if not url.startswith(('http://', 'https://')):
                url = 'http://' + url

            # Display analysis in progress
            with st.spinner("Analyzing URL..."):
                # Extract features
                features, domain = extract_features(url)
                # Get domain age for additional context
                domain_age = get_domain_age(domain)               
                # Scale features
                scaled_features = scaler.transform([features])              
                # Make prediction using model
                prediction = model.predict(scaled_features)[0]
                probabilities = model.predict_proba(scaled_features)[0]               
                # IP address check
                is_ip = is_ip_address(url)               
                # Calculate confidence and verdict
                confidence = np.max(probabilities)
                conf_threshold = 0.75 
                if confidence < conf_threshold:
                    verdict = "Unknown ❔"
                    verdict_message = "The model is not confident enough to classify this URL. Please review manually."
                    verdict_color = "yellow"
                elif prediction == 1:
                    verdict = "Phishing ⚠️"
                    verdict_message = "This URL shows characteristics commonly associated with phishing attempts."
                    verdict_color = "red"
                else:
                    verdict = "Legitimate ✔️"
                    verdict_message = "This URL appears to be legitimate based on our analysis."
                    verdict_color = "green"

            # Display results
            st.subheader("Analysis Results:")
            col1, col2 = st.columns(2)
            with col1:
                st.write(f"**Domain:** {domain}")
                st.write(f"**SSL Enabled:** {'✅' if url.startswith('https') else '❌'}")
                st.write(f"**Cloudflare Protected:** {'✅' if features[15] else '❌'}")
                if domain_age:
                    st.write(f"**Domain Age:** {domain_age} days")
                else:
                    st.write("**Domain Age:** Unknown")
                st.write(f"**Confidence:** {confidence*100:.1f}%")
                st.write(f"**Verdict:** {verdict}")
                if verdict == "Unknown ❔":
                    st.info(verdict_message)
                elif verdict_color == "red":
                    st.error(verdict_message)
                else:
                    st.success(verdict_message)
            with col2:
                st.write("**Feature Highlights:**")
                st.write(f"URL Length: {features[0]}")
                st.write(f"Special Characters: {sum(features[1:10])}")
                st.write(f"Digit Count: {features[16]}")
                st.write(f"Risk Score: {features[20]:.2f}")
            
            # Show risk factors
            risk_factors = []
            if is_ip:
                risk_factors.append("URL contains IP address instead of domain name")
            if features[18] > 0:  # suspicious_tld_risk
                risk_factors.append("Domain uses a high-risk TLD or suspicious platform")
            if features[19]:  # has_redirects
                risk_factors.append("URL contains redirects")
            if features[12]:  # is_long_url
                risk_factors.append("Unusually long URL")
            if features[16] > 5:  # digit_count
                risk_factors.append("URL contains many numeric characters")
            if not features[14]:  # has_ssl
                risk_factors.append("No SSL/HTTPS protection")
            
            if risk_factors:
                st.subheader("Risk Factors:")
                for factor in risk_factors:
                    st.warning(factor)
            
            # Show VirusTotal results
            vt_results = check_url_with_virustotal(url)
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
                    risk_factors.append(f"URL flagged by {vt_results['malicious']} security vendors on VirusTotal")
        except Exception as e:
            st.error(f"Error analyzing URL: {str(e)}")
    else:
        st.warning("Please enter a URL to analyze")