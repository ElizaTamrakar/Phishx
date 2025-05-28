import pickle
import os
import re
import socket
from urllib.parse import urlparse


# Load model once
MODEL_PATH = os.path.join(os.path.dirname(__file__), "phishing_model.pkl")
with open(MODEL_PATH, "rb") as f:
    model = pickle.load(f)

def extract_features(url):
    features = []
    parsed = urlparse(url)
    domain = parsed.netloc
    

    def having_ip_address():
        try:
            socket.inet_aton(domain)
            return -1
        except:
            return 1

    def url_length(url):
        if len(url) < 54:
            return -1
        elif 54 <= len(url) <= 75:
            return 0
        else:
            return 1
        
    def shortening_service(url):
        shorteners = r"bit\.ly|goo\.gl|tinyurl|ow\.ly|t\.co|bitly\.com|is\.gd|buff\.ly|adf\.ly"
        return -1 if re.search(shorteners, url) else 1

    def having_at_symbol(url):
        return -1 if "@" in url else 1

    def double_slash_redirecting(url):
        return -1 if url.count("//") > 1 else 1

    def prefix_suffix(domain):
        return -1 if "-" in domain else 1

    def having_sub_domain(domain):
        dots = domain.split(".")
        if len(dots) < 3:
            return -1
        elif len(dots) == 3:
            return 0
        else:
            return 1

    def ssl_final_state(url):
        return 1 if url.startswith("https") else -1

    def domain_registration_length():
        return 1  # placeholder — needs WHOIS (skip for now)

    def favicon(url):
        return 1  # placeholder

    def port(url):
        return -1  # placeholder

    def https_token(url):
        return -1 if "https" in urlparse(url).netloc else 1

    def request_url():
        return 1 # placeholder

    def url_of_anchor():
        return 0  # placeholder

    def links_in_tags():
        return 0  # placeholder

    def sfh():
        return 0  # placeholder

    def submitting_to_email():
        return -1  # placeholder

    def abnormal_url():
        return 1  # placeholder

    def redirect():
        return 0  # placeholder

    def on_mouseover():
        return -1  # placeholder

    def right_click():
        return -1  # placeholder

    def popupwindow():
        return 0  # placeholder

    def iframe():
        return -1  # placeholder

    def age_of_domain():
        return -1  # placeholder

    def dnsrecord():
        return 1  # placeholder

    def web_traffic():
        return 0  # placeholder

    def page_rank():
        return -1  # placeholder

    def google_index():
        return 1  # assume indexed

    def links_pointing_to_page():
        return 0  # placeholder

    def statistical_report():
        return -1  # placeholder

    # Now assemble all features in order
    features = [
        having_ip_address(),
        url_length(url),
        shortening_service(url),
        having_at_symbol(url),
        double_slash_redirecting(url),
        prefix_suffix(domain),
        having_sub_domain(domain),
        ssl_final_state(url),
        domain_registration_length(),
        favicon(url),
        port(url),
        https_token(url),
        request_url(),
        url_of_anchor(),
        links_in_tags(),
        sfh(),
        submitting_to_email(),
        abnormal_url(),
        redirect(),
        on_mouseover(),
        right_click(),
        popupwindow(),
        iframe(),
        age_of_domain(),
        dnsrecord(),
        web_traffic(),
        page_rank(),
        google_index(),
        links_pointing_to_page(),
        statistical_report()
    ]

    return features

def classify_url(url):
    features = [extract_features(url)]
    prediction = model.predict(features)[0]
    prob = model.predict_proba(features)[0]

    if prediction == -1:
        classification = "Phishing"
        risk_score = int(prob[0] * 100)  
    else:
        classification = "Safe"
        risk_score = int((1 - prob[1]) * 100)  

    return classification, risk_score

    