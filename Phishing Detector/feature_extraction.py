import pandas as pd
import whois
import time
from datetime import datetime
from urllib.parse import urlparse
import requests
from bs4 import BeautifulSoup
import pathlib
import re
from difflib import SequenceMatcher

# WHOIS cache to avoid repeated lookups
whois_cache = {}

# -----------------------------
# Utility Functions
# -----------------------------

def normalize(domain):
    replacements = {
        '0': 'o', '1': 'l', '3': 'e', '5': 's', '7': 't', '8': 'b'
    }
    return ''.join(replacements.get(c, c) for c in domain)

def similar(a, b):
    return SequenceMatcher(None, a, b).ratio()

# -----------------------------
# Feature Extraction Functions
# -----------------------------

def get_url_length(url):
    return len(url)

def has_ssl(url):
    return 1 if url.lower().startswith("https") else 0

def contains_suspicious_keywords(url):
    keywords = ['login', 'verify', 'secure', 'account', 'update', 'bank']
    return int(any(keyword in url.lower() for keyword in keywords))

def get_domain_age(url):
    domain = urlparse(url).netloc.split(':')[0]

    if domain in whois_cache:
        return whois_cache[domain]

    if domain.endswith('blogspot.com') or domain.count('.') > 2:
        whois_cache[domain] = -1
        return -1

    try:
        time.sleep(1)
        w = whois.whois(domain)
        creation = w.creation_date

        if isinstance(creation, list):
            creation = creation[0]
        if creation is None:
            whois_cache[domain] = -1
            return -1

        if isinstance(creation, datetime):
            age_days = (datetime.now() - creation).days
            whois_cache[domain] = age_days
            return age_days

        whois_cache[domain] = -1
        return -1

    except Exception as e:
        print(f"WHOIS error for domain {domain}: {e}")
        whois_cache[domain] = -1
        return -1

# -----------------------------
# Pattern + Impersonation Detection
# -----------------------------

def analyze_url(url):
    domain = urlparse(url).netloc.lower()
    main_domain = domain.split('.')[-2] if '.' in domain else domain
    normalized = normalize(main_domain)

    # Check against known brands
    known_brands = [
    'microsoft', 'paypal', 'google', 'apple', 'amazon', 'linkedin',
    'facebook', 'instagram', 'twitter', 'tiktok', 'netflix',
    'whatsapp', 'youtube', 'icloud', 'gmail', 'outlook',
    'bankofamerica', 'wellsfargo', 'chase', 'citibank', 'capitalone',
    'hdfc', 'icici', 'sbi', 'axisbank', 'kotak',
    'flipkart', 'snapdeal', 'myntra', 'olx', 'ebay',
    'github', 'gitlab', 'dropbox', 'adobe', 'zoom',
    'spotify', 'airbnb', 'uber', 'zomato', 'swiggy',
    'paypal', 'venmo', 'revolut', 'stripe', 'binance',
    'telegram', 'discord', 'skype', 'yahoo', 'protonmail',
    'pinterest', 'quora', 'reddit', 'booking', 'expedia'
]

    for brand in known_brands:
        sim = similar(normalized, brand)
        if sim > 0.75 and brand not in main_domain:
            print(f" Impersonation detected: {main_domain} → {brand} (score: {sim:.2f})")
            return "impersonation"

    # Regex-based patterns
    patterns = [
        r"@", r"-\w*\.com", r"\d", r"^\d{1,3}(\.\d{1,3}){3}$",
        r"(?:https?:\/\/)?(?:www\.)?\d+\.\d+\.\d+\.\d+"
    ]

    shortening_services = ['bit.ly', 'tinyurl.com', 'goo.gl', 't.co', 'bit.do', 'ow.ly']
    if any(service in domain for service in shortening_services):
        return "suspicious"

    if any(re.search(pattern, url) for pattern in patterns):
        return "suspicious"

    return "clean"

# -----------------------------
# Rule-Based Detection Logic
# -----------------------------

def is_suspicious_url(url, pattern_result=None):
    if pattern_result is None:
        pattern_result = analyze_url(url)

    if pattern_result == "impersonation":
        return True

    score = 0
    if get_url_length(url) > 150:
        score += 1
    if not has_ssl(url):
        score += 1
    if contains_suspicious_keywords(url):
        score += 1
    if pattern_result == "suspicious":
        score += 1

    domain_age = get_domain_age(url)
    if domain_age == -1 or domain_age < 30:
        score += 1

    try:
        response = requests.get(url, timeout=5)
        if response.status_code == 200:
            soup = BeautifulSoup(response.text, 'html.parser')
            if soup.find('form') and 'login' in soup.text.lower():
                score += 1
    except requests.exceptions.RequestException:
        score += 1

    return score >= 4

def classify_url(url):
    pattern_result = analyze_url(url)
    return 'phishing' if is_suspicious_url(url, pattern_result) else 'legitimate'

# -----------------------------
# Dataset Processing
# -----------------------------

def extract_features_from_dataset(file_path):
    try:
        df = pd.read_csv(file_path)

        df['url_length'] = df['url'].apply(get_url_length)
        df['has_ssl'] = df['url'].apply(has_ssl)
        df['suspicious_keywords'] = df['url'].apply(contains_suspicious_keywords)
        df['domain_age'] = df['url'].apply(get_domain_age)
        df['pattern_analysis'] = df['url'].apply(analyze_url)
        df['classification'] = df.apply(lambda row: classify_url(row['url']), axis=1)

        # Save all results
        output_file = pathlib.Path(file_path).parent / 'enhanced_dataset.csv'
        df.to_csv(output_file, index=False)

        # Save only legitimate sites
        legit_df = df[df['classification'] == 'legitimate']
        legit_file = pathlib.Path(file_path).parent / 'legitimate_sites.csv'
        legit_df.to_csv(legit_file, index=False)

        print(f"\n ✅ Dataset processing complete.")
        print(f"    - All results saved to: {output_file}")
        print(f"    - Legitimate sites saved to: {legit_file}\n")

    except FileNotFoundError:
        print("  File not found. Please check the path and try again.")
    except Exception as e:
        print(f"  Error processing dataset: {e}")


# -----------------------------
# Single URL Check
# -----------------------------

def check_url_features(url):
    print(f"\n====== URL ANALYSIS ======")
    pattern_result = analyze_url(url)

    result = {
        'URL': url,
        'URL Length': get_url_length(url),
        'Has SSL': has_ssl(url),
        'Contains Suspicious Keywords': contains_suspicious_keywords(url),
        'Pattern/Impersonation Result': pattern_result,
        'Domain Age (days)': get_domain_age(url),
        'Classification': 'phishing' if is_suspicious_url(url, pattern_result) else 'legitimate'
    }

    for key, value in result.items():
        print(f"{key}: {value}")
    print()

# -----------------------------
# Main Menu
# -----------------------------

def main():
    print("\n====== PHISHING DETECTOR TOOL ======")
    print("Choose an option:")
    print("1. Process URLs from a Dataset (CSV file)")
    print("2. Check a Single URL manually")

    choice = input("Enter 1 or 2: ").strip()

    if choice == '1':
        while True:
            file_path = input("Enter the path to the dataset CSV file: ").strip().strip('"')
            file_path = pathlib.Path(file_path)

            if file_path.exists():
                extract_features_from_dataset(str(file_path))
                break
            else:
                print("  File not found. Please try again.\n")

    elif choice == '2':
        url = input("Enter the URL to check: ").strip()
        check_url_features(url)

    else:
        print("  Invalid option. Please enter 1 or 2.")

# -----------------------------
# Entry Point
# -----------------------------

if __name__ == "__main__":
    main()
