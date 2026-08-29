import re
from urllib.parse import urlparse

def check_for_ip(url):
    # Regex pattern to detect a standard IPv4 address (e.g., 192.168.1.1)
    # It looks for four sets of 1 to 3 digits, separated by periods.
    ip_pattern = r'\b(?:\d{1,3}\.){3}\d{1,3}\b'
    if re.search(ip_pattern, url):
        return 1
    return 0

def count_suspicious_words(url):
    # A core list of keywords phishers rely on to create a false sense of urgency or legitimacy
    red_flag_words = ['login', 'verify', 'update', 'account', 'secure', 'paypal', 'banking', 'auth', 'confirm']
    
    count = 0
    url_lower = url.lower()
    for word in red_flag_words:
        if word in url_lower:
            count += 1
    return count

def extract_url_features(url):
    parsed = urlparse(url)
    
    # Feature extraction logic
    length = len(url)
    has_https = 1 if url.startswith('https://') else 0
    uses_ip = check_for_ip(url)
    suspicious_words = count_suspicious_words(url)
    
    # Subdomain count calculation
    subdomains = parsed.netloc.split('.')
    subdomain_count = len(subdomains) - 2 if len(subdomains) > 2 else 0

    return {
        'url_length': length,
        'has_https': has_https,
        'uses_ip': uses_ip,
        'suspicious_word_count': suspicious_words,
        'domain_length': len(parsed.netloc),
        'path_length': len(parsed.path),
        'count_dots': url.count('.'),
        'count_hyphens': url.count('-'),
        'count_slash': url.count('/'),
        'has_at_symbol': 1 if '@' in url else 0,
        'subdomain_count': subdomain_count,
        'num_digits': sum(c.isdigit() for c in url)
    }