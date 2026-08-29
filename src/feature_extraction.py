import pandas as pd
import re

def extract_url_features(url):
    features = {}
    features['url_length'] = len(url)
    features['has_at_symbol'] = 1 if '@' in url else 0
    features['has_ip'] = 1 if re.search(r'\d+\.\d+\.\d+\.\d+', url) else 0
    features['count_dots'] = url.count('.')
    features['count_hyphens'] = url.count('-')
    features['count_slash'] = url.count('/')
    features['has_https'] = 1 if url.startswith('https') else 0
    return features

if __name__ == "__main__":
    test_url = "http://br-icloud.com.br/phishing"
    print("Features extracted for test URL:")
    print(extract_url_features(test_url))