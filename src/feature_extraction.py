import ipaddress
import math
import re
from collections import Counter
from urllib.parse import urlparse, parse_qs, unquote
 
# Optional dependency: pip install tldextract  (much more accurate than the fallback)
try:
    import tldextract
    _extract = tldextract.TLDExtract(suffix_list_urls=())  # offline, bundled snapshot
except Exception:  # pragma: no cover
    _extract = None
 
# ---------------------------------------------------------------- constants
SUSPICIOUS_KEYWORDS = {
    'login', 'signin', 'sign-in', 'logon', 'verify', 'verification', 'update',
    'account', 'secure', 'security', 'banking', 'auth', 'authenticate',
    'confirm', 'password', 'passwd', 'credential', 'wallet', 'suspend',
    'unlock', 'recover', 'billing', 'invoice', 'payment', 'support', 'alert',
    'webscr', 'validate',
}
 
BRANDS = {
    'paypal', 'apple', 'microsoft', 'google', 'amazon', 'netflix', 'facebook',
    'instagram', 'whatsapp', 'linkedin', 'dropbox', 'adobe', 'ebay', 'chase',
    'wellsfargo', 'bankofamerica', 'citibank', 'hsbc', 'sbi', 'hdfc', 'icici',
    'outlook', 'office365', 'docusign', 'dhl', 'fedex', 'usps', 'coinbase',
    'binance', 'metamask',
}
 
SUSPICIOUS_TLDS = {
    'tk', 'ml', 'ga', 'cf', 'gq', 'xyz', 'top', 'click', 'link', 'work',
    'zip', 'mov', 'country', 'kim', 'loan', 'men', 'party', 'review',
    'stream', 'download', 'racing', 'win', 'bid', 'icu', 'cyou', 'rest',
}
 
SHORTENERS = {
    'bit.ly', 'tinyurl.com', 'goo.gl', 't.co', 'ow.ly', 'is.gd', 'buff.ly',
    'rebrand.ly', 'cutt.ly', 'shorturl.at', 'tiny.cc', 'rb.gy', 'bit.do',
}
 
# Fallback only used when tldextract is unavailable
_MULTI_PART_SUFFIXES = {
    'co.uk', 'org.uk', 'ac.uk', 'gov.uk', 'com.au', 'net.au', 'org.au',
    'co.in', 'net.in', 'org.in', 'gov.in', 'ac.in', 'co.jp', 'com.br',
    'com.cn', 'com.mx', 'co.za', 'com.sg', 'co.nz', 'com.tr', 'com.ru',
}
 
_DEFAULT_PORTS = {'http': 80, 'https': 443, '': None}
 
 
# ------------------------------------------------------------------ helpers
def normalize_url(url: str) -> str:
    """Trim whitespace and add a scheme if missing so urlparse works properly."""
    url = (url or '').strip()
    if not re.match(r'^[a-zA-Z][a-zA-Z0-9+.\-]*://', url):
        url = 'http://' + url.lstrip('/')
    return url
 
 
def shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    counts = Counter(s)
    n = len(s)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())
 
 
def _parse_obfuscated_ipv4(host: str):
    """Detect IPv4 written as decimal (3232235777), hex (0xC0A80101),
    octal-dotted (0300.0250.1.1) or mixed. Returns True if it resolves to an IP."""
    if not host:
        return False
    parts = host.split('.')
    if not 1 <= len(parts) <= 4:
        return False
 
    def to_int(p):
        if re.fullmatch(r'0[xX][0-9a-fA-F]+', p):
            return int(p, 16)
        if re.fullmatch(r'0[0-7]+', p):
            return int(p, 8)
        if re.fullmatch(r'\d+', p):
            return int(p, 10)
        return None
 
    nums = [to_int(p) for p in parts]
    if any(n is None for n in nums):
        return False
    # Last part fills the remaining bytes (inet_aton rules)
    *head, last = nums
    if any(n > 255 for n in head):
        return False
    if last >= 256 ** (4 - len(head)):
        return False
    return True
 
 
def is_ip_host(host: str) -> bool:
    if not host:
        return False
    try:
        ipaddress.ip_address(host.strip('[]'))
        return True
    except ValueError:
        pass
    return _parse_obfuscated_ipv4(host)
 
 
def split_domain(host: str):
    """Return (subdomain, registered_domain_label, suffix)."""
    if not host or is_ip_host(host):
        return '', host or '', ''
    if _extract is not None:
        ext = _extract(host)
        return ext.subdomain, ext.domain, ext.suffix
    labels = host.split('.')
    if len(labels) < 2:
        return '', host, ''
    last2 = '.'.join(labels[-2:])
    if last2 in _MULTI_PART_SUFFIXES and len(labels) >= 3:
        return '.'.join(labels[:-3]), labels[-3], last2
    return '.'.join(labels[:-2]), labels[-2], labels[-1]
 
 
def count_keywords(text: str) -> int:
    text = text.lower()
    return sum(1 for w in SUSPICIOUS_KEYWORDS if w in text)
 
 
def brand_impersonation(subdomain: str, domain_label: str, path_query: str) -> int:
    """1 if a well-known brand appears in the subdomain/path but is NOT the
    actual registered domain (e.g. paypal.com.evil.xyz, evil.com/paypal/login)."""
    real = domain_label.lower()
    haystack = (subdomain + ' ' + path_query).lower()
    for brand in BRANDS:
        if brand in haystack and brand not in real:
            return 1
    return 0
 
 
def _default_features() -> dict:
    return {k: 0 for k in FEATURE_NAMES}
 
 
# ------------------------------------------------------------ main function
def extract_url_features(url: str) -> dict:
    try:
        raw = (url or '').strip()
        norm = normalize_url(raw)
        parsed = urlparse(norm)
 
        host = (parsed.hostname or '').lower().rstrip('.')
        path = parsed.path or ''
        query = parsed.query or ''
        scheme = parsed.scheme.lower()
        decoded = unquote(norm)
 
        try:
            port = parsed.port
        except ValueError:
            port = -1  # malformed port
        nonstandard_port = int(port is not None and port != _DEFAULT_PORTS.get(scheme))
 
        subdomain, domain_label, suffix = split_domain(host)
        subdomain_count = len([s for s in subdomain.split('.') if s]) if subdomain else 0
        tld = suffix.split('.')[-1] if suffix else ''
 
        # '@' only matters when it's in the authority (userinfo trick)
        has_userinfo = int('@' in parsed.netloc)
 
        registered = f'{domain_label}.{suffix}' if suffix else domain_label
        param_dict = parse_qs(query, keep_blank_values=True)
        url_len = len(norm)
        host_len = len(host)
 
        letters = sum(c.isalpha() for c in norm)
        digits = sum(c.isdigit() for c in norm)
        specials = sum(not c.isalnum() for c in norm)
 
        feats = {
            # --- length
            'url_length': url_len,
            'hostname_length': host_len,
            'path_length': len(path),
            'query_length': len(query),
            'longest_host_label': max((len(l) for l in host.split('.')), default=0),
 
            # --- protocol / host type
            'has_https': int(scheme == 'https'),
            'uses_ip': int(is_ip_host(host)),
            'nonstandard_port': nonstandard_port,
            'has_userinfo_at': has_userinfo,
            'has_punycode': int('xn--' in host),
            'has_non_ascii': int(any(ord(c) > 127 for c in raw)),
 
            # --- domain structure
            'subdomain_count': subdomain_count,
            'count_dots_host': host.count('.'),
            'count_hyphens_host': host.count('-'),
            'count_digits_host': sum(c.isdigit() for c in host),
            'suspicious_tld': int(tld in SUSPICIOUS_TLDS),
            'is_shortener': int(registered in SHORTENERS),
            'domain_label_entropy': round(shannon_entropy(domain_label), 4),
 
            # --- path / query
            'path_depth': len([p for p in path.split('/') if p]),
            'count_query_params': len(param_dict),
            'count_percent_encoded': norm.count('%'),
            'double_slash_in_path': int('//' in path),
            'embedded_url': int(bool(re.search(r'https?(://|%3a%2f%2f)', norm[8:], re.I))),
            'has_fragment': int(bool(parsed.fragment)),
            'file_extension_exec': int(bool(re.search(
                r'\.(exe|scr|zip|rar|apk|js|jar|bat|cmd|msi|dmg)$', path, re.I))),
 
            # --- keywords (location-aware)
            'keywords_in_host': count_keywords(host),
            'keywords_in_path': count_keywords(path),
            'keywords_in_query': count_keywords(query),
            'suspicious_word_count': count_keywords(decoded),
            'brand_impersonation': brand_impersonation(subdomain, domain_label, path + '?' + query),
 
            # --- character stats (raw and ratio)
            'count_dots': norm.count('.'),
            'count_hyphens': norm.count('-'),
            'count_underscores': norm.count('_'),
            'count_slash': norm.count('/'),
            'count_equals': norm.count('=') ,
            'count_ampersand': norm.count('&'),
            'count_at': norm.count('@'),
            'num_digits': digits,
            'digit_ratio': round(digits / url_len, 4) if url_len else 0,
            'letter_ratio': round(letters / url_len, 4) if url_len else 0,
            'special_char_ratio': round(specials / url_len, 4) if url_len else 0,
            'url_entropy': round(shannon_entropy(norm), 4),
        }
        return feats
    except Exception:
        return _default_features()
 
 
# Fixed column order -> use this to build a DataFrame / model input consistently
FEATURE_NAMES = list(extract_url_features.__wrapped__({}) if False else [
    'url_length', 'hostname_length', 'path_length', 'query_length', 'longest_host_label',
    'has_https', 'uses_ip', 'nonstandard_port', 'has_userinfo_at', 'has_punycode',
    'has_non_ascii', 'subdomain_count', 'count_dots_host', 'count_hyphens_host',
    'count_digits_host', 'suspicious_tld', 'is_shortener', 'domain_label_entropy',
    'path_depth', 'count_query_params', 'count_percent_encoded', 'double_slash_in_path',
    'embedded_url', 'has_fragment', 'file_extension_exec', 'keywords_in_host',
    'keywords_in_path', 'keywords_in_query', 'suspicious_word_count',
    'brand_impersonation', 'count_dots', 'count_hyphens', 'count_underscores',
    'count_slash', 'count_equals', 'count_ampersand', 'count_at', 'num_digits',
    'digit_ratio', 'letter_ratio', 'special_char_ratio', 'url_entropy',
])
 
 
if __name__ == '__main__':
    tests = [
        'https://www.google.com/search?q=python',
        'http://192.168.1.1/secure/login.php',
        'http://0xC0A80101/verify',
        'http://paypal.com.account-verify.xyz/webscr?cmd=login',
        'https://user:pass@evil.tk/paypal/update',
        'https://www.bbc.co.uk/news',
        'http://xn--pple-43d.com/login',
        'not a url ::::',
    ]
    for t in tests:
        f = extract_url_features(t)
        print(t)
        print('  ', {k: f[k] for k in ('uses_ip', 'subdomain_count', 'suspicious_tld',
                                       'brand_impersonation', 'suspicious_word_count',
                                       'has_userinfo_at', 'has_punycode')})