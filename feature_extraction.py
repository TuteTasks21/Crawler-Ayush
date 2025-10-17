import math
import json
import idna
import tldextract
from typing import Dict, Any

# Simple English letter frequency as proxy char probability
LETTER_FREQ = {
    'e': 12.70,'t': 9.06,'a': 8.17,'o': 7.51,'i': 6.97,'n': 6.75,'s': 6.33,'h': 6.09,
    'r': 5.99,'d': 4.25,'l': 4.03,'c': 2.78,'u': 2.76,'m': 2.41,'w': 2.36,'f': 2.23,
    'g': 2.02,'y': 1.97,'p': 1.93,'b': 1.49,'v': 0.98,'k': 0.77,'j': 0.15,'x': 0.15,
    'q': 0.10,'z': 0.07
}

SUSPICIOUS_SUBWORDS = ['secure', 'update', 'verify', 'account', 'login', 'signin', 'confirm']


def shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    freq = {}
    for ch in s:
        freq[ch] = freq.get(ch, 0) + 1
    ent = 0.0
    n = len(s)
    for c in freq.values():
        p = c / n
        ent -= p * math.log2(p)
    return ent


def levenshtein(a: str, b: str) -> int:
    if len(a) < len(b):
        return levenshtein(b, a)
    if len(b) == 0:
        return len(a)
    prev = list(range(len(b)+1))
    for i, ca in enumerate(a):
        cur = [i+1]
        for j, cb in enumerate(b):
            ins = prev[j+1] + 1
            del_ = cur[j] + 1
            sub = prev[j] + (ca != cb)
            cur.append(min(ins, del_, sub))
        prev = cur
    return prev[-1]


def continuation_rate(s: str) -> float:
    """Average run-length of same char normalized by string length."""
    if not s:
        return 0.0
    runs = 1
    cur = 1
    for i in range(1, len(s)):
        if s[i] == s[i-1]:
            cur += 1
        else:
            runs += 1
            cur = 1
    avg_run = len(s) / runs
    return avg_run / len(s)


def compute_features(seed_domain: str, candidate_domain: str, resolved_ip: str, whois_json: Dict[str, Any], http_html: str, tld_whitelist: list, tld_blacklist: list) -> Dict[str, Any]:
    url = f"http://{candidate_domain}/"
    ext = tldextract.extract(candidate_domain)
    domain = f"{ext.domain}.{ext.suffix}" if ext.suffix else candidate_domain
    tld = ext.suffix or ''
    punycode = ''
    try:
        punycode = idna.encode(domain).decode('ascii')
    except Exception:
        punycode = domain

    # Basic counts
    url_str = url
    letters = sum(ch.isalpha() for ch in url_str)
    digits = sum(ch.isdigit() for ch in url_str)
    total = max(1, len(url_str))
    letter_ratio = letters / total
    digit_ratio = digits / total

    # Obfuscation
    non_alnum = sum(not ch.isalnum() for ch in domain)
    obfuscation_ratio = non_alnum / max(1, len(domain))
    has_obfuscation = obfuscation_ratio > 0.15

    # URLCharProb: average probability from LETTER_FREQ for letters
    probs = []
    for ch in url_str.lower():
        if ch.isalpha():
            probs.append(LETTER_FREQ.get(ch, 0.01))
    url_char_prob = sum(probs)/max(1, len(probs)) if probs else 0.0

    # Similarity to seed
    sld_candidate = ext.domain
    sld_seed = tldextract.extract(seed_domain).domain
    lev = levenshtein(sld_candidate, sld_seed)
    url_similarity_index = 1.0 - (lev / max(len(sld_candidate), len(sld_seed), 1))

    # TLD legitimate probability
    tld_legit_prob = 0.9 if tld in tld_whitelist else (0.1 if tld in tld_blacklist else 0.5)

    # Abnormal subdomain
    labels = candidate_domain.split('.')
    sub_labels = labels[:-2] if len(labels) > 2 else []
    abnormal_subdomain = any(any(sw in lab.lower() for sw in SUSPICIOUS_SUBWORDS) for lab in sub_labels)

    # Prefix-suffix
    prefix_suffix = '-' in domain

    # Random domain via entropy
    random_domain = shannon_entropy(ext.domain) > 3.5

    # Suspicious tld
    suspicious_tld = (tld in tld_blacklist) or (tld not in tld_whitelist)

    # counts
    no_subdomain = len(sub_labels)
    nb_dots = url_str.count('.')
    nb_hyphens = url_str.count('-')
    nb_at = url_str.count('@')
    nb_www = url_str.count('www')
    nb_com = url_str.count('com')
    nb_dslash = url_str.count('//')
    nb_eq = url_str.count('=')
    nb_qm = url_str.count('?')
    nb_and = url_str.count('&')

    special_counts = {
        '@': nb_at,
        '-': nb_hyphens,
        '.': nb_dots,
        '/': url_str.count('/'),
        '\\': url_str.count('\\'),
        '=': nb_eq,
        '?': nb_qm,
        '&': nb_and,
        '#': url_str.count('#'),
        '%': url_str.count('%'),
        '$': url_str.count('$'),
    }

    # HTML-derived features
    line_of_code = len(http_html.splitlines()) if http_html else 0
    has_hidden_fields = ('type="hidden"' in http_html.lower()) if http_html else False

    # Domain registration info is WHOIS JSON
    whois_registered_domain_info = json.dumps(whois_json, ensure_ascii=False)
    domain_registration_info = whois_registered_domain_info

    return {
        'URL': url,
        'Domain': domain,
        'TLD': tld,
        'whois_registered_domain_info': whois_registered_domain_info,
        'domain_registration_info': domain_registration_info,
        'port': 443 if url.startswith('https') else 80,
        'path_extension': '',
        'punycode': punycode,
        'IP': resolved_ip or '',
        'DomainLength': len(domain),
        'TLDLength': len(tld),
        'NoOfLettersInURL': letters,
        'LetterRatioInURL': letter_ratio,
        'NoOfDigitsInURL': digits,
        'DigitRatioInURL': digit_ratio,
        'CharContinuationRate': continuation_rate(domain),
        'ObfuscationRatio': obfuscation_ratio,
        'URLCharProb': url_char_prob,
        'URLSimilarityIndex': url_similarity_index,
        'TLDLegitimateProb': tld_legit_prob,
        'HasObfuscation': has_obfuscation,
        'NoOfObfuscatedChar': non_alnum,
        'abnormal_subdomain': abnormal_subdomain,
        'prefix_suffix': prefix_suffix,
        'random_domain': random_domain,
        'suspicious_tld': suspicious_tld,
        'NoOfSubDomain': no_subdomain,
        'nb_dots': nb_dots,
        'nb_hyphens': nb_hyphens,
        'nb_at': nb_at,
        'nb_www': nb_www,
        'nb_com': nb_com,
        'nb_dslash': nb_dslash,
        'nb_eq': nb_eq,
        'nb_qm': nb_qm,
        'nb_and': nb_and,
        'special_char_counts': json.dumps(special_counts),
        'LineOfCode': line_of_code,
        'Robots': False,  # set in analyzer after check
        'favicon_present': False,  # set in analyzer after check
        'HasHiddenFields': has_hidden_fields,
    }