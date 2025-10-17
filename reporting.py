import csv
import os
from typing import List, Dict, Any

CANDIDATE_HEADERS = [
    'seed_domain', 'candidate_domain', 'source', 'resolved', 'resolved_ip', 'first_seen_ts'
]

FEATURE_HEADERS = [
    'URL','Domain','TLD','whois_registered_domain_info','domain_registration_info','port','path_extension','punycode','IP','DomainLength','TLDLength','NoOfLettersInURL','LetterRatioInURL','NoOfDigitsInURL','DigitRatioInURL','CharContinuationRate','ObfuscationRatio','URLCharProb','URLSimilarityIndex','TLDLegitimateProb','HasObfuscation','NoOfObfuscatedChar','abnormal_subdomain','prefix_suffix','random_domain','suspicious_tld','NoOfSubDomain','nb_dots','nb_hyphens','nb_at','nb_www','nb_com','nb_dslash','nb_eq','nb_qm','nb_and','special_char_counts','LineOfCode','Robots','favicon_present','HasHiddenFields'
]


def write_candidates_csv(path: str, rows: List[Dict[str, Any]]):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, 'w', newline='', encoding='utf-8') as f:
        writer = csv.DictWriter(f, fieldnames=CANDIDATE_HEADERS)
        writer.writeheader()
        for r in rows:
            writer.writerow(r)


def write_features_csv(path: str, rows: List[Dict[str, Any]]):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, 'w', newline='', encoding='utf-8') as f:
        writer = csv.DictWriter(f, fieldnames=FEATURE_HEADERS)
        writer.writeheader()
        for r in rows:
            writer.writerow(r)