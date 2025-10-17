import os
import sys
import csv
import json
import time
import argparse
import asyncio
from typing import List, Dict, Any

import yaml

from cache_utils import JSONCache
from discovery import canonicalize_domain, discover_assets
from mutation import generate_candidates
from resolution import resolve_and_probe
from enrichment import whois_info, tls_cert_info, fetch_html_and_headers, check_robots, check_favicon
from feature_extraction import compute_features
from reporting import write_candidates_csv, write_features_csv


def load_config(config_path: str) -> Dict[str, Any]:
    if not os.path.exists(config_path):
        return {
            'timeouts': {
                'dns_timeout_seconds': 5,
                'http_timeout_seconds': 8,
                'tls_timeout_seconds': 10,
                'robots_timeout_seconds': 5,
                'concurrency_limit': 50,
            },
            'thresholds': {
                'obfuscation_ratio_high': 0.15,
                'entropy_random_threshold': 3.5,
                'similarity_suspicious_threshold': 0.8,
            },
            'whitelist_tlds': ['com', 'net', 'org', 'edu', 'gov'],
            'blacklist_tlds': ['zip', 'mov', 'country'],
            'common_paths': ['/', '/login', '/signin', '/account', '/secure', '/update', '/index.html'],
            'artifacts': {
                'save_html': True,
                'save_headers': True,
                'save_certs': True,
                'out_subdir': 'artifacts',
            },
            'executables': {
                'amass': 'amass', 'dnstwist': 'dnstwist', 'urlcrazy': 'urlcrazy', 'sslyze': 'sslyze', 'openssl': 'openssl'
            }
        }
    with open(config_path, 'r', encoding='utf-8') as f:
        return yaml.safe_load(f)


def aggregate_candidates(seed: str, assets: Dict[str, Any], mutations: Dict[str, List[str]]) -> List[Dict[str, Any]]:
    now_ts = int(time.time())
    rows: List[Dict[str, Any]] = []
    seen = set()
    # Subdomains
    for d in assets.get('subdomains', []):
        if d not in seen:
            seen.add(d)
            rows.append({
                'seed_domain': seed, 'candidate_domain': d, 'source': 'amass/common',
                'resolved': False, 'resolved_ip': '', 'first_seen_ts': now_ts,
            })
    # Mutations from tools and generator
    for src, cands in mutations.items():
        for d in cands:
            if d not in seen:
                seen.add(d)
                rows.append({
                    'seed_domain': seed, 'candidate_domain': d, 'source': src,
                    'resolved': False, 'resolved_ip': '', 'first_seen_ts': now_ts,
                })
    return rows


async def enrich_candidates(seed: str, candidates: List[Dict[str, Any]], config: Dict[str, Any], cache: JSONCache, outdir: str) -> List[Dict[str, Any]]:
    # Resolve + probe concurrently
    domains = [row['candidate_domain'] for row in candidates]
    resolved_map = await resolve_and_probe(
        domains,
        dns_timeout=config['timeouts']['dns_timeout_seconds'],
        http_timeout=config['timeouts']['http_timeout_seconds'],
        common_paths=config['common_paths'],
        concurrency_limit=config['timeouts']['concurrency_limit'],
    )

    # Update candidate rows with resolution
    for row in candidates:
        info = resolved_map.get(row['candidate_domain'], {})
        row['resolved'] = bool(info.get('resolved'))
        row['resolved_ip'] = info.get('resolved_ip', '')

    # Only keep resolving/registered candidates for features
    active_candidates = [r for r in candidates if r['resolved']]

    # Prepare artifacts dir
    artifacts_dir = os.path.join(outdir, config['artifacts']['out_subdir'])
    os.makedirs(artifacts_dir, exist_ok=True)

    # Enrich each concurrently (HTML, robots, favicon) using asyncio
    async def enrich_one(domain: str) -> Dict[str, Any]:
        html_headers = await fetch_html_and_headers(domain, config['timeouts']['http_timeout_seconds'])
        robots = await check_robots(domain, config['timeouts']['robots_timeout_seconds'])
        favicon = await check_favicon(domain, config['timeouts']['robots_timeout_seconds'])
        return {
            'html': html_headers.get('html', ''),
            'headers': html_headers.get('headers', {}),
            'final_url': html_headers.get('final_url', ''),
            'robots': robots,
            'favicon_present': favicon,
        }

    tasks = [enrich_one(r['candidate_domain']) for r in active_candidates]
    enrich_results = await asyncio.gather(*tasks)

    # Save artifacts and compute features
    features_rows: List[Dict[str, Any]] = []
    for row, enr in zip(active_candidates, enrich_results):
        domain = row['candidate_domain']
        # WHOIS and TLS (sync; cached)
        wjson = whois_info(domain, cache)
        tlsjson = tls_cert_info(domain, config['timeouts']['tls_timeout_seconds'], cache)

        # Save artifacts
        if config['artifacts']['save_html'] and enr['html']:
            with open(os.path.join(artifacts_dir, f"{domain}_html.txt"), 'w', encoding='utf-8') as f:
                f.write(enr['html'])
        if config['artifacts']['save_headers'] and enr['headers']:
            with open(os.path.join(artifacts_dir, f"{domain}_headers.json"), 'w', encoding='utf-8') as f:
                json.dump(enr['headers'], f, indent=2, ensure_ascii=False)
        if config['artifacts']['save_certs'] and tlsjson:
            with open(os.path.join(artifacts_dir, f"{domain}_tls.json"), 'w', encoding='utf-8') as f:
                json.dump(tlsjson, f, indent=2, ensure_ascii=False)

        # Compute features
        feats = compute_features(
            seed_domain=seed,
            candidate_domain=domain,
            resolved_ip=row['resolved_ip'],
            whois_json=wjson,
            http_html=enr['html'],
            tld_whitelist=config.get('whitelist_tlds', []),
            tld_blacklist=config.get('blacklist_tlds', []),
        )
        feats['Robots'] = enr['robots']
        feats['favicon_present'] = enr['favicon_present']
        features_rows.append(feats)

    return active_candidates, features_rows


def main():
    parser = argparse.ArgumentParser(description='One-shot Phishing Domain Analyzer')
    parser.add_argument('seed_domain', help='Seed domain to analyze')
    parser.add_argument('-o', '--output', default='outdir', help='Output directory')
    parser.add_argument('-c', '--config', default='config.yaml', help='Path to config.yaml')
    args = parser.parse_args()

    seed = canonicalize_domain(args.seed_domain)
    outdir = os.path.abspath(args.output)
    os.makedirs(outdir, exist_ok=True)

    config = load_config(args.config)

    # Cache
    cache = JSONCache(os.path.join(outdir, 'cache'))

    # Step 1: Discover assets
    assets = discover_assets(seed, config['common_paths'])

    # Step 2: Mutations
    mutations = generate_candidates(seed)

    # Step 3: Aggregate & dedupe candidates
    candidate_rows = aggregate_candidates(seed, assets, mutations)

    # Step 4: Write suspicious_candidates.csv (initial)
    cand_path = os.path.join(outdir, 'suspicious_candidates.csv')
    write_candidates_csv(cand_path, candidate_rows)

    # Step 5: Enrich and feature extraction (only resolving candidates)
    active_candidates, features_rows = asyncio.run(enrich_candidates(seed, candidate_rows, config, cache, outdir))

    # Step 6: Write suspicious_features.csv
    feats_path = os.path.join(outdir, 'suspicious_features.csv')
    write_features_csv(feats_path, features_rows)

    print(f"Wrote: {cand_path}")
    print(f"Wrote: {feats_path}")
    return 0


if __name__ == '__main__':
    sys.exit(main())