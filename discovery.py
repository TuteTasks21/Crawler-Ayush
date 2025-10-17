import os
import re
import shutil
import subprocess
from typing import List, Dict, Tuple

import requests
import tldextract

COMMON_SUBDOMAINS = [
    'www', 'mail', 'remote', 'blog', 'webmail', 'server', 'ns1', 'ns2',
    'smtp', 'secure', 'vpn', 'api', 'dev', 'staging', 'app', 'support',
    'ftp', 'admin', 'portal', 'test', 'cdn', 'shop', 'm', 'mobile'
]

COMMON_PATHS_DEFAULT = ['/', '/login', '/signin', '/account', '/secure', '/update', '/index.html']


def canonicalize_domain(domain: str) -> str:
    d = domain.strip().lower()
    d = re.sub(r'^https?://', '', d)
    d = d.split('/')[0]
    if d.startswith('www.'):
        d = d[4:]
    if ':' in d:
        d = d.split(':')[0]
    return d


def find_canonical_urls(seed: str, common_paths: List[str]) -> List[str]:
    """Try HTTPS first, then HTTP; return reachable canonical URLs."""
    urls = []
    for scheme in ('https', 'http'):
        base = f"{scheme}://{seed}"
        try:
            r = requests.get(base, timeout=6, allow_redirects=True, headers={'User-Agent': 'Mozilla/5.0'})
            if r.status_code < 500:
                urls.append(r.url)
                # Try common paths quickly
                for p in common_paths:
                    if p == '/':
                        continue
                    u = base + p
                    try:
                        rr = requests.head(u, timeout=4, allow_redirects=True)
                        if rr.status_code < 500:
                            urls.append(u)
                    except Exception:
                        pass
        except Exception:
            continue
    # Dedup
    seen = set()
    out = []
    for u in urls:
        if u not in seen:
            seen.add(u)
            out.append(u)
    return out


def _which(exe: str) -> str:
    return shutil.which(exe) or ''


def enumerate_subdomains_amass(seed: str) -> List[str]:
    """Use amass passive mode if available; otherwise return common subdomains."""
    exe = _which('amass')
    subs: List[str] = []
    if exe:
        try:
            cmd = [exe, 'enum', '-passive', '-d', seed]
            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
            if proc.returncode == 0:
                for line in proc.stdout.splitlines():
                    line = line.strip()
                    # amass outputs subdomain lines; filter domain-shaped entries
                    if line and seed in line:
                        subs.append(line)
        except Exception:
            pass
    if not subs:
        # Fallback: synthesize common subdomains
        ext = tldextract.extract(seed)
        base = f"{ext.domain}.{ext.suffix}"
        subs = [f"{s}.{base}" for s in COMMON_SUBDOMAINS] + [base]
    return sorted(set(subs))


def discover_assets(seed: str, common_paths: List[str]) -> Dict[str, List[str]]:
    """Return dict with keys: canonical_urls, subdomains, common_paths."""
    canon_urls = find_canonical_urls(seed, common_paths)
    subs = enumerate_subdomains_amass(seed)
    return {
        'canonical_urls': canon_urls,
        'subdomains': subs,
        'common_paths': common_paths,
    }