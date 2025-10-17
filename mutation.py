import csv
import os
import shutil
import subprocess
from typing import List, Dict, Tuple

import tldextract

# Basic fallback mutations
HOMOGLYPHS = {
    'a': ['4', '@'], 'b': ['8'], 'e': ['3'], 'i': ['1', '!'],
    'l': ['1', '|'], 'o': ['0'], 's': ['5', '$'], 't': ['7']
}

COMMON_TLDS = ['com', 'net', 'org', 'info', 'biz', 'io']


def _which(exe: str) -> str:
    return shutil.which(exe) or ''


def run_dnstwist(seed: str) -> List[str]:
    exe = _which('dnstwist')
    results: List[str] = []
    if exe:
        try:
            cmd = [exe, seed, '--registered', '--format', 'csv']
            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
            if proc.returncode == 0:
                # Parse CSV lines; expect column with domain names
                reader = csv.reader(proc.stdout.splitlines())
                for row in reader:
                    if not row:
                        continue
                    domain = row[0].strip()
                    if domain and domain != 'domain' and '.' in domain:
                        results.append(domain)
        except Exception:
            pass
    return sorted(set(results))


def run_urlcrazy(seed: str) -> List[str]:
    exe = _which('urlcrazy')
    results: List[str] = []
    if exe:
        try:
            cmd = [exe, seed]
            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
            if proc.returncode == 0:
                for line in proc.stdout.splitlines():
                    # urlcrazy outputs candidate domains
                    line = line.strip()
                    if line and '.' in line and '|' not in line and 'Domain' not in line:
                        results.append(line)
        except Exception:
            pass
    return sorted(set(results))


def fallback_mutations(seed: str) -> List[str]:
    ext = tldextract.extract(seed)
    name = ext.domain
    suffix = ext.suffix
    muts = set()

    # 1. Homoglyph replacements
    for i, c in enumerate(name):
        if c in HOMOGLYPHS:
            for rep in HOMOGLYPHS[c]:
                muts.add(f"{name[:i]}{rep}{name[i+1:]}.{suffix}")

    # 2. Omission
    for i in range(len(name)):
        muts.add(f"{name[:i]}{name[i+1:]}.{suffix}")

    # 3. Insertion
    for i in range(len(name)):
        for c in 'abcdefghijklmnopqrstuvwxyz0123456789-':
            muts.add(f"{name[:i]}{c}{name[i:]}.{suffix}")

    # 4. Swap
    for i in range(len(name) - 1):
        swapped = list(name)
        swapped[i], swapped[i+1] = swapped[i+1], swapped[i]
        muts.add(f"{''.join(swapped)}.{suffix}")

    # 5. Hyphenation
    if '-' not in name:
        for i in range(1, len(name)):
            muts.add(f"{name[:i]}-{name[i:]}.{suffix}")

    # 6. TLD variations
    for tld in COMMON_TLDS:
        if tld != suffix:
            muts.add(f"{name}.{tld}")

    muts.discard(seed)
    return sorted(muts)


def generate_candidates(seed: str) -> Dict[str, List[str]]:
    """Return dict of sources to candidate domains."""
    dnst = run_dnstwist(seed)
    urlc = run_urlcrazy(seed)
    fallback = fallback_mutations(seed)
    return {
        'dnstwist': dnst,
        'urlcrazy': urlc,
        'generator': fallback,
    }