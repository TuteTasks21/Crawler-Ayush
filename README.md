# One-shot Phishing Domain Analyzer

This repository provides a one-shot pipeline to analyze a seed domain and produce:
- `suspicious_candidates.csv`: Aggregated related/suspicious domains with sources and resolution info.
- `suspicious_features.csv`: Full feature set for each resolving candidate domain.

No third-party web APIs are used; only local tools and open-source libraries.

## Requirements
- Python 3.7+
- Optional local CLI tools (used if present, otherwise fallback logic is applied):
  - `amass` (passive subdomain discovery)
  - `dnstwist` (typosquats)
  - `urlcrazy` (permutations)
  - `sslyze` or `openssl` (TLS cert details)

## Install
```
python -m pip install -r requirements.txt
```

## Usage
```
python analyze.py example.com -o outdir
```
- `-o outdir`: Output directory (default: `outdir`).
- `-c config.yaml`: Optional config (defaults to repository `config.yaml`).

Outputs:
- `outdir/suspicious_candidates.csv`
- `outdir/suspicious_features.csv`
- `outdir/artifacts/` contains saved HTML, headers, TLS details when available.

## Pipeline Overview
1. Canonicalize seed domain and probe canonical URLs.
2. Enumerate subdomains via `amass` if available; fallback to common subdomains.
3. Generate domain permutations via `dnstwist`/`urlcrazy` if available; robust fallback generator included.
4. Aggregate and deduplicate into `suspicious_candidates.csv` with columns:
   - `seed_domain, candidate_domain, source, resolved, resolved_ip, first_seen_ts`
5. For each candidate, concurrently resolve DNS and probe HTTP (async `httpx` + `dnspython` async).
6. Enrich with WHOIS, TLS certificate (via `sslyze`/`openssl` when available), and save HTML/headers locally.
7. Compute features locally and write `suspicious_features.csv` with exact columns:
   - `URL, Domain, TLD, whois_registered_domain_info, domain_registration_info, port, path_extension, punycode, IP, DomainLength, TLDLength, NoOfLettersInURL, LetterRatioInURL, NoOfDigitsInURL, DigitRatioInURL, CharContinuationRate, ObfuscationRatio, URLCharProb, URLSimilarityIndex, TLDLegitimateProb, HasObfuscation, NoOfObfuscatedChar, abnormal_subdomain, prefix_suffix, random_domain, suspicious_tld, NoOfSubDomain, nb_dots, nb_hyphens, nb_at, nb_www, nb_com, nb_dslash, nb_eq, nb_qm, nb_and, special_char_counts, LineOfCode, Robots, favicon_present, HasHiddenFields`

## Config
`config.yaml` provides timeouts, thresholds, TLD whitelist/blacklist, common paths, and artifact settings. Example:
```
timeouts:
  dns_timeout_seconds: 5
  http_timeout_seconds: 8
  tls_timeout_seconds: 10
  robots_timeout_seconds: 5
  concurrency_limit: 50

thresholds:
  obfuscation_ratio_high: 0.15
  entropy_random_threshold: 3.5

whitelist_tlds: [com, net, org, edu, gov]
blacklist_tlds: [zip, mov, country]

common_paths: ['/', '/login', '/signin', '/account', '/secure', '/update', '/index.html']

artifacts:
  save_html: true
  save_headers: true
  save_certs: true
  out_subdir: artifacts
```

## Sample Run
- Command: `python analyze.py example.com -o outdir`
- Produces: `outdir/suspicious_candidates.csv`, `outdir/suspicious_features.csv`, and `outdir/artifacts/` with HTML/headers/TLS snapshots where available.
- Network timeouts are handled gracefully; some domains may not resolve or respond depending on environment policies.

## LLM Assistant Stub
`llm_assistant.py` provides a stub interface:
```
from llm_assistant import classify
result = classify(feature_json)
```
This returns a placeholder label and suggested rules. No LLM logic is implemented now.

## Continuous Monitoring (Future Notes)
- Wrap the one-shot pipeline in a scheduler (e.g., cron/Task Scheduler).
- Persist historical states, compare deltas, and emit alerts.
- Add rotating cache and evidence archiving.

## License
Open-source libraries used; no external web APIs consumed.