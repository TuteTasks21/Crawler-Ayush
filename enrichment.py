import os
import json
import shutil
import subprocess
from typing import Dict, Any

import httpx
import whois

from cache_utils import JSONCache


def whois_info(domain: str, cache: JSONCache) -> Dict[str, Any]:
    cached = cache.get('whois', domain)
    if cached is not None:
        return cached
    try:
        w = whois.whois(domain)
        info = {
            'registrar': getattr(w, 'registrar', None),
            'creation_date': str(getattr(w, 'creation_date', None)),
            'expiration_date': str(getattr(w, 'expiration_date', None)),
            'updated_date': str(getattr(w, 'updated_date', None)),
            'name_servers': list(getattr(w, 'name_servers', []) or []),
            'raw': str(getattr(w, 'text', ''))
        }
    except Exception as e:
        info = {'error': str(e)}
    cache.set('whois', domain, info)
    return info


def _which(exe: str) -> str:
    return shutil.which(exe) or ''


def tls_cert_info(domain: str, timeout: int, cache: JSONCache) -> Dict[str, Any]:
    cached = cache.get('tls', domain)
    if cached is not None:
        return cached
    exe_sslyze = _which('sslyze')
    exe_openssl = _which('openssl')
    cert_info: Dict[str, Any] = {}
    pem_text = ''
    if exe_sslyze:
        try:
            cmd = [exe_sslyze, f"--regular", domain]
            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
            pem_text = proc.stdout[:4096]
            cert_info = {'tool': 'sslyze', 'summary': pem_text}
        except Exception:
            pass
    elif exe_openssl:
        try:
            cmd = [exe_openssl, 's_client', '-connect', f"{domain}:443", '-servername', domain]
            proc = subprocess.run(cmd, input='\n', capture_output=True, text=True, timeout=timeout)
            out = proc.stdout
            # Extract certificate block
            start = out.find('-----BEGIN CERTIFICATE-----')
            end = out.find('-----END CERTIFICATE-----')
            if start != -1 and end != -1:
                pem_text = out[start:end+len('-----END CERTIFICATE-----')]
                cert_info = {'tool': 'openssl', 'pem': pem_text[:4096]}
        except Exception:
            pass
    cache.set('tls', domain, cert_info or {'tool': None})
    return cert_info or {'tool': None}


async def fetch_html_and_headers(domain: str, timeout: float) -> Dict[str, Any]:
    url_https = f"https://{domain}"
    url_http = f"http://{domain}"
    out: Dict[str, Any] = {'html': '', 'headers': {}, 'final_url': ''}
    async with httpx.AsyncClient(timeout=timeout, follow_redirects=True) as client:
        try:
            r = await client.get(url_https, headers={'User-Agent': 'Mozilla/5.0'})
            out['html'] = r.text
            out['headers'] = dict(r.headers)
            out['final_url'] = str(r.url)
            return out
        except Exception:
            try:
                r = await client.get(url_http, headers={'User-Agent': 'Mozilla/5.0'})
                out['html'] = r.text
                out['headers'] = dict(r.headers)
                out['final_url'] = str(r.url)
                return out
            except Exception:
                return out


async def check_robots(domain: str, timeout: float) -> bool:
    async with httpx.AsyncClient(timeout=timeout, follow_redirects=True) as client:
        for scheme in ('https', 'http'):
            try:
                r = await client.head(f"{scheme}://{domain}/robots.txt")
                if r.status_code < 500:
                    return True
            except Exception:
                continue
    return False


async def check_favicon(domain: str, timeout: float) -> bool:
    async with httpx.AsyncClient(timeout=timeout, follow_redirects=True) as client:
        for scheme in ('https', 'http'):
            try:
                r = await client.head(f"{scheme}://{domain}/favicon.ico")
                if r.status_code < 500:
                    return True
            except Exception:
                continue
    return False