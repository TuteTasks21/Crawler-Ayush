import asyncio
from typing import List, Dict, Any, Tuple

import httpx
import dns.asyncresolver

from cache_utils import JSONCache


async def resolve_dns(domain: str, timeout: float) -> Tuple[bool, str]:
    try:
        resolver = dns.asyncresolver.Resolver()
        resolver.lifetime = timeout
        answers = await resolver.resolve(domain, 'A')
        ips = [a.address for a in answers]
        return (len(ips) > 0, ips[0] if ips else '')
    except Exception:
        return (False, '')


async def probe_http(domain: str, timeout: float, common_paths: List[str]) -> Dict[str, Any]:
    url_https = f"https://{domain}"
    url_http = f"http://{domain}"
    out: Dict[str, Any] = {
        'final_url': '',
        'status_code': 0,
        'headers': {},
        'paths': [],
    }
    async with httpx.AsyncClient(timeout=timeout, follow_redirects=True) as client:
        # Try HTTPS then HTTP
        try:
            r = await client.get(url_https, headers={'User-Agent': 'Mozilla/5.0'})
            out['final_url'] = str(r.url)
            out['status_code'] = r.status_code
            out['headers'] = dict(r.headers)
        except Exception:
            try:
                r = await client.get(url_http, headers={'User-Agent': 'Mozilla/5.0'})
                out['final_url'] = str(r.url)
                out['status_code'] = r.status_code
                out['headers'] = dict(r.headers)
            except Exception:
                return out
        # Quick path probes (HEAD)
        for p in common_paths:
            base = out['final_url'] or url_https
            if not base:
                base = url_http
            if not base:
                continue
            u = base.rstrip('/') + p
            try:
                rr = await client.head(u)
                if rr.status_code < 500:
                    out['paths'].append(u)
            except Exception:
                pass
    return out


async def resolve_and_probe(domains: List[str], dns_timeout: float, http_timeout: float, common_paths: List[str], concurrency_limit: int = 50) -> Dict[str, Dict[str, Any]]:
    sem = asyncio.Semaphore(concurrency_limit)

    async def worker(domain: str) -> Tuple[str, Dict[str, Any]]:
        async with sem:
            resolved, ip = await resolve_dns(domain, dns_timeout)
            http_info = await probe_http(domain, http_timeout, common_paths)
            return domain, {
                'resolved': resolved,
                'resolved_ip': ip,
                'http_info': http_info
            }

    tasks = [worker(d) for d in domains]
    results: Dict[str, Dict[str, Any]] = {}
    for coro in asyncio.as_completed(tasks):
        d, info = await coro
        results[d] = info
    return results