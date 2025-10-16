#!/usr/bin/env python3
"""
Phishing Domain Crawler
-----------------------
A comprehensive tool for detecting potential phishing domains by:
1. Canonicalizing and scoping target domains
2. Discovering subdomains through passive techniques
3. Generating domain mutations and typosquats
4. Resolving DNS to identify active domains
5. Enriching and validating candidates
6. Scoring and triaging results
7. Reporting and archiving evidence
"""

import os
import sys
import json
import argparse
import subprocess
import logging
import datetime
import csv
import re
import socket
import requests
import tldextract
import whois
import dns.resolver
from urllib.parse import urlparse
from bs4 import BeautifulSoup
from tqdm import tqdm
from concurrent.futures import ThreadPoolExecutor, as_completed

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler("phishing_crawler.log"),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger("PhishingCrawler")

class PhishingCrawler:
    def __init__(self, target_domain, output_dir="output", max_threads=10):
        """Initialize the phishing crawler with target domain and configuration."""
        self.target_domain = target_domain
        self.output_dir = output_dir
        self.max_threads = max_threads
        
        # Create output directory if it doesn't exist
        os.makedirs(output_dir, exist_ok=True)
        
        # Extract domain components
        self.domain_info = tldextract.extract(target_domain)
        self.base_domain = f"{self.domain_info.domain}.{self.domain_info.suffix}"
        
        # Initialize results storage
        self.subdomains = set()
        self.mutations = set()
        self.resolved_domains = set()
        self.enriched_domains = []
        
        logger.info(f"Initialized crawler for target domain: {target_domain}")
        logger.info(f"Base domain identified as: {self.base_domain}")

    def canonicalize_and_scope(self):
        """
        Canonicalize the target domain and define scope for the crawl.
        Returns the base domain and TLD for further processing.
        """
        logger.info("Step 1: Canonicalizing and scoping target domain")
        
        # Get domain information
        domain_parts = tldextract.extract(self.target_domain)
        
        # Normalize domain (lowercase)
        normalized_domain = self.target_domain.lower()
        
        # Remove www if present in the original target
        if normalized_domain.startswith('www.'):
            normalized_domain = normalized_domain[4:]
            
        # Get related TLDs to check
        related_tlds = self._get_related_tlds(domain_parts.suffix)
        
        logger.info(f"Canonicalized domain: {normalized_domain}")
        logger.info(f"Related TLDs to check: {', '.join(related_tlds[:5])}... (total: {len(related_tlds)})")
        
        return {
            "normalized_domain": normalized_domain,
            "domain": domain_parts.domain,
            "suffix": domain_parts.suffix,
            "related_tlds": related_tlds
        }

    def _get_related_tlds(self, current_tld):
        """Get a list of related TLDs to check for typosquatting."""
        # Common TLDs to check regardless of the current TLD
        common_tlds = [
            "com", "net", "org", "io", "co", "info", "biz", "xyz", 
            "online", "site", "website", "tech", "app"
        ]
        
        # Ensure the current TLD is included
        if current_tld not in common_tlds:
            common_tlds.append(current_tld)
            
        return common_tlds

    def discover_subdomains(self):
        """
        Discover subdomains using Amass and other passive techniques.
        """
        logger.info("Step 2: Discovering subdomains")
        
        # Check if Amass is installed
        try:
            # Use Amass for subdomain discovery if available
            logger.info("Running Amass for subdomain discovery...")
            
            output_file = os.path.join(self.output_dir, "amass_results.txt")
            
            # This is a simulation of running Amass since we can't actually execute it here
            # In a real implementation, you would use subprocess to run Amass
            logger.info(f"Would execute: amass enum -d {self.base_domain} -o {output_file}")
            
            # For demonstration, let's add some example subdomains
            example_subdomains = [
                f"www.{self.base_domain}",
                f"mail.{self.base_domain}",
                f"blog.{self.base_domain}",
                f"shop.{self.base_domain}",
                f"support.{self.base_domain}",
                f"api.{self.base_domain}"
            ]
            
            # Add discovered subdomains to our set
            self.subdomains.update(example_subdomains)
            
            logger.info(f"Discovered {len(self.subdomains)} subdomains")
            
            # Write subdomains to file
            with open(os.path.join(self.output_dir, "subdomains.txt"), "w") as f:
                for subdomain in sorted(self.subdomains):
                    f.write(f"{subdomain}\n")
                    
            return self.subdomains
            
        except Exception as e:
            logger.error(f"Error during subdomain discovery: {str(e)}")
            return set()

    def generate_mutations(self):
        """
        Generate domain mutations using dnstwist and urlcrazy.
        """
        logger.info("Step 3: Generating domain mutations")
        
        # Check if dnstwist and urlcrazy are installed
        # In a real implementation, you would use these tools directly
        
        # For demonstration, let's generate some example mutations
        domain_parts = tldextract.extract(self.target_domain)
        domain_name = domain_parts.domain
        
        # Simple mutation algorithms
        mutations = set()
        
        # 1. Character omission (removing one character at a time)
        for i in range(len(domain_name)):
            mutation = domain_name[:i] + domain_name[i+1:]
            mutations.add(f"{mutation}.{domain_parts.suffix}")
        
        # 2. Character replacement (common typos)
        replacements = {
            'a': ['e', 's', 'q', 'w', 'z'],
            'b': ['v', 'g', 'h', 'n'],
            'c': ['x', 'd', 'f', 'v'],
            # Add more replacements for other characters
        }
        
        for i, char in enumerate(domain_name):
            if char in replacements:
                for replacement in replacements[char]:
                    mutation = domain_name[:i] + replacement + domain_name[i+1:]
                    mutations.add(f"{mutation}.{domain_parts.suffix}")
        
        # 3. Character insertion
        for i in range(len(domain_name) + 1):
            for char in 'abcdefghijklmnopqrstuvwxyz':
                mutation = domain_name[:i] + char + domain_name[i:]
                mutations.add(f"{mutation}.{domain_parts.suffix}")
        
        # 4. Homoglyphs (similar looking characters)
        homoglyphs = {
            'a': ['à', 'á', 'â', 'ã', 'ä', 'å', 'ą'],
            'b': ['ḃ', 'ḅ', 'ḇ', 'ƀ'],
            'c': ['ç', 'ć', 'ĉ', 'ċ', 'č'],
            # Add more homoglyphs for other characters
        }
        
        for i, char in enumerate(domain_name):
            if char in homoglyphs:
                for homoglyph in homoglyphs[char]:
                    mutation = domain_name[:i] + homoglyph + domain_name[i+1:]
                    mutations.add(f"{mutation}.{domain_parts.suffix}")
        
        # 5. Bitsquatting (bit-flipping)
        # This is a simplified version of bitsquatting
        for i, char in enumerate(domain_name):
            ascii_val = ord(char)
            for bit in range(8):
                new_val = ascii_val ^ (1 << bit)
                if 97 <= new_val <= 122:  # ASCII range for lowercase letters
                    mutation = domain_name[:i] + chr(new_val) + domain_name[i+1:]
                    mutations.add(f"{mutation}.{domain_parts.suffix}")
        
        # Add mutations to our set
        self.mutations.update(mutations)
        
        logger.info(f"Generated {len(self.mutations)} domain mutations")
        
        # Write mutations to file
        with open(os.path.join(self.output_dir, "mutations.txt"), "w") as f:
            for mutation in sorted(self.mutations):
                f.write(f"{mutation}\n")
                
        return self.mutations

    def aggregate_and_normalize(self):
        """
        Aggregate and normalize all candidate domains.
        """
        logger.info("Step 4: Aggregating and normalizing candidates")
        
        # Combine subdomains and mutations
        all_domains = self.subdomains.union(self.mutations)
        
        # Normalize domains
        normalized_domains = set()
        for domain in all_domains:
            # Convert to lowercase
            normalized = domain.lower()
            
            # Convert punycode if needed
            try:
                if 'xn--' in normalized:
                    normalized = normalized.encode('idna').decode('utf-8')
            except:
                pass
                
            normalized_domains.add(normalized)
        
        # Remove duplicates
        unique_domains = set(normalized_domains)
        
        logger.info(f"Aggregated and normalized {len(unique_domains)} unique domains")
        
        # Write normalized domains to file
        with open(os.path.join(self.output_dir, "normalized_domains.txt"), "w") as f:
            for domain in sorted(unique_domains):
                f.write(f"{domain}\n")
                
        return unique_domains

    def resolve_dns(self, domains):
        """
        Resolve DNS for candidate domains using SanicDNS or similar fast resolver.
        """
        logger.info("Step 5: Resolving DNS for candidate domains")
        
        resolved = set()
        
        # In a real implementation, you would use SanicDNS or another fast resolver
        # For demonstration, we'll use Python's dns.resolver
        
        def resolve_domain(domain):
            try:
                answers = dns.resolver.resolve(domain, 'A')
                ip_addresses = [rdata.address for rdata in answers]
                return domain, ip_addresses
            except:
                return domain, None
        
        # Use ThreadPoolExecutor for parallel resolution
        with ThreadPoolExecutor(max_workers=self.max_threads) as executor:
            future_to_domain = {executor.submit(resolve_domain, domain): domain for domain in domains}
            
            for future in tqdm(as_completed(future_to_domain), total=len(domains), desc="Resolving domains"):
                domain, ip_addresses = future.result()
                if ip_addresses:
                    resolved.add(domain)
                    logger.debug(f"Resolved {domain} to {ip_addresses}")
        
        self.resolved_domains = resolved
        
        logger.info(f"Resolved {len(resolved)} domains out of {len(domains)}")
        
        # Write resolved domains to file
        with open(os.path.join(self.output_dir, "resolved_domains.txt"), "w") as f:
            for domain in sorted(resolved):
                f.write(f"{domain}\n")
                
        return resolved

    def enrich_and_validate(self):
        """
        Enrich and validate resolved domains with additional information.
        """
        logger.info("Step 6: Enriching and validating resolved domains")
        
        enriched_domains = []
        
        for domain in tqdm(self.resolved_domains, desc="Enriching domains"):
            try:
                domain_info = {
                    "domain": domain,
                    "whois": self._get_whois_info(domain),
                    "ssl": self._get_ssl_info(domain),
                    "http": self._get_http_info(domain),
                    "similarity": self._calculate_similarity(domain)
                }
                
                enriched_domains.append(domain_info)
                
            except Exception as e:
                logger.error(f"Error enriching domain {domain}: {str(e)}")
        
        self.enriched_domains = enriched_domains
        
        logger.info(f"Enriched {len(enriched_domains)} domains")
        
        # Write enriched domains to file
        with open(os.path.join(self.output_dir, "enriched_domains.json"), "w") as f:
            json.dump(enriched_domains, f, indent=2, default=str)
            
        return enriched_domains

    def _get_whois_info(self, domain):
        """Get WHOIS information for a domain."""
        try:
            w = whois.whois(domain)
            return {
                "registrar": w.registrar,
                "creation_date": w.creation_date,
                "expiration_date": w.expiration_date,
                "updated_date": w.updated_date,
                "name_servers": w.name_servers
            }
        except:
            return {"error": "Failed to retrieve WHOIS information"}

    def _get_ssl_info(self, domain):
        """Get SSL certificate information for a domain."""
        # In a real implementation, you would use sslyze or OpenSSL
        # For demonstration, we'll return placeholder data
        return {
            "issuer": "Example CA",
            "valid_from": "2023-01-01",
            "valid_to": "2024-01-01",
            "subject": f"CN={domain}",
            "sans": [domain, f"www.{domain}"]
        }

    def _get_http_info(self, domain):
        """Get HTTP information for a domain."""
        try:
            url = f"https://{domain}"
            response = requests.get(url, timeout=5, allow_redirects=True)
            
            # Parse HTML
            soup = BeautifulSoup(response.text, 'lxml')
            
            return {
                "status_code": response.status_code,
                "final_url": response.url,
                "redirects": len(response.history),
                "server": response.headers.get('Server', ''),
                "title": soup.title.string if soup.title else '',
                "has_login_form": bool(soup.find('form') and (soup.find('input', {'type': 'password'}) or 'login' in response.text.lower())),
                "content_length": len(response.text)
            }
        except:
            try:
                # Try HTTP if HTTPS fails
                url = f"http://{domain}"
                response = requests.get(url, timeout=5, allow_redirects=True)
                
                # Parse HTML
                soup = BeautifulSoup(response.text, 'lxml')
                
                return {
                    "status_code": response.status_code,
                    "final_url": response.url,
                    "redirects": len(response.history),
                    "server": response.headers.get('Server', ''),
                    "title": soup.title.string if soup.title else '',
                    "has_login_form": bool(soup.find('form') and (soup.find('input', {'type': 'password'}) or 'login' in response.text.lower())),
                    "content_length": len(response.text)
                }
            except:
                return {"error": "Failed to retrieve HTTP information"}

    def _calculate_similarity(self, domain):
        """Calculate similarity between this domain and the target domain."""
        # In a real implementation, you would use more sophisticated similarity metrics
        # For demonstration, we'll use a simple Levenshtein distance
        
        domain_parts = tldextract.extract(domain)
        target_parts = tldextract.extract(self.target_domain)
        
        domain_name = domain_parts.domain
        target_name = target_parts.domain
        
        # Calculate Levenshtein distance
        distance = self._levenshtein_distance(domain_name, target_name)
        
        # Calculate similarity score (0-100)
        max_len = max(len(domain_name), len(target_name))
        similarity = (1 - (distance / max_len)) * 100
        
        return {
            "levenshtein_distance": distance,
            "similarity_score": similarity
        }

    def _levenshtein_distance(self, s1, s2):
        """Calculate the Levenshtein distance between two strings."""
        if len(s1) < len(s2):
            return self._levenshtein_distance(s2, s1)
        
        if len(s2) == 0:
            return len(s1)
        
        previous_row = range(len(s2) + 1)
        for i, c1 in enumerate(s1):
            current_row = [i + 1]
            for j, c2 in enumerate(s2):
                insertions = previous_row[j + 1] + 1
                deletions = current_row[j] + 1
                substitutions = previous_row[j] + (c1 != c2)
                current_row.append(min(insertions, deletions, substitutions))
            previous_row = current_row
        
        return previous_row[-1]

    def score_and_triage(self):
        """
        Score and triage enriched domains to identify potential phishing domains.
        """
        logger.info("Step 7: Scoring and triaging enriched domains")
        
        scored_domains = []
        
        for domain_info in self.enriched_domains:
            score = 0
            risk_factors = []
            
            # Factor 1: Domain similarity
            similarity = domain_info.get("similarity", {}).get("similarity_score", 0)
            if similarity > 80:
                score += 30
                risk_factors.append(f"High similarity to target domain ({similarity:.1f}%)")
            elif similarity > 60:
                score += 15
                risk_factors.append(f"Medium similarity to target domain ({similarity:.1f}%)")
            
            # Factor 2: Domain age
            whois_info = domain_info.get("whois", {})
            creation_date = whois_info.get("creation_date")
            
            if creation_date:
                if isinstance(creation_date, list):
                    creation_date = creation_date[0]
                
                try:
                    domain_age_days = (datetime.datetime.now() - creation_date).days
                    if domain_age_days < 30:
                        score += 25
                        risk_factors.append(f"Recently registered domain ({domain_age_days} days old)")
                    elif domain_age_days < 90:
                        score += 15
                        risk_factors.append(f"Domain registered within last 3 months ({domain_age_days} days old)")
                except:
                    pass
            
            # Factor 3: SSL certificate
            ssl_info = domain_info.get("ssl", {})
            if "error" in ssl_info:
                score += 10
                risk_factors.append("No SSL certificate")
            
            # Factor 4: Login form
            http_info = domain_info.get("http", {})
            if http_info.get("has_login_form", False):
                score += 20
                risk_factors.append("Contains login form")
            
            # Factor 5: Redirects
            redirects = http_info.get("redirects", 0)
            if redirects > 0:
                score += 10
                risk_factors.append(f"Uses {redirects} redirects")
            
            # Determine risk level
            risk_level = "Low"
            if score >= 70:
                risk_level = "Critical"
            elif score >= 50:
                risk_level = "High"
            elif score >= 30:
                risk_level = "Medium"
            
            # Add score and risk level to domain info
            domain_info["risk_score"] = score
            domain_info["risk_level"] = risk_level
            domain_info["risk_factors"] = risk_factors
            
            scored_domains.append(domain_info)
        
        # Sort domains by risk score (descending)
        scored_domains.sort(key=lambda x: x["risk_score"], reverse=True)
        
        # Write scored domains to file
        with open(os.path.join(self.output_dir, "scored_domains.json"), "w") as f:
            json.dump(scored_domains, f, indent=2, default=str)
        
        logger.info(f"Scored {len(scored_domains)} domains")
        logger.info(f"Critical risk: {sum(1 for d in scored_domains if d['risk_level'] == 'Critical')}")
        logger.info(f"High risk: {sum(1 for d in scored_domains if d['risk_level'] == 'High')}")
        logger.info(f"Medium risk: {sum(1 for d in scored_domains if d['risk_level'] == 'Medium')}")
        logger.info(f"Low risk: {sum(1 for d in scored_domains if d['risk_level'] == 'Low')}")
        
        return scored_domains

    def generate_report(self, scored_domains):
        """
        Generate a report of potential phishing domains.
        """
        logger.info("Step 8: Generating report")
        
        # Generate CSV report
        csv_file = os.path.join(self.output_dir, "phishing_report.csv")
        with open(csv_file, "w", newline="") as f:
            writer = csv.writer(f)
            writer.writerow([
                "Domain", "Risk Level", "Risk Score", "Risk Factors", 
                "Similarity Score", "Domain Age (days)", "Has Login Form",
                "Redirects", "SSL Valid", "HTTP Status"
            ])
            
            for domain in scored_domains:
                # Calculate domain age
                whois_info = domain.get("whois", {})
                creation_date = whois_info.get("creation_date")
                domain_age = ""
                
                if creation_date:
                    if isinstance(creation_date, list):
                        creation_date = creation_date[0]
                    
                    try:
                        domain_age = (datetime.datetime.now() - creation_date).days
                    except:
                        domain_age = "Unknown"
                
                writer.writerow([
                    domain["domain"],
                    domain["risk_level"],
                    domain["risk_score"],
                    ", ".join(domain["risk_factors"]),
                    domain.get("similarity", {}).get("similarity_score", ""),
                    domain_age,
                    domain.get("http", {}).get("has_login_form", ""),
                    domain.get("http", {}).get("redirects", ""),
                    "No" if "error" in domain.get("ssl", {}) else "Yes",
                    domain.get("http", {}).get("status_code", "")
                ])
        
        # Generate HTML report
        html_file = os.path.join(self.output_dir, "phishing_report.html")
        with open(html_file, "w") as f:
            f.write(f"""<!DOCTYPE html>
<html>
<head>
    <title>Phishing Domain Report for {self.target_domain}</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 20px; }}
        h1, h2 {{ color: #333; }}
        table {{ border-collapse: collapse; width: 100%; margin-top: 20px; }}
        th, td {{ border: 1px solid #ddd; padding: 8px; text-align: left; }}
        th {{ background-color: #f2f2f2; }}
        tr:nth-child(even) {{ background-color: #f9f9f9; }}
        .critical {{ background-color: #ffdddd; }}
        .high {{ background-color: #ffffcc; }}
        .medium {{ background-color: #e6f2ff; }}
        .summary {{ margin: 20px 0; padding: 10px; background-color: #f2f2f2; border-radius: 5px; }}
    </style>
</head>
<body>
    <h1>Phishing Domain Report</h1>
    <p>Target Domain: <strong>{self.target_domain}</strong></p>
    <p>Report Generated: <strong>{datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</strong></p>
    
    <div class="summary">
        <h2>Summary</h2>
        <p>Total domains analyzed: <strong>{len(scored_domains)}</strong></p>
        <p>Critical risk domains: <strong>{sum(1 for d in scored_domains if d['risk_level'] == 'Critical')}</strong></p>
        <p>High risk domains: <strong>{sum(1 for d in scored_domains if d['risk_level'] == 'High')}</strong></p>
        <p>Medium risk domains: <strong>{sum(1 for d in scored_domains if d['risk_level'] == 'Medium')}</strong></p>
        <p>Low risk domains: <strong>{sum(1 for d in scored_domains if d['risk_level'] == 'Low')}</strong></p>
    </div>
    
    <h2>Potential Phishing Domains</h2>
    <table>
        <tr>
            <th>Domain</th>
            <th>Risk Level</th>
            <th>Risk Score</th>
            <th>Risk Factors</th>
            <th>Similarity</th>
            <th>Domain Age</th>
            <th>Has Login</th>
        </tr>
""")
            
            for domain in scored_domains:
                # Calculate domain age
                whois_info = domain.get("whois", {})
                creation_date = whois_info.get("creation_date")
                domain_age = "Unknown"
                
                if creation_date:
                    if isinstance(creation_date, list):
                        creation_date = creation_date[0]
                    
                    try:
                        domain_age = f"{(datetime.datetime.now() - creation_date).days} days"
                    except:
                        domain_age = "Unknown"
                
                risk_class = domain["risk_level"].lower()
                
                f.write(f"""
        <tr class="{risk_class}">
            <td>{domain["domain"]}</td>
            <td>{domain["risk_level"]}</td>
            <td>{domain["risk_score"]}</td>
            <td>{"<br>".join(domain["risk_factors"])}</td>
            <td>{domain.get("similarity", {}).get("similarity_score", ""):.1f}%</td>
            <td>{domain_age}</td>
            <td>{"Yes" if domain.get("http", {}).get("has_login_form", False) else "No"}</td>
        </tr>""")
            
            f.write("""
    </table>
</body>
</html>""")
        
        logger.info(f"Generated CSV report: {csv_file}")
        logger.info(f"Generated HTML report: {html_file}")
        
        return {
            "csv_report": csv_file,
            "html_report": html_file
        }

    def archive_evidence(self, high_risk_domains):
        """
        Archive evidence for high-risk domains.
        """
        logger.info("Step 9: Archiving evidence for high-risk domains")
        
        # Create archive directory
        archive_dir = os.path.join(self.output_dir, "evidence")
        os.makedirs(archive_dir, exist_ok=True)
        
        # In a real implementation, you would:
        # 1. Take screenshots of the websites
        # 2. Save HTML content
        # 3. Save HTTP headers
        # 4. Save SSL certificates
        
        # For demonstration, we'll just create placeholder files
        for domain in high_risk_domains:
            domain_name = domain["domain"]
            domain_dir = os.path.join(archive_dir, domain_name.replace(".", "_"))
            os.makedirs(domain_dir, exist_ok=True)
            
            # Save domain info as JSON
            with open(os.path.join(domain_dir, "domain_info.json"), "w") as f:
                json.dump(domain, f, indent=2, default=str)
            
            # Create placeholder for screenshot
            with open(os.path.join(domain_dir, "screenshot.txt"), "w") as f:
                f.write(f"Screenshot of {domain_name} would be saved here")
            
            # Create placeholder for HTML content
            with open(os.path.join(domain_dir, "content.html"), "w") as f:
                f.write(f"<html><body><h1>HTML content of {domain_name} would be saved here</h1></body></html>")
            
            # Create placeholder for HTTP headers
            with open(os.path.join(domain_dir, "headers.txt"), "w") as f:
                f.write(f"HTTP headers of {domain_name} would be saved here")
            
            # Create placeholder for SSL certificate
            with open(os.path.join(domain_dir, "certificate.txt"), "w") as f:
                f.write(f"SSL certificate of {domain_name} would be saved here")
        
        logger.info(f"Archived evidence for {len(high_risk_domains)} high-risk domains")
        
        return archive_dir

    def run(self):
        """
        Run the complete phishing domain crawling workflow.
        """
        logger.info(f"Starting phishing domain crawling workflow for {self.target_domain}")
        
        # Step 1: Canonicalize and scope
        scope_info = self.canonicalize_and_scope()
        
        # Step 2: Discover subdomains
        self.discover_subdomains()
        
        # Step 3: Generate mutations
        self.generate_mutations()
        
        # Step 4: Aggregate and normalize
        normalized_domains = self.aggregate_and_normalize()
        
        # Step 5: Resolve DNS
        self.resolve_dns(normalized_domains)
        
        # Step 6: Enrich and validate
        self.enrich_and_validate()
        
        # Step 7: Score and triage
        scored_domains = self.score_and_triage()
        
        # Step 8: Generate report
        reports = self.generate_report(scored_domains)
        
        # Step 9: Archive evidence for high-risk domains
        high_risk_domains = [d for d in scored_domains if d["risk_level"] in ["Critical", "High"]]
        archive_dir = self.archive_evidence(high_risk_domains)
        
        logger.info(f"Phishing domain crawling workflow completed for {self.target_domain}")
        logger.info(f"Results saved to {self.output_dir}")
        logger.info(f"CSV report: {reports['csv_report']}")
        logger.info(f"HTML report: {reports['html_report']}")
        logger.info(f"Evidence archived in: {archive_dir}")
        
        return {
            "target_domain": self.target_domain,
            "subdomains": len(self.subdomains),
            "mutations": len(self.mutations),
            "resolved_domains": len(self.resolved_domains),
            "high_risk_domains": len(high_risk_domains),
            "reports": reports,
            "archive_dir": archive_dir
        }


def main():
    """Main function to run the phishing domain crawler."""
    parser = argparse.ArgumentParser(description="Phishing Domain Crawler")
    parser.add_argument("domain", help="Target domain to analyze")
    parser.add_argument("-o", "--output", default="output", help="Output directory")
    parser.add_argument("-t", "--threads", type=int, default=10, help="Maximum number of threads")
    args = parser.parse_args()
    
    try:
        crawler = PhishingCrawler(args.domain, args.output, args.threads)
        results = crawler.run()
        
        print("\nPhishing Domain Crawler completed successfully!")
        print(f"Target domain: {results['target_domain']}")
        print(f"Subdomains discovered: {results['subdomains']}")
        print(f"Mutations generated: {results['mutations']}")
        print(f"Resolved domains: {results['resolved_domains']}")
        print(f"High-risk domains: {results['high_risk_domains']}")
        print(f"Reports saved to: {args.output}")
        print(f"CSV report: {results['reports']['csv_report']}")
        print(f"HTML report: {results['reports']['html_report']}")
        print(f"Evidence archived in: {results['archive_dir']}")
        
    except Exception as e:
        logger.error(f"Error running phishing domain crawler: {str(e)}")
        sys.exit(1)


if __name__ == "__main__":
    main()