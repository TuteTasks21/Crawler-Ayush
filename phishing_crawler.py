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
import time
import hashlib
import pickle
import numpy as np
from urllib.parse import urlparse
from bs4 import BeautifulSoup
from tqdm import tqdm
from concurrent.futures import ThreadPoolExecutor, as_completed
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.ensemble import IsolationForest
from sentence_transformers import SentenceTransformer
from functools import lru_cache
import traceback
import shutil

# Configure logging
def setup_logging(log_level=logging.INFO, log_file="phishing_crawler.log"):
    """Set up logging with file and console handlers"""
    # Create logs directory if it doesn't exist
    log_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "logs")
    os.makedirs(log_dir, exist_ok=True)
    
    # Set up log file with timestamp
    timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    log_file_path = os.path.join(log_dir, f"{timestamp}_{log_file}")
    
    # Configure logging
    logging.basicConfig(
        level=log_level,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        handlers=[
            logging.FileHandler(log_file_path),
            logging.StreamHandler()
        ]
    )
    return logging.getLogger("PhishingCrawler")

# Initialize logger
logger = setup_logging()

class CacheManager:
    """Manages caching for expensive operations to improve performance"""
    
    def __init__(self, cache_dir="cache", max_cache_size_mb=500):
        """Initialize the cache manager with specified directory and size limit"""
        self.cache_dir = cache_dir
        self.max_cache_size_mb = max_cache_size_mb
        
        # Create cache directory if it doesn't exist
        os.makedirs(self.cache_dir, exist_ok=True)
        
        # Initialize cache stats
        self.hits = 0
        self.misses = 0
        
        # Clean cache if needed
        self._clean_cache_if_needed()
        
        logger.info(f"Cache initialized at {self.cache_dir} with {max_cache_size_mb}MB limit")
    
    def _get_cache_key(self, prefix, data):
        """Generate a unique cache key for the data"""
        if isinstance(data, str):
            data_str = data
        else:
            data_str = json.dumps(data, sort_keys=True)
        
        return f"{prefix}_{hashlib.md5(data_str.encode()).hexdigest()}"
    
    def _get_cache_path(self, key):
        """Get the file path for a cache key"""
        return os.path.join(self.cache_dir, f"{key}.cache")
    
    def _clean_cache_if_needed(self):
        """Clean the cache if it exceeds the size limit"""
        try:
            # Get total size of cache directory
            total_size = sum(os.path.getsize(os.path.join(self.cache_dir, f)) 
                            for f in os.listdir(self.cache_dir) 
                            if os.path.isfile(os.path.join(self.cache_dir, f)))
            
            total_size_mb = total_size / (1024 * 1024)
            
            if total_size_mb > self.max_cache_size_mb:
                logger.info(f"Cache size ({total_size_mb:.2f}MB) exceeds limit ({self.max_cache_size_mb}MB). Cleaning...")
                
                # Get all cache files with their modification times
                cache_files = [(f, os.path.getmtime(os.path.join(self.cache_dir, f))) 
                              for f in os.listdir(self.cache_dir) 
                              if os.path.isfile(os.path.join(self.cache_dir, f))]
                
                # Sort by modification time (oldest first)
                cache_files.sort(key=lambda x: x[1])
                
                # Remove oldest files until we're under the limit
                for f, _ in cache_files:
                    if total_size_mb <= self.max_cache_size_mb * 0.8:  # Clean until we're at 80% of limit
                        break
                    
                    file_path = os.path.join(self.cache_dir, f)
                    file_size = os.path.getsize(file_path) / (1024 * 1024)
                    
                    try:
                        os.remove(file_path)
                        total_size_mb -= file_size
                        logger.debug(f"Removed cache file {f} ({file_size:.2f}MB)")
                    except Exception as e:
                        logger.error(f"Failed to remove cache file {f}: {str(e)}")
        
        except Exception as e:
            logger.error(f"Error cleaning cache: {str(e)}")
    
    def get(self, prefix, data):
        """Get data from cache if it exists"""
        key = self._get_cache_key(prefix, data)
        cache_path = self._get_cache_path(key)
        
        if os.path.exists(cache_path):
            try:
                with open(cache_path, 'rb') as f:
                    cached_data = pickle.load(f)
                
                self.hits += 1
                logger.debug(f"Cache hit for {prefix} ({self.hits} hits, {self.misses} misses)")
                return cached_data
            except Exception as e:
                logger.error(f"Error reading from cache: {str(e)}")
                self.misses += 1
                return None
        else:
            self.misses += 1
            logger.debug(f"Cache miss for {prefix} ({self.hits} hits, {self.misses} misses)")
            return None
    
    def set(self, prefix, data, result):
        """Store data in cache"""
        key = self._get_cache_key(prefix, data)
        cache_path = self._get_cache_path(key)
        
        try:
            with open(cache_path, 'wb') as f:
                pickle.dump(result, f)
            
            logger.debug(f"Cached result for {prefix}")
            return True
        except Exception as e:
            logger.error(f"Error writing to cache: {str(e)}")
            return False
    
    def clear(self):
        """Clear all cache files"""
        try:
            for f in os.listdir(self.cache_dir):
                file_path = os.path.join(self.cache_dir, f)
                if os.path.isfile(file_path):
                    os.remove(file_path)
            
            logger.info("Cache cleared")
            return True
        except Exception as e:
            logger.error(f"Error clearing cache: {str(e)}")
            return False
    
    def get_stats(self):
        """Get cache statistics"""
        try:
            # Get total size of cache directory
            total_size = sum(os.path.getsize(os.path.join(self.cache_dir, f)) 
                            for f in os.listdir(self.cache_dir) 
                            if os.path.isfile(os.path.join(self.cache_dir, f)))
            
            total_size_mb = total_size / (1024 * 1024)
            file_count = len([f for f in os.listdir(self.cache_dir) if os.path.isfile(os.path.join(self.cache_dir, f))])
            
            hit_rate = self.hits / (self.hits + self.misses) * 100 if (self.hits + self.misses) > 0 else 0
            
            return {
                "size_mb": total_size_mb,
                "file_count": file_count,
                "hits": self.hits,
                "misses": self.misses,
                "hit_rate": hit_rate
            }
        except Exception as e:
            logger.error(f"Error getting cache stats: {str(e)}")
            return {
                "error": str(e)
            }


class LocalLLMPhishingDetector:
    """
    Local LLM-based phishing detection using sentence embeddings and anomaly detection.
    This avoids using third-party APIs by implementing local ML techniques.
    """
    def __init__(self, cache_dir="cache"):
        """Initialize the LLM-based phishing detector with local models."""
        self.cache_dir = cache_dir
        os.makedirs(cache_dir, exist_ok=True)
        
        # Initialize sentence transformer model for text embeddings
        try:
            self.model = SentenceTransformer('all-MiniLM-L6-v2')
            logger.info("Loaded sentence transformer model for text embeddings")
        except Exception as e:
            logger.error(f"Failed to load sentence transformer model: {str(e)}")
            self.model = None
            
        # Initialize anomaly detection model
        self.anomaly_detector = IsolationForest(contamination=0.1, random_state=42)
        
        # Initialize TF-IDF vectorizer for content analysis
        self.tfidf = TfidfVectorizer(max_features=1000)
        
        # Cache for domain embeddings and scores
        self.embedding_cache_file = os.path.join(cache_dir, "domain_embeddings.pkl")
        self.load_cache()
        
    def load_cache(self):
        """Load cached embeddings and scores if available."""
        try:
            if os.path.exists(self.embedding_cache_file):
                with open(self.embedding_cache_file, 'rb') as f:
                    self.cache = pickle.load(f)
                logger.info(f"Loaded {len(self.cache)} cached domain embeddings")
            else:
                self.cache = {}
        except Exception as e:
            logger.error(f"Failed to load cache: {str(e)}")
            self.cache = {}
            
    def save_cache(self):
        """Save embeddings and scores to cache."""
        try:
            with open(self.embedding_cache_file, 'wb') as f:
                pickle.dump(self.cache, f)
            logger.info(f"Saved {len(self.cache)} domain embeddings to cache")
        except Exception as e:
            logger.error(f"Failed to save cache: {str(e)}")
            
    def get_domain_features(self, domain_info):
        """Extract features from domain information for analysis."""
        features = []
        
        # Domain name features
        domain = domain_info.get("domain", "")
        features.append(domain)
        
        # WHOIS features
        whois_info = domain_info.get("whois", {})
        if whois_info and not isinstance(whois_info, dict):
            whois_info = {}
            
        registrar = str(whois_info.get("registrar", ""))
        features.append(registrar)
        
        # HTTP features
        http_info = domain_info.get("http", {})
        if http_info and not isinstance(http_info, dict):
            http_info = {}
            
        title = str(http_info.get("title", ""))
        features.append(title)
        
        # Combine all text features
        text_features = " ".join([f for f in features if f])
        return text_features
        
    def get_embedding(self, text):
        """Get embedding for text using sentence transformer."""
        if not self.model or not text:
            return np.zeros(384)  # Default embedding size for all-MiniLM-L6-v2
            
        try:
            return self.model.encode(text)
        except Exception as e:
            logger.error(f"Failed to get embedding: {str(e)}")
            return np.zeros(384)
            
    def analyze_domain(self, domain_info):
        """Analyze domain using local LLM techniques."""
        domain = domain_info.get("domain", "")
        
        # Check cache first
        cache_key = domain
        if cache_key in self.cache:
            logger.debug(f"Using cached analysis for {domain}")
            return self.cache[cache_key]
            
        # Extract features
        features = self.get_domain_features(domain_info)
        
        # Get embedding
        embedding = self.get_embedding(features)
        
        # Calculate lexical features
        domain_parts = tldextract.extract(domain)
        domain_name = domain_parts.domain
        
        # Calculate entropy as a measure of randomness
        entropy = 0
        if domain_name:
            char_freq = {}
            for char in domain_name:
                if char in char_freq:
                    char_freq[char] += 1
                else:
                    char_freq[char] = 1
                    
            for char, freq in char_freq.items():
                prob = freq / len(domain_name)
                entropy -= prob * np.log2(prob)
                
        # Calculate digit ratio
        digit_ratio = sum(c.isdigit() for c in domain_name) / max(len(domain_name), 1)
        
        # Calculate special character ratio
        special_ratio = sum(not c.isalnum() for c in domain_name) / max(len(domain_name), 1)
        
        # Combine features for scoring
        score = {
            "embedding": embedding.tolist(),
            "entropy": float(entropy),
            "digit_ratio": float(digit_ratio),
            "special_ratio": float(special_ratio),
            "domain_length": len(domain_name),
            "timestamp": time.time()
        }
        
        # Cache the result
        self.cache[cache_key] = score
        
        # Periodically save cache
        if len(self.cache) % 10 == 0:
            self.save_cache()
            
        return score
        
    def detect_anomalies(self, domain_scores):
        """Detect anomalies in domain scores using Isolation Forest."""
        if not domain_scores:
            return {}
            
        # Extract features for anomaly detection
        features = []
        domains = []
        
        for domain, score in domain_scores.items():
            feature_vector = [
                score.get("entropy", 0),
                score.get("digit_ratio", 0),
                score.get("special_ratio", 0),
                score.get("domain_length", 0)
            ]
            features.append(feature_vector)
            domains.append(domain)
            
        if not features:
            return {}
            
        # Convert to numpy array
        features = np.array(features)
        
        # Fit and predict
        try:
            self.anomaly_detector.fit(features)
            anomaly_scores = self.anomaly_detector.decision_function(features)
            
            # Normalize scores to 0-1 range where 0 is most anomalous
            normalized_scores = (anomaly_scores - np.min(anomaly_scores)) / (np.max(anomaly_scores) - np.min(anomaly_scores) + 1e-10)
            
            # Create result dictionary
            result = {}
            for i, domain in enumerate(domains):
                result[domain] = 1.0 - normalized_scores[i]
                
            return result
        except Exception as e:
            logger.error(f"Failed to detect anomalies: {str(e)}")
            return {}

class PhishingCrawler:
    def __init__(self, target_domain, output_dir="output", max_threads=10, monitoring_interval=86400):
        """Initialize the phishing crawler with target domain and configuration."""
        self.target_domain = target_domain
        self.output_dir = output_dir
        self.max_threads = max_threads
        self.monitoring_interval = monitoring_interval  # Default: 24 hours in seconds
        
        # Create output directory if it doesn't exist
        os.makedirs(output_dir, exist_ok=True)
        
        # Create monitoring directory
        self.monitoring_dir = os.path.join(output_dir, "monitoring")
        os.makedirs(self.monitoring_dir, exist_ok=True)
        
        # Create cache directory
        self.cache_dir = os.path.join(output_dir, "cache")
        os.makedirs(self.cache_dir, exist_ok=True)
        
        # Extract domain components
        self.domain_info = tldextract.extract(target_domain)
        self.base_domain = f"{self.domain_info.domain}.{self.domain_info.suffix}"
        
        # Initialize results storage
        self.subdomains = set()
        self.mutations = set()
        self.resolved_domains = set()
        self.enriched_domains = []
        
        # Initialize LLM-based phishing detector
        self.llm_detector = LocalLLMPhishingDetector(cache_dir=self.cache_dir)
        
        # Initialize monitoring state
        self.monitoring_state_file = os.path.join(self.monitoring_dir, "monitoring_state.json")
        self.monitoring_state = self._load_monitoring_state()
        
        # Initialize retry mechanism
        self.max_retries = 3
        self.retry_delay = 5  # seconds
        
        logger.info(f"Initialized crawler for target domain: {target_domain}")
        logger.info(f"Base domain identified as: {self.base_domain}")
        
    def _load_monitoring_state(self):
        """Load monitoring state from file if it exists."""
        if os.path.exists(self.monitoring_state_file):
            try:
                with open(self.monitoring_state_file, 'r') as f:
                    return json.load(f)
            except Exception as e:
                logger.error(f"Failed to load monitoring state: {str(e)}")
                return self._initialize_monitoring_state()
        else:
            return self._initialize_monitoring_state()
            
    def _initialize_monitoring_state(self):
        """Initialize monitoring state with default values."""
        return {
            "last_run": None,
            "run_history": [],
            "domain_history": {},
            "alerts": []
        }
        
    def _save_monitoring_state(self):
        """Save current monitoring state to file."""
        try:
            with open(self.monitoring_state_file, 'w') as f:
                json.dump(self.monitoring_state, f, indent=2, default=str)
            logger.info("Saved monitoring state")
        except Exception as e:
            logger.error(f"Failed to save monitoring state: {str(e)}")
            
    def _update_domain_history(self, domain, data):
        """Update domain history in monitoring state."""
        if domain not in self.monitoring_state["domain_history"]:
            self.monitoring_state["domain_history"][domain] = []
            
        # Add current state with timestamp
        entry = {
            "timestamp": datetime.datetime.now().isoformat(),
            "data": data
        }
        
        self.monitoring_state["domain_history"][domain].append(entry)
        
        # Limit history size to prevent excessive growth
        if len(self.monitoring_state["domain_history"][domain]) > 10:
            self.monitoring_state["domain_history"][domain] = self.monitoring_state["domain_history"][domain][-10:]

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

    def _safe_request(self, url, method="get", timeout=10, max_retries=3, **kwargs):
        """
        Make a safe HTTP request with retry mechanism and error handling.
        """
        retry_count = 0
        while retry_count < max_retries:
            try:
                if method.lower() == "get":
                    response = requests.get(url, timeout=timeout, **kwargs)
                elif method.lower() == "post":
                    response = requests.post(url, timeout=timeout, **kwargs)
                else:
                    raise ValueError(f"Unsupported HTTP method: {method}")
                    
                return response
            except requests.exceptions.RequestException as e:
                retry_count += 1
                if retry_count >= max_retries:
                    logger.warning(f"Failed to {method} {url} after {max_retries} attempts: {str(e)}")
                    return None
                    
                logger.debug(f"Retrying {method} request to {url} ({retry_count}/{max_retries})")
                time.sleep(self.retry_delay)
                
        return None
        
    def _safe_dns_resolve(self, domain):
        """
        Safely resolve DNS with retry mechanism and error handling.
        """
        retry_count = 0
        while retry_count < self.max_retries:
            try:
                answers = dns.resolver.resolve(domain, 'A')
                ip_addresses = [rdata.address for rdata in answers]
                return domain, ip_addresses
            except Exception as e:
                retry_count += 1
                if retry_count >= self.max_retries:
                    logger.debug(f"Failed to resolve {domain} after {self.max_retries} attempts: {str(e)}")
                    return domain, None
                    
                logger.debug(f"Retrying DNS resolution for {domain} ({retry_count}/{self.max_retries})")
                time.sleep(self.retry_delay)
                
        return domain, None
                
    def _get_http_info(self, domain):
        """Get HTTP information for a domain with improved error handling."""
        # Try HTTPS first
        url = f"https://{domain}"
        response = self._safe_request(url, timeout=5, allow_redirects=True)
        
        # If HTTPS fails, try HTTP
        if not response:
            url = f"http://{domain}"
            response = self._safe_request(url, timeout=5, allow_redirects=True)
            
        # If both fail, return error
        if not response:
            return {"error": "Failed to connect to domain"}
            
        try:
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
        except Exception as e:
            logger.error(f"Error parsing HTTP response for {domain}: {str(e)}")
            return {"error": f"Failed to parse HTTP response: {str(e)}"}

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
        Score and triage enriched domains using LLM-based analysis.
        """
        logger.info("Step 7: Scoring and triaging enriched domains")
        
        # Prepare domain scores
        domain_scores = {}
        
        # Analyze each domain with LLM
        for domain_info in tqdm(self.enriched_domains, desc="Analyzing domains"):
            domain = domain_info.get("domain", "")
            
            # Skip if domain is empty
            if not domain:
                continue
                
            # Analyze domain using LLM
            score_data = self.llm_detector.analyze_domain(domain_info)
            
            # Store score data
            domain_scores[domain] = score_data
            
            # Update domain info with score data
            domain_info["llm_score"] = score_data
            
            # Update monitoring history
            self._update_domain_history(domain, domain_info)
            
        # Detect anomalies across all domains
        anomaly_scores = self.llm_detector.detect_anomalies(domain_scores)
        
        # Update domain info with anomaly scores
        for domain_info in self.enriched_domains:
            domain = domain_info.get("domain", "")
            if domain in anomaly_scores:
                domain_info["anomaly_score"] = anomaly_scores[domain]
                
        # Sort domains by anomaly score (highest first)
        self.enriched_domains.sort(key=lambda x: x.get("anomaly_score", 0), reverse=True)
        
        # Write scored domains to file
        with open(os.path.join(self.output_dir, "scored_domains.json"), "w") as f:
            json.dump(self.enriched_domains, f, indent=2, default=str)
            
        # Save monitoring state
        self._save_monitoring_state()
        
        logger.info(f"Scored and triaged {len(self.enriched_domains)} domains")
        
        return self.enriched_domains
        
    def monitor_domains(self, force=False):
        """
        Continuously monitor domains for changes over time.
        """
        logger.info("Starting domain monitoring")
        
        # Check if it's time to run monitoring
        last_run = self.monitoring_state.get("last_run")
        current_time = datetime.datetime.now()
        
        if last_run:
            last_run = datetime.datetime.fromisoformat(last_run)
            time_since_last_run = (current_time - last_run).total_seconds()
            
            if time_since_last_run < self.monitoring_interval and not force:
                logger.info(f"Skipping monitoring, last run was {time_since_last_run} seconds ago")
                return
        
        # Update last run time
        self.monitoring_state["last_run"] = current_time.isoformat()
        
        # Get previously resolved domains
        previous_domains = set()
        for run in self.monitoring_state.get("run_history", []):
            if "domains" in run:
                previous_domains.update(run.get("domains", []))
        
        # Run the crawler to get current domains
        self.canonicalize_and_scope()
        self.discover_subdomains()
        self.generate_mutations()
        normalized_domains = self.aggregate_and_normalize()
        current_domains = self.resolve_dns(normalized_domains)
        
        # Find new and disappeared domains
        new_domains = current_domains - previous_domains
        disappeared_domains = previous_domains - current_domains
        
        # Log changes
        if new_domains:
            logger.info(f"Found {len(new_domains)} new domains: {', '.join(list(new_domains)[:5])}...")
            
            # Add alert for new domains
            self.monitoring_state["alerts"].append({
                "timestamp": current_time.isoformat(),
                "type": "new_domains",
                "count": len(new_domains),
                "domains": list(new_domains)
            })
            
        if disappeared_domains:
            logger.info(f"Found {len(disappeared_domains)} disappeared domains: {', '.join(list(disappeared_domains)[:5])}...")
            
            # Add alert for disappeared domains
            self.monitoring_state["alerts"].append({
                "timestamp": current_time.isoformat(),
                "type": "disappeared_domains",
                "count": len(disappeared_domains),
                "domains": list(disappeared_domains)
            })
        
        # Update run history
        self.monitoring_state["run_history"].append({
            "timestamp": current_time.isoformat(),
            "domains": list(current_domains),
            "new_domains": list(new_domains),
            "disappeared_domains": list(disappeared_domains)
        })
        
        # Limit history size
        if len(self.monitoring_state["run_history"]) > 30:  # Keep last 30 runs
            self.monitoring_state["run_history"] = self.monitoring_state["run_history"][-30:]
            
        # Limit alerts size
        if len(self.monitoring_state["alerts"]) > 100:  # Keep last 100 alerts
            self.monitoring_state["alerts"] = self.monitoring_state["alerts"][-100:]
        
        # Save monitoring state
        self._save_monitoring_state()
        
        # If there are new domains, enrich and score them
        if new_domains:
            # Enrich only the new domains
            self.resolved_domains = new_domains
            self.enrich_and_validate()
            self.score_and_triage()
            
        logger.info("Domain monitoring completed")
        
        return {
            "new_domains": list(new_domains),
            "disappeared_domains": list(disappeared_domains),
            "total_domains": len(current_domains)
        }

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