"""
llm_assistant.py
----------------
Stub interface for on-prem LLM integration.

Usage:
    from llm_assistant import classify
    result = classify(feature_json)

This stub returns a deterministic placeholder response.
"""
from typing import Dict, Any

def classify(features: Dict[str, Any]) -> Dict[str, Any]:
    """Accept a JSON feature object and return a JSON label/suggested_rules.
    No LLM logic is implemented here; this is only an interface stub.
    """
    domain = features.get('Domain', '')
    risk = 'low'
    score = features.get('URLSimilarityIndex', 0.0)
    if score > 0.8 or features.get('HasObfuscation', False):
        risk = 'medium'
    if features.get('suspicious_tld', False) and score > 0.9:
        risk = 'high'
    return {
        'label': risk,
        'suggested_rules': [
            {'rule': 'block_high_risk_domains', 'enabled': True},
            {'rule': 'alert_medium_risk_similarity', 'enabled': True},
        ]
    }