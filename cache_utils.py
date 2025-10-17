import os
import json
import threading
from typing import Any, Dict

class JSONCache:
    """Simple JSON-backed cache for one-shot runs.
    Data is persisted under a category (e.g., 'dns', 'whois', 'http').
    """

    def __init__(self, base_dir: str):
        self.base_dir = base_dir
        os.makedirs(self.base_dir, exist_ok=True)
        self._lock = threading.Lock()
        self._stores: Dict[str, Dict[str, Any]] = {}

    def _path(self, category: str) -> str:
        return os.path.join(self.base_dir, f"{category}.json")

    def _ensure_loaded(self, category: str):
        if category in self._stores:
            return
        path = self._path(category)
        if os.path.exists(path):
            try:
                with open(path, 'r', encoding='utf-8') as f:
                    self._stores[category] = json.load(f)
            except Exception:
                self._stores[category] = {}
        else:
            self._stores[category] = {}

    def get(self, category: str, key: str) -> Any:
        with self._lock:
            self._ensure_loaded(category)
            return self._stores.get(category, {}).get(key)

    def set(self, category: str, key: str, value: Any):
        with self._lock:
            self._ensure_loaded(category)
            self._stores[category][key] = value
            # Write-through
            path = self._path(category)
            try:
                with open(path, 'w', encoding='utf-8') as f:
                    json.dump(self._stores[category], f, indent=2, ensure_ascii=False)
            except Exception:
                # Best effort; do not crash pipeline
                pass