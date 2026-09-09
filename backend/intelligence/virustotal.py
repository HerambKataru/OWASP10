import base64
import requests
from typing import Dict, Any

class VirusTotalClient:
    def __init__(self, api_key: str = ""):
        self.api_key = api_key
        self.base_url = "https://www.virustotal.com/api/v3"

    def get_headers(self) -> Dict[str, str]:
        return {"x-apikey": self.api_key, "Accept": "application/json"}

    def scan_domain(self, domain: str) -> Dict[str, Any]:
        if not self.api_key:
            return {
                "success": False,
                "mock": True,
                "domain": domain,
                "malicious": 0,
                "suspicious": 0,
                "harmless": 72,
                "undetected": 15,
                "reputation": 95,
                "status": "No API key configured (Settings -> Threat Intel)"
            }
        
        try:
            url = f"{self.base_url}/domains/{domain}"
            res = requests.get(url, headers=self.get_headers(), timeout=10)
            if res.status_code == 200:
                data = res.json().get("data", {}).get("attributes", {})
                stats = data.get("last_analysis_stats", {})
                return {
                    "success": True,
                    "domain": domain,
                    "malicious": stats.get("malicious", 0),
                    "suspicious": stats.get("suspicious", 0),
                    "harmless": stats.get("harmless", 0),
                    "undetected": stats.get("undetected", 0),
                    "reputation": data.get("reputation", 0),
                    "categories": data.get("categories", {}),
                    "whois": data.get("whois", "")[:500]
                }
            return {"success": False, "error": f"HTTP {res.status_code}: {res.text[:100]}"}
        except Exception as e:
            return {"success": False, "error": str(e)}

    def scan_url(self, target_url: str) -> Dict[str, Any]:
        if not self.api_key:
            return {
                "success": False,
                "mock": True,
                "url": target_url,
                "malicious": 0,
                "suspicious": 0,
                "harmless": 68,
                "undetected": 18,
                "status": "No API key configured"
            }
        
        try:
            # VT URL ID is base64 encoded without '='
            url_id = base64.urlsafe_b64encode(target_url.encode()).decode().strip("=")
            url = f"{self.base_url}/urls/{url_id}"
            res = requests.get(url, headers=self.get_headers(), timeout=10)
            if res.status_code == 200:
                data = res.json().get("data", {}).get("attributes", {})
                stats = data.get("last_analysis_stats", {})
                return {
                    "success": True,
                    "url": target_url,
                    "malicious": stats.get("malicious", 0),
                    "suspicious": stats.get("suspicious", 0),
                    "harmless": stats.get("harmless", 0),
                    "undetected": stats.get("undetected", 0),
                    "threat_severity": "High" if stats.get("malicious", 0) > 0 else "Clean"
                }
            return {"success": False, "error": f"HTTP {res.status_code}"}
        except Exception as e:
            return {"success": False, "error": str(e)}

    def lookup_hash(self, file_hash: str) -> Dict[str, Any]:
        if not self.api_key:
            return {
                "success": False,
                "mock": True,
                "hash": file_hash,
                "malicious": 0,
                "suspicious": 0,
                "harmless": 50,
                "status": "No API key configured"
            }
        try:
            url = f"{self.base_url}/files/{file_hash}"
            res = requests.get(url, headers=self.get_headers(), timeout=10)
            if res.status_code == 200:
                data = res.json().get("data", {}).get("attributes", {})
                stats = data.get("last_analysis_stats", {})
                return {
                    "success": True,
                    "hash": file_hash,
                    "malicious": stats.get("malicious", 0),
                    "suspicious": stats.get("suspicious", 0),
                    "harmless": stats.get("harmless", 0),
                    "meaningful_name": data.get("meaningful_name", "Unknown"),
                    "size": data.get("size", 0)
                }
            return {"success": False, "error": f"HTTP {res.status_code}"}
        except Exception as e:
            return {"success": False, "error": str(e)}
