import requests
from typing import Dict, Any

class AbuseIPDBClient:
    def __init__(self, api_key: str = ""):
        self.api_key = api_key
        self.base_url = "https://api.abuseipdb.com/api/v2"

    def check_ip(self, ip_address: str) -> Dict[str, Any]:
        if not self.api_key:
            return {
                "success": True,
                "mock": True,
                "ipAddress": ip_address,
                "abuseConfidenceScore": 0,
                "countryCode": "US",
                "countryName": "United States",
                "isp": "Local / Cloudflare Mock ISP",
                "usageType": "Data Center/Web Hosting/Transit",
                "domain": "example.com",
                "totalReports": 0,
                "lastReportedAt": "Never",
                "severity_color": "green",
                "status": "No API Key configured (Settings -> AbuseIPDB)"
            }

        try:
            headers = {
                "Key": self.api_key,
                "Accept": "application/json"
            }
            params = {
                "ipAddress": ip_address,
                "maxAgeInDays": 90,
                "verbose": True
            }
            res = requests.get(f"{self.base_url}/check", headers=headers, params=params, timeout=10)
            if res.status_code == 200:
                data = res.json().get("data", {})
                score = data.get("abuseConfidenceScore", 0)
                
                # Determine color severity
                if score >= 75:
                    color = "red"
                elif score >= 25:
                    color = "yellow"
                else:
                    color = "green"

                return {
                    "success": True,
                    "mock": False,
                    "ipAddress": data.get("ipAddress"),
                    "abuseConfidenceScore": score,
                    "countryCode": data.get("countryCode"),
                    "countryName": data.get("countryName"),
                    "isp": data.get("isp"),
                    "usageType": data.get("usageType"),
                    "domain": data.get("domain"),
                    "totalReports": data.get("totalReports", 0),
                    "lastReportedAt": data.get("lastReportedAt", "N/A"),
                    "severity_color": color,
                    "isWhitelisted": data.get("isWhitelisted", False)
                }
            return {"success": False, "error": f"HTTP {res.status_code}: {res.text[:100]}"}
        except Exception as e:
            return {"success": False, "error": str(e)}
