import requests
from typing import Dict, Any

class ShodanClient:
    def __init__(self, api_key: str = ""):
        self.api_key = api_key
        self.base_url = "https://api.shodan.io"

    def host_info(self, ip_address: str) -> Dict[str, Any]:
        if not self.api_key:
            return {
                "success": True,
                "mock": True,
                "ip": ip_address,
                "ports": [80, 443, 8080],
                "hostnames": ["localhost", "local.target"],
                "org": "Internal / Mock Organization",
                "os": "Linux 5.x",
                "services": [
                    {"port": 80, "service": "http", "banner": "HTTP/1.1 200 OK\nServer: nginx/1.24.0"},
                    {"port": 443, "service": "https", "banner": "HTTP/1.1 200 OK\nServer: nginx/1.24.0 (SSL/TLS)"}
                ],
                "vulns": [],
                "status": "No Shodan API Key configured (Settings -> Shodan)"
            }

        try:
            url = f"{self.base_url}/shodan/host/{ip_address}?key={self.api_key}"
            res = requests.get(url, timeout=10)
            if res.status_code == 200:
                data = res.json()
                services = []
                for item in data.get("data", []):
                    services.append({
                        "port": item.get("port"),
                        "service": item.get("transport", "tcp"),
                        "banner": item.get("data", "")[:200],
                        "product": item.get("product", "")
                    })
                return {
                    "success": True,
                    "mock": False,
                    "ip": ip_address,
                    "ports": data.get("ports", []),
                    "hostnames": data.get("hostnames", []),
                    "org": data.get("org", "Unknown"),
                    "os": data.get("os", "Unknown"),
                    "services": services,
                    "vulns": list(data.get("vulns", {}).keys()) if isinstance(data.get("vulns"), dict) else data.get("vulns", [])
                }
            return {"success": False, "error": f"HTTP {res.status_code}: {res.text[:100]}"}
        except Exception as e:
            return {"success": False, "error": str(e)}
