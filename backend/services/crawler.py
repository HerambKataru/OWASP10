import re
import urllib.parse
from typing import List, Dict, Set, Any
import requests
from bs4 import BeautifulSoup
import time

class WebCrawler:
    def __init__(self, base_url: str, max_depth: int = 2, timeout: int = 10, user_agent: str = "SentinelX-VAPT-Agent/1.0"):
        # Normalize base URL
        if not base_url.startswith("http://") and not base_url.startswith("https://"):
            base_url = "http://" + base_url
        self.base_url = base_url.rstrip("/")
        self.parsed_base = urllib.parse.urlparse(self.base_url)
        self.domain = self.parsed_base.netloc
        self.max_depth = max_depth
        self.timeout = timeout
        self.headers = {"User-Agent": user_agent, "Accept": "*/*"}
        
        self.visited_urls: Set[str] = set()
        self.discovered_endpoints: List[Dict[str, Any]] = []
        self.discovered_forms: List[Dict[str, Any]] = []
        self.discovered_parameters: Set[str] = set()
        self.js_files: Set[str] = set()
        self.css_files: Set[str] = set()
        self.server_headers: Dict[str, str] = {}
        self.cookies_found: Dict[str, Any] = {}
        self.robots_txt: str = ""
        self.sitemap_xml: str = ""

    def is_same_domain(self, url: str) -> bool:
        parsed = urllib.parse.urlparse(url)
        return parsed.netloc == "" or parsed.netloc.lower() == self.domain.lower()

    def normalize_url(self, current_url: str, link: str) -> str:
        if not link or link.startswith("javascript:") or link.startswith("mailto:") or link.startswith("tel:"):
            return ""
        joined = urllib.parse.urljoin(current_url, link)
        parsed = urllib.parse.urlparse(joined)
        # Strip fragments
        return urllib.parse.urlunparse((parsed.scheme, parsed.netloc, parsed.path, parsed.params, parsed.query, ""))

    def check_robots_and_sitemap(self):
        # robots.txt
        try:
            robots_url = f"{self.parsed_base.scheme}://{self.domain}/robots.txt"
            res = requests.get(robots_url, headers=self.headers, timeout=self.timeout, verify=False)
            if res.status_code == 200:
                self.robots_txt = res.text[:2000]
                # parse paths from robots
                for line in res.text.splitlines():
                    if line.lower().startswith("disallow:") or line.lower().startswith("allow:"):
                        parts = line.split(":", 1)
                        if len(parts) > 1:
                            path = parts[1].strip()
                            if path and not path.startswith("*"):
                                full = urllib.parse.urljoin(self.base_url, path)
                                self.discovered_endpoints.append({
                                    "url": full,
                                    "method": "GET",
                                    "status_code": 200,
                                    "content_type": "text/plain",
                                    "source": "robots.txt"
                                })
        except Exception:
            pass

        # sitemap.xml
        try:
            sitemap_url = f"{self.parsed_base.scheme}://{self.domain}/sitemap.xml"
            res = requests.get(sitemap_url, headers=self.headers, timeout=self.timeout, verify=False)
            if res.status_code == 200:
                self.sitemap_xml = res.text[:2000]
                # extract urls
                urls = re.findall(r'<loc>(.*?)</loc>', res.text)
                for u in urls[:30]:
                    if self.is_same_domain(u):
                        self.discovered_endpoints.append({
                            "url": u.strip(),
                            "method": "GET",
                            "status_code": 200,
                            "content_type": "application/xml",
                            "source": "sitemap.xml"
                        })
        except Exception:
            pass

    def extract_forms(self, soup: BeautifulSoup, current_url: str) -> List[Dict[str, Any]]:
        forms = []
        for form in soup.find_all("form"):
            action = form.get("action") or ""
            action_url = self.normalize_url(current_url, action) or current_url
            method = (form.get("method") or "GET").upper()
            
            inputs = []
            for inp in form.find_all(["input", "textarea", "select"]):
                name = inp.get("name")
                inp_type = inp.get("type", "text")
                value = inp.get("value", "")
                if name:
                    inputs.append({"name": name, "type": inp_type, "value": value})
                    self.discovered_parameters.add(name)

            forms.append({
                "action": action_url,
                "method": method,
                "inputs": inputs,
                "page": current_url
            })
        return forms

    def crawl_url(self, url: str, depth: int, log_callback=None) -> List[str]:
        if depth > self.max_depth or url in self.visited_urls or len(self.visited_urls) > 50:
            return []
        
        self.visited_urls.add(url)
        if log_callback:
            log_callback(f"Crawling [Depth {depth}]: {url}")

        links_to_crawl = []
        try:
            start_t = time.time()
            res = requests.get(url, headers=self.headers, timeout=self.timeout, verify=False, allow_redirects=True)
            duration = round(time.time() - start_t, 3)

            # Store headers & cookies
            if not self.server_headers:
                self.server_headers = dict(res.headers)
            for k, v in res.cookies.items():
                self.cookies_found[k] = v

            content_type = res.headers.get("Content-Type", "")
            
            # Extract query parameters
            parsed = urllib.parse.urlparse(url)
            query_params = urllib.parse.parse_qs(parsed.query)
            for p in query_params.keys():
                self.discovered_parameters.add(p)

            forms_found = []
            if "text/html" in content_type:
                soup = BeautifulSoup(res.text, "html.parser")
                forms_found = self.extract_forms(soup, url)
                self.discovered_forms.extend(forms_found)

                # Extract script tags
                for script in soup.find_all("script", src=True):
                    src_url = self.normalize_url(url, script["src"])
                    if src_url:
                        self.js_files.add(src_url)

                # Extract link stylesheet
                for link in soup.find_all("link", rel="stylesheet"):
                    href = link.get("href")
                    if href:
                        href_url = self.normalize_url(url, href)
                        if href_url:
                            self.css_files.add(href_url)

                # Extract anchor links
                for a in soup.find_all("a", href=True):
                    href = a["href"]
                    norm_link = self.normalize_url(url, href)
                    if norm_link and self.is_same_domain(norm_link) and norm_link not in self.visited_urls:
                        links_to_crawl.append(norm_link)

            self.discovered_endpoints.append({
                "url": url,
                "method": "GET",
                "status_code": res.status_code,
                "content_type": content_type,
                "response_time": duration,
                "parameters": list(query_params.keys()),
                "forms": forms_found,
                "source": "crawler"
            })

        except Exception as e:
            if log_callback:
                log_callback(f"Failed to crawl {url}: {str(e)}", level="WARN")

        return links_to_crawl

    def start_crawl(self, log_callback=None) -> Dict[str, Any]:
        if log_callback:
            log_callback(f"Initiating Recon & Crawler against target domain: {self.domain}")
        
        self.check_robots_and_sitemap()
        
        queue = [(self.base_url, 0)]
        while queue and len(self.visited_urls) < 40:
            current_url, depth = queue.pop(0)
            if current_url not in self.visited_urls:
                sub_links = self.crawl_url(current_url, depth, log_callback)
                if depth + 1 <= self.max_depth:
                    for link in sub_links:
                        if link not in self.visited_urls:
                            queue.append((link, depth + 1))

        return {
            "endpoints": self.discovered_endpoints,
            "forms": self.discovered_forms,
            "parameters": list(self.discovered_parameters),
            "js_files": list(self.js_files),
            "css_files": list(self.css_files),
            "headers": self.server_headers,
            "cookies": self.cookies_found,
            "robots_txt": self.robots_txt,
            "sitemap_xml": self.sitemap_xml
        }
