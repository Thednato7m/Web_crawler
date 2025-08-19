import nmap  # Requires: pip install python-nmap
from urllib.parse import urljoin, urlparse, urldefrag
import requests
from bs4 import BeautifulSoup
import re
import time
import certifi
import urllib3
from concurrent.futures import ThreadPoolExecutor, as_completed
import threading

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


def run_nmap_scan(target, ports="80,443,8080,8000", arguments="-sS -T4"):
    """
    Run Nmap scan on target IP/range and return list of discovered web URLs.
    """
    nm = nmap.PortScanner()
    print(f"Running Nmap scan on {target} for ports {ports}...")
    nm.scan(target, ports=ports, arguments=arguments)

    urls = set()
    for host in nm.all_hosts():
        for proto in nm[host].all_protocols():
            for port in nm[host][proto]:
                if nm[host][proto][port]['state'] == 'open':
                    scheme = 'https' if port == 443 else 'http'
                    url = f"{scheme}://{host}"
                    urls.add(url)
    print(f"Nmap found {len(urls)} web services.")
    return list(urls)


class WebCrawler:
    def __init__(self, base_urls, max_workers=10, max_pages=300, delay=0.2):
        self.base_urls = base_urls
        self.visited = set()
        self.to_visit = set(self.normalize_url(u) for u in base_urls)
        self.session = requests.Session()
        self.max_workers = max_workers
        self.max_pages = max_pages
        self.delay = delay
        self.disallowed_paths = set()
        self.lock = threading.Lock()
        self.robots_loaded = False

    def normalize_url(self, url):
        url, _ = urldefrag(url)
        parsed = urlparse(url)
        scheme = parsed.scheme.lower()
        netloc = parsed.netloc.lower()
        path = parsed.path.rstrip('/')
        if not path:
            path = '/'
        normalized = f"{scheme}://{netloc}{path}"
        if parsed.query:
            normalized += '?' + parsed.query
        return normalized

    def load_robots_txt(self, base_url):
        robots_url = urljoin(base_url, "/robots.txt")
        try:
            resp = self.session.get(robots_url, timeout=5, verify=certifi.where())
            if resp.status_code == 200:
                for line in resp.text.splitlines():
                    if line.strip().lower().startswith("disallow:"):
                        path = line.split(":", 1)[1].strip()
                        if path:
                            disallowed_url = urljoin(base_url, path)
                            self.disallowed_paths.add(disallowed_url)
                print(f"Loaded robots.txt for {base_url}")
            else:
                print(f"No robots.txt found at {robots_url}")
        except Exception as e:
            print(f"Could not load robots.txt from {robots_url}: {e}")

    def fetch_common_hidden_files(self, base_url):
        """
        Attempt to fetch common hidden pages/files like sitemap.xml, humans.txt,
        security.txt, redirects.txt, .git/config, .htaccess, web.config, etc.
        Add discovered URLs or info into crawling queue.
        """
        common_files = [
            "sitemap.xml",
            "humans.txt",
            "security.txt",
            "ads.txt",
            "robots.txt",  # Already handled but safe to re-check
            "redirects.txt",
            ".htaccess",
            "web.config",
            "README.md",
            ".git/config",
            ".env",
        ]

        discovered_urls = set()

        for filename in common_files:
            url = urljoin(base_url, filename)
            try:
                resp = self.session.get(url, timeout=7, verify=certifi.where())
                if resp.status_code == 200:
                    print(f"Found {filename} at {url}")
                    content = resp.text

                    if filename == "sitemap.xml":
                        try:
                            soup = BeautifulSoup(content, "xml")
                            for loc in soup.find_all("loc"):
                                loc_url = loc.text.strip()
                                loc_url = self.normalize_url(loc_url)
                                if self.is_internal(loc_url):
                                    discovered_urls.add(loc_url)
                        except Exception as e:
                            print(f"Error parsing sitemap.xml: {e}")
                    else:
                        urls_in_text = re.findall(r"https?://[^\s'\"\<\>]+", content)
                        for found_url in urls_in_text:
                            norm_url = self.normalize_url(found_url)
                            if self.is_internal(norm_url):
                                discovered_urls.add(norm_url)

            except Exception:
                # Ignore failures (commonly 404)
                pass

        self.to_visit.update(discovered_urls)

    def is_allowed(self, url):
        for disallowed in self.disallowed_paths:
            if url.startswith(disallowed):
                return False
        return True

    def is_internal(self, url):
        parsed_url = urlparse(url)
        for base in self.base_urls:
            parsed_base = urlparse(base)
            if parsed_url.netloc == parsed_base.netloc:
                return True
        return False

    def extract_links(self, url, html):
        soup = BeautifulSoup(html, "html.parser")
        links = set()

        attrs = ['href', 'src', 'action', 'data-src']
        tags = ['a', 'link', 'script', 'iframe', 'form', 'img', 'source', 'embed']

        for tag in tags:
            for elem in soup.find_all(tag):
                for attr in attrs:
                    val = elem.get(attr)
                    if val:
                        full_url = urljoin(url, val)
                        full_url = self.normalize_url(full_url)
                        if self.is_internal(full_url):
                            links.add(full_url)

        url_regex = re.compile(r'''(?:"|')((?:https?:)?//[^"']+)(?:"|')''', re.IGNORECASE)
        for script in soup.find_all('script'):
            if script.string:
                for match in url_regex.findall(script.string):
                    full_url = urljoin(url, match)
                    full_url = self.normalize_url(full_url)
                    if self.is_internal(full_url):
                        links.add(full_url)

        meta = soup.find('meta', attrs={"http-equiv": "refresh"})
        if meta:
            content = meta.get("content", "")
            m = re.search(r'url=([^;]+)', content, flags=re.IGNORECASE)
            if m:
                redirect_url = urljoin(url, m.group(1))
                redirect_url = self.normalize_url(redirect_url)
                if self.is_internal(redirect_url):
                    links.add(redirect_url)

        return links

    def worker(self, current_url):
        with self.lock:
            if current_url in self.visited or len(self.visited) >= self.max_pages:
                return set()
            self.visited.add(current_url)

        if not self.is_allowed(current_url):
            print(f"Disallowed by robots.txt: {current_url}")
            return set()

        try:
            print(f"Crawling: {current_url}")
            resp = self.session.get(current_url, timeout=10, verify=certifi.where())
            resp.raise_for_status()
            found_links = self.extract_links(current_url, resp.text)
            time.sleep(self.delay)
            return found_links
        except requests.RequestException as e:
            print(f"Failed to crawl {current_url}: {e}")
            return set()

    def crawl(self):
        if not self.robots_loaded and self.base_urls:
            self.load_robots_txt(self.base_urls[0])
            self.fetch_common_hidden_files(self.base_urls[0])
            self.robots_loaded = True

        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            futures = {}

            while self.to_visit and len(self.visited) < self.max_pages:
                for url in list(self.to_visit):
                    if url not in self.visited and (len(self.visited) + len(futures)) < self.max_pages:
                        futures[executor.submit(self.worker, url)] = url
                        self.to_visit.remove(url)

                if not futures:
                    break

                for future in as_completed(futures):
                    url = futures.pop(future)
                    try:
                        new_links = future.result() or set()
                    except Exception as e:
                        print(f"Error crawling {url}: {e}")
                        new_links = set()
                    with self.lock:
                        self.to_visit.update(new_links - self.visited - self.to_visit)

        print("\nCrawling complete. Discovered URLs:")
        for url in sorted(self.visited):
            print(url)


if __name__ == "__main__":
    target = input("Enter target (IP, CIDR, hostname) for Nmap scan: ").strip()
    nmap_urls = run_nmap_scan(target, ports="80,443,8080,8000")

    if not nmap_urls:
        print("No web services detected by Nmap. Exiting.")
    else:
        print(f"\nStarting web crawler on {len(nmap_urls)} discovered URLs...\n")
        crawler = WebCrawler(nmap_urls, max_workers=15, max_pages=500, delay=0.2)
        crawler.crawl()
