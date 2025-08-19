import requests
from urllib.parse import urljoin, urlparse, urldefrag
from bs4 import BeautifulSoup
import re
import time
import urllib3
import certifi
from concurrent.futures import ThreadPoolExecutor, as_completed
import threading

# Disable warnings for insecure requests
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

class DetailedConcurrentCrawler:
    def __init__(self, base_url, delay=0.2, max_workers=10, max_pages=1000):
        self.base_url = base_url
        self.visited = set()
        self.to_visit = set([self.normalize_url(base_url)])
        self.session = requests.Session()
        self.delay = delay
        self.disallowed_paths = set()
        self.scheme_netloc = '{uri.scheme}://{uri.netloc}'.format(uri=urlparse(base_url))
        self.lock = threading.Lock()
        self.load_robots_txt()
        self.max_workers = max_workers
        self.max_pages = max_pages

    def load_robots_txt(self):
        robots_url = urljoin(self.base_url, "/robots.txt")
        try:
            resp = self.session.get(robots_url, timeout=5, verify=certifi.where())
            if resp.status_code == 200:
                for line in resp.text.splitlines():
                    if line.strip().lower().startswith("disallow:"):
                        path = line.split(":", 1)[1].strip()
                        if path:
                            disallowed_url = urljoin(self.scheme_netloc, path)
                            self.disallowed_paths.add(disallowed_url)
        except Exception as e:
            print(f"Could not load robots.txt: {e}")

    def is_allowed(self, url):
        for disallowed in self.disallowed_paths:
            if url.startswith(disallowed):
                return False
        return True

    def normalize_url(self, url):
        # Remove fragment, normalize scheme and host case, strip trailing slash
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

    def extract_links(self, url, html):
        soup = BeautifulSoup(html, "html.parser")
        links = set()

        # Extract links from various elements and attributes
        attributes = ['href', 'src', 'action', 'data-src']
        tags = ['a', 'link', 'script', 'iframe', 'form', 'img', 'source', 'embed']

        for tag in tags:
            for element in soup.find_all(tag):
                for attr in attributes:
                    attr_val = element.get(attr)
                    if attr_val:
                        full_url = urljoin(url, attr_val)
                        full_url = self.normalize_url(full_url)
                        if self.is_internal(full_url):
                            links.add(full_url)

        # Extract URLs from inline JavaScript (simple regex for URLs inside scripts)
        scripts = soup.find_all('script')
        url_regex = re.compile(
            r"""(?:"|')((?:https?:)?//[^"']+)(?:"|')""", re.IGNORECASE)
        for script in scripts:
            if script.string:
                for match in url_regex.findall(script.string):
                    full_url = urljoin(url, match)
                    full_url = self.normalize_url(full_url)
                    if self.is_internal(full_url):
                        links.add(full_url)

        # Extract meta refresh
        meta = soup.find("meta", attrs={"http-equiv": "refresh"})
        if meta:
            content = meta.get("content", "")
            match = re.search(r'url=([^;]+)', content, flags=re.IGNORECASE)
            if match:
                redirect_url = urljoin(url, match.group(1))
                redirect_url = self.normalize_url(redirect_url)
                if self.is_internal(redirect_url):
                    links.add(redirect_url)

        return links

    def is_internal(self, url):
        parsed_base = urlparse(self.base_url)
        parsed = urlparse(url)
        return parsed.netloc == parsed_base.netloc

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
            response = self.session.get(current_url, timeout=10, verify=certifi.where())
            response.raise_for_status()
            links = self.extract_links(current_url, response.text)
            time.sleep(self.delay)
            return links
        except requests.RequestException as e:
            print(f"Failed to fetch {current_url}: {e}")
            return set()

    def crawl(self):
        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            future_to_url = {}

            while self.to_visit and len(self.visited) < self.max_pages:
                # Submit all URLs
                for url in list(self.to_visit):
                    if url not in self.visited and len(self.visited) + len(future_to_url) < self.max_pages:
                        future = executor.submit(self.worker, url)
                        future_to_url[future] = url
                        self.to_visit.remove(url)

                if not future_to_url:
                    break

                for future in as_completed(future_to_url):
                    url = future_to_url[future]
                    future_to_url.pop(future)
                    links = future.result() or set()
                    with self.lock:
                        new_links = links - self.visited - self.to_visit
                        self.to_visit.update(new_links)

        print("\nDiscovered URLs:")
        for url in sorted(self.visited):
            print(url)


if __name__ == "__main__":
    start_url = input("Enter the URL to crawl: ").strip()
    crawler = DetailedConcurrentCrawler(start_url, delay=0.2, max_workers=15, max_pages=500)
    crawler.crawl()
