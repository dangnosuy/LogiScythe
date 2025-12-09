# LogiScythe - crawler.py
# Author: dangnosuy (Dang) & Gemini
# Refactored for stability and performance

import asyncio
import json
import os
import re
from collections import deque
from datetime import datetime
from urllib.parse import urljoin, urlparse
from typing import List, Dict, Any, Set, Optional, Tuple

from playwright.async_api import async_playwright, Page, Request, BrowserContext

# Keywords to avoid in URLs to prevent logging out or destructive actions
BLACKLISTED_URL_KEYWORDS = ['logout', 'delete', 'signout', 'exit', 'quit']

class BrowserAgent:
    """
    The BrowserAgent is responsible for controlling a browser instance (via Playwright),
    crawling the target website, and capturing all relevant HTTP traffic.
    """
    def __init__(self, headless: bool = True, timeout: int = 60000):
        self.headless = headless
        self.timeout = timeout
        self.http_traffic: List[Dict[str, Any]] = []
        self.target_domain: str = ""
        self.discovered_from_requests: Set[str] = set()
        self.url_pattern_counts: Dict[str, int] = {}
        self.external_links: Set[str] = set()  # Collect external domain links
        print(f"[Crawler] Initialized BrowserAgent. Headless: {self.headless}, Timeout: {self.timeout}ms")

    def _get_url_pattern(self, url: str) -> str:
        """Generates a pattern from a URL to group similar pages."""
        try:
            parsed = urlparse(url)
            # Pattern is scheme + netloc + path. Query params are ignored for grouping.
            return f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
        except:
            return url

    def _should_queue_url(self, url: str, force: bool = False) -> bool:
        """Decides if a URL should be queued based on pattern limits."""
        if force:
            return True
        pattern = self._get_url_pattern(url)
        count = self.url_pattern_counts.get(pattern, 0)
        if count >= 1: # Limit to 1 similar URL per pattern
            return False
        self.url_pattern_counts[pattern] = count + 1
        return True

    async def _intercept_request(self, request: Request):
        """Callback function to intercept and log network requests."""
        # We only care about requests within our target domain that are relevant
        if self.target_domain in request.url and not request.resource_type in ['image', 'stylesheet', 'font']:
            print(f"[Crawler] >> Intercepted Request: {request.method} {request.url}")
            
            # Try to get response, but don't fail if it's not available
            response = await request.response()
            response_status = response.status if response else "N/A"
            response_headers = dict(await response.all_headers()) if response else {}

            # Try to capture resource type and (for scripts) a snippet of the response body
            resource_type = request.resource_type
            response_body = None
            try:
                if response and resource_type == 'script':
                    # Limit to avoid huge logs
                    text = await response.text()
                    response_body = text[:200000] if text else None
            except Exception:
                response_body = None

            try:
                parent_url = request.frame.url if request.frame else None
            except Exception:
                parent_url = None

            self.http_traffic.append({
                "method": request.method,
                "url": request.url,
                "headers": dict(await request.all_headers()),
                "postData": request.post_data,
                "response_status": response_status,
                "response_headers": response_headers,
                "resource_type": resource_type,
                "response_body": response_body,
                "parent_url": parent_url
            })

            # Record discovered endpoints to enqueue later
            try:
                ru = urlparse(request.url)
                same_domain = ru and ru.netloc and (self.target_domain in ru.netloc)
                if same_domain and not any(keyword in request.url.lower() for keyword in BLACKLISTED_URL_KEYWORDS):
                    if request.method == 'GET':
                        self.discovered_from_requests.add(request.url)
                    else:
                        # If a non-GET has a redirect Location, enqueue it
                        loc = response_headers.get('location') or response_headers.get('Location')
                        if loc:
                            absolute_loc = urljoin(request.url, loc)
                            lru = urlparse(absolute_loc)
                            if lru and lru.netloc and (self.target_domain in lru.netloc):
                                self.discovered_from_requests.add(absolute_loc)
            except Exception:
                pass

    async def _extract_links(self, page: Page, base_url: str) -> List[str]:
        """Extracts all valid links from the current page."""
        links = []
        try:
            # DOM extraction
            link_elements = await page.query_selector_all("a[href]")
            for link in link_elements:
                href = await link.get_attribute("href")
                if href:
                    links.append(href.strip())
            
            # HTML fallback extraction
            html = await page.content()
            for href in re.findall(r"href\s*=\s*[\"']([^\"'#>\s]+)", html, flags=re.IGNORECASE):
                links.append(href.strip())
        except Exception as e:
            print(f"[Crawler] Error extracting links: {e}")

        valid_urls = []
        ignored_extensions = [
            '.css', '.png', '.jpg', '.jpeg', '.gif', '.svg', 
            '.woff', '.woff2', '.ttf', '.eot', '.ico', '.js', '.json', '.xml'
        ]

        for href in set(links): # Deduplicate
            absolute_url = urljoin(base_url, href)
            parsed = urlparse(absolute_url)
            
            if not absolute_url.startswith(("http://", "https://")):
                continue
            if any(parsed.path.lower().endswith(ext) for ext in ignored_extensions):
                continue
            
            # Check if external link
            if self.target_domain not in parsed.netloc:
                # Store external link (skip blacklisted)
                if not any(keyword in absolute_url.lower() for keyword in BLACKLISTED_URL_KEYWORDS):
                    self.external_links.add(absolute_url)
                continue

            if any(keyword in absolute_url.lower() for keyword in BLACKLISTED_URL_KEYWORDS):
                continue
                
            valid_urls.append(absolute_url)
        return valid_urls

    async def _extract_form_metadata(self, form) -> List[Dict[str, Any]]:
        fields = []
        try:
            inputs = await form.locator("input").all()
            textareas = await form.locator("textarea").all()
            selects = await form.locator("select").all()

            for element in inputs + textareas + selects:
                name = await element.get_attribute("name") or await element.get_attribute("id")
                if not name:
                    continue
                tag_name = await element.evaluate("el => el.tagName.toLowerCase()")
                field = {
                    "name": name,
                    "tag": tag_name,
                    "type": await element.get_attribute("type") if tag_name == "input" else tag_name,
                    "value": await element.get_attribute("value"),
                    "placeholder": await element.get_attribute("placeholder"),
                    "required": await element.get_attribute("required") is not None
                }
                if tag_name == "select":
                    options = await element.locator("option").all()
                    field["options"] = []
                    for option in options:
                        field["options"].append({
                            "value": await option.get_attribute("value"),
                            "text": await option.text_content(),
                            "selected": await option.get_attribute("selected") is not None
                        })
                fields.append(field)
        except Exception:
            pass
        return fields

    async def _extract_actions(self, page: Page, base_url: str, visited_actions: Set) -> List[Dict]:
        """Extracts clickable elements and forms to interact with."""
        actions = []
        
        # 1. Clickables
        try:
            selectors = [
                "button", "input[type='submit']", "input[type='button']",
                "[onclick]", "[role='button']", "a[onclick]", "a[role='button']", "[role='link']"
            ]
            for selector in selectors:
                count = await page.locator(selector).count()
                for i in range(count):
                    sel = f"{selector} >> nth={i}"
                    key = (base_url, "click", sel)
                    if key not in visited_actions:
                        actions.append({"type": "click", "url": base_url, "selector": sel})
        except Exception:
            pass

        # 2. Forms (DOM)
        try:
            forms = await page.locator("form").all()
            for i, form in enumerate(forms):
                key = (base_url, "form", i)
                if key not in visited_actions:
                    actions.append({"type": "form", "url": base_url, "form_index": i})
                
                # Record endpoint immediately
                action_attr = await form.get_attribute("action")
                method_attr = await form.get_attribute("method")
                method_val = (method_attr or "GET").upper()
                action_url = urljoin(base_url, action_attr) if action_attr else base_url
                
                fields = await self._extract_form_metadata(form)
                self.http_traffic.append({
                    "method": method_val,
                    "url": action_url,
                    "headers": {},
                    "postData": None,
                    "response_status": "N/A",
                    "response_headers": {},
                    "resource_type": "form",
                    "response_body": None,
                    "parent_url": base_url,
                    "form_fields": fields
                })
        except Exception as e:
            print(f"[Crawler] Error extracting forms (DOM): {e}")

        # 3. Forms (HTML Fallback - Improved Regex)
        try:
            html = await page.content()
            # Matches <form ... action="val" ...> or <form ... action=val ...>
            # Group 1: quoted action, Group 2: unquoted action
            form_tags = re.findall(r"<form[^>]*>", html, flags=re.IGNORECASE)
            for tag in form_tags:
                action_match = re.search(r"action\s*=\s*(?:[\"']([^\"']*)[\"']|([^\"'\s>]+))", tag, flags=re.IGNORECASE)
                method_match = re.search(r"method\s*=\s*(?:[\"']([a-zA-Z]+)[\"']|([a-zA-Z]+))", tag, flags=re.IGNORECASE)
                
                action_attr = (action_match.group(1) or action_match.group(2)) if action_match else None
                method_val = ((method_match.group(1) or method_match.group(2)) if method_match else "GET").upper()
                
                if action_attr:
                    action_url = urljoin(base_url, action_attr)
                    # We don't add to actions queue here because we can't reliably target them without DOM index
                    # But we DO record the endpoint
                    self.http_traffic.append({
                        "method": method_val,
                        "url": action_url,
                        "headers": {},
                        "postData": None,
                        "response_status": "N/A",
                        "response_headers": {},
                        "resource_type": "form_fallback",
                        "response_body": None,
                        "parent_url": base_url,
                        "form_fields": []
                    })
        except Exception as e:
            print(f"[Crawler] Error extracting forms (HTML): {e}")

        return actions

    async def _process_visit(self, page: Page, url: str, visited_urls: Set, action_queue: deque, visited_actions: Set, seen_urls: Set) -> bool:
        print(f"[Crawler] Navigating to: {url}")
        try:
            await page.goto(url, wait_until="networkidle", timeout=self.timeout)
            await page.wait_for_timeout(2000) # Wait for dynamic content
            visited_urls.add(url)
        except Exception as e:
            print(f"[Crawler] [!] Could not navigate to {url}: {e}")
            return False

        # Extract links
        new_links = await self._extract_links(page, url)
        for link in new_links:
            if link not in seen_urls:
                if self._should_queue_url(link):
                    seen_urls.add(link)
                    action_queue.append({"type": "visit", "url": link})
                    print(f"[Crawler] Discovered link -> queued visit: {link}")
                else:
                    # Silently skip to avoid noise, or log if verbose needed
                    pass

        # Extract actions
        new_actions = await self._extract_actions(page, url, visited_actions)
        for action in new_actions:
            action_queue.append(action)
        
        if new_actions:
            print(f"[Crawler] Queued {len(new_actions)} actions for page.")

        return True

    async def _process_click(self, page: Page, action: Dict, visited_actions: Set, action_queue: deque, visited_urls: Set, seen_urls: Set):
        base_url = action.get("url")
        selector = action.get("selector")
        key = (base_url, "click", selector)
        
        if key in visited_actions: return
        visited_actions.add(key)
        
        print(f"[Crawler] Re-loading base page to perform click: {base_url} :: {selector}")
        try:
            await page.goto(base_url, wait_until="networkidle", timeout=self.timeout)
            await page.wait_for_timeout(1000)
            
            element = page.locator(selector)
            if await element.is_hidden() or not await element.is_enabled():
                return
            
            await element.click(timeout=5000)
            await page.wait_for_load_state("networkidle", timeout=self.timeout)
            await page.wait_for_timeout(2000)
            print("[Crawler] Click action performed.")
            
            # Discover new things
            new_url = page.url
            new_links = await self._extract_links(page, new_url)
            for link in new_links:
                if link not in seen_urls:
                    if self._should_queue_url(link):
                        seen_urls.add(link)
                        action_queue.append({"type": "visit", "url": link})
        except Exception as e:
            print(f"[Crawler] [!] Click action failed: {e}")

    async def _process_form(self, page: Page, action: Dict, visited_actions: Set, action_queue: deque, visited_urls: Set, seen_urls: Set):
        base_url = action.get("url")
        form_index = action.get("form_index")
        key = (base_url, "form", form_index)
        
        if key in visited_actions: return
        visited_actions.add(key)
        
        print(f"[Crawler] Re-loading base page to submit form: {base_url} :: form #{form_index}")
        try:
            await page.goto(base_url, wait_until="networkidle", timeout=self.timeout)
            await page.wait_for_timeout(1000)
            
            form_selector = f"form >> nth={form_index}"
            form = page.locator(form_selector)
            
            # Fill inputs
            for input_type, value in [("text", "test"), ("email", "test@example.com"), ("password", "password123")]:
                try:
                    inp = form.locator(f"input[type='{input_type}']").first
                    if await inp.count() > 0 and await inp.is_visible():
                        await inp.fill(value, timeout=2000)
                except: pass
            
            # Submit
            sb = form.locator("input[type='submit'], button[type='submit']")
            if await sb.count() > 0:
                await sb.first.click(timeout=5000)
            else:
                await page.evaluate("form => form.submit()", await form.element_handle())
            
            await page.wait_for_load_state("networkidle", timeout=self.timeout)
            await page.wait_for_timeout(2000)
            print("[Crawler] Form submission performed.")
            
            # Discover new things on the result page
            new_url = page.url
            new_links = await self._extract_links(page, new_url)
            for link in new_links:
                if link not in seen_urls:
                    if self._should_queue_url(link):
                        seen_urls.add(link)
                        action_queue.append({"type": "visit", "url": link})

        except Exception as e:
            print(f"[Crawler] [!] Form submission failed: {e}")
            print(f"[Crawler] [!] Form submission failed: {e}")

    async def _crawl_logic(self, start_url: str, domain: str, max_rounds: int = 2):
        """The main async logic for crawling with multiple rounds to capture state changes."""
        self.target_domain = domain

        async with async_playwright() as p:
            print("[Crawler] Launching browser...")
            browser = await p.chromium.launch(headless=self.headless)
            context = await browser.new_context(ignore_https_errors=True)
            page = await context.new_page()
            page.on("request", self._intercept_request)

            # Run multiple crawl rounds with the same session
            abort_crawl = False
            for round_num in range(1, max_rounds + 1):
                print(f"\n{'='*60}")
                print(f"[Crawler] Starting crawl round {round_num}/{max_rounds}")
                print(f"{'='*60}\n")
                
                # Reset dedupe bookkeeping so each round explores everything anew
                self.url_pattern_counts = {}
                self.discovered_from_requests = set()

                action_queue = deque([{"type": "visit", "url": start_url}])
                visited_urls = set()
                visited_actions = set()
                seen_urls = set()  # Reset seen_urls each round to allow re-discovery
                seen_urls.add(start_url)
                
                # Note: url_pattern_counts is NOT reset to maintain pattern limit across rounds

                while action_queue:
                    print(f"\n[Crawler] [Round {round_num}] Queue Status: {len(action_queue)} items pending.")
                    action = action_queue.popleft()
                    atype = action.get("type")
                    target_desc = action.get("url") or action.get("selector") or "(unknown)"
                    print(f"[Crawler] [Round {round_num}] Executing {atype} -> {target_desc}")

                    if atype == "visit":
                        success = await self._process_visit(page, action.get("url"), visited_urls, action_queue, visited_actions, seen_urls)
                        if not success and action.get("url") == start_url and round_num == 1:
                            print("[Crawler] [!] Unable to reach the starting URL. Aborting crawl.")
                            abort_crawl = True
                            break
                    elif atype == "click":
                        await self._process_click(page, action, visited_actions, action_queue, visited_urls, seen_urls)
                    elif atype == "form":
                        await self._process_form(page, action, visited_actions, action_queue, visited_urls, seen_urls)
                    
                    # Enqueue discovered requests
                    if self.discovered_from_requests:
                        for absolute_url in list(self.discovered_from_requests):
                            if absolute_url not in seen_urls:
                                if self._should_queue_url(absolute_url):
                                    seen_urls.add(absolute_url)
                                    action_queue.append({"type": "visit", "url": absolute_url})
                                    print(f"[Crawler] Enqueueing from network discovery: {absolute_url}")
                        self.discovered_from_requests.clear()

                if abort_crawl:
                    break

                print(f"\n[Crawler] Round {round_num} complete. Queue is empty.")
                
                # After each round except the last, give time for any async state changes
                if round_num < max_rounds and not abort_crawl:
                    print(f"[Crawler] Preparing for next round (session maintained)...")
                    await page.wait_for_timeout(1000)

            if abort_crawl:
                print("\n[Crawler] Crawl aborted due to unreachable start URL.")
            else:
                print("\n[Crawler] All crawl rounds finished. Finishing up.")
            cookies = await context.cookies()
            await browser.close()
            return self.http_traffic, cookies

    def crawl(self, url: str, domain: str):
        """Public method to start the crawling process."""
        print("[Crawler] Starting crawl process...")
        return asyncio.run(self._crawl_logic(url, domain))

    @staticmethod
    def save_cache(cache_path: Optional[str], conversations: List[Dict[str, Any]], cookies: List[Dict[str, Any]], source_url: Optional[str] = None):
        """Persists analysis-ready request/response conversations to disk."""
        if not cache_path:
            return

        try:
            directory = os.path.dirname(cache_path)
            if directory:
                os.makedirs(directory, exist_ok=True)

            parsed_source = urlparse(source_url) if source_url else None
            payload = {
                "metadata": {
                    "source_url": source_url,
                    "target_domain": parsed_source.netloc if parsed_source else None,
                    "saved_at": datetime.utcnow().isoformat() + "Z",
                    "entry_count": len(conversations)
                },
                "conversations": conversations,
                "cookies": cookies
            }

            with open(cache_path, "w", encoding="utf-8") as f:
                json.dump(payload, f, indent=2)

            print(f"[Crawler] Cached crawl data to '{cache_path}' ({len(http_traffic)} interactions).")
        except Exception as e:
            print(f"[Crawler] Warning: Failed to cache crawl results to '{cache_path}': {e}")

    @staticmethod
    def load_cache(cache_path: Optional[str]) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]]]:
        """Loads cached request/response conversations from disk."""
        if not cache_path:
            raise ValueError("Cache path must be provided to load crawl data.")

        if not os.path.exists(cache_path):
            raise FileNotFoundError(f"Cache file '{cache_path}' not found.")

        with open(cache_path, "r", encoding="utf-8") as f:
            data = json.load(f)

        conversations = data.get("conversations") or data.get("http_traffic")
        cookies = data.get("cookies", [])

        if conversations is None:
            raise ValueError(f"Cache file '{cache_path}' is missing conversations.")

        return conversations, cookies

if __name__ == '__main__':
    print("[+] Running crawler.py in standalone test mode.")
    agent = BrowserAgent(headless=True)
    test_url = "http://testphp.vulnweb.com/" 
    test_domain = "testphp.vulnweb.com"
    traffic, captured_cookies = agent.crawl(test_url, test_domain)
    
    print("\n" + "="*30 + " CRAWL RESULTS " + "="*30)
    print(f"Captured {len(traffic)} total requests.")
    print(f"Captured {len(captured_cookies)} cookies.")