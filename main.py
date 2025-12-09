# LogiScythe - Business Logic Testing Tool
# Author: dangnosuy (Dang) & Gemini
# Version: 0.1.0

import argparse
import base64
import json
import sys
from urllib.parse import urlparse, urljoin
import re

from bs4 import BeautifulSoup

import requests
from requests.packages.urllib3.exceptions import InsecureRequestWarning

from crawler import BrowserAgent
from gemini_client import GeminiAnalyst
from exploiter import Exploiter
from dashboard import app, socketio, DashboardLogger
import threading
import time

MAX_CAPTURE_BODY_CHARS = 200_000
TEXTUAL_MIME_PREFIXES = (
    "text/",
    "application/json",
    "application/javascript",
    "application/xml",
    "application/xhtml+xml",
    "application/x-www-form-urlencoded"
)


def _normalize_url_for_key(url: str) -> str:
    if not url:
        return ""
    # Replace numeric IDs in query params
    url = re.sub(r'([a-zA-Z0-9_\[\]]+)=\d+', r'\1={id}', url)
    # Replace numeric path segments
    url = re.sub(r'/\d+', '/{id}', url)
    return url


def _is_textual_content(content_type: str) -> bool:
    if not content_type:
        return True
    lowered = content_type.lower()
    return any(lowered.startswith(prefix) for prefix in TEXTUAL_MIME_PREFIXES)


def _sanitize_headers(headers: dict) -> dict:
    if not headers:
        return {}
    banned = {"host", "content-length", "content-encoding", "transfer-encoding", "connection", "accept-encoding", "cookie"}
    sanitized = {}
    for key, value in headers.items():
        if not key:
            continue
        if key.startswith(":"):
            continue
        if key.lower() in banned:
            continue
        sanitized[key] = value
    return sanitized


def _build_cookie_jar(cookies):
    jar = requests.cookies.RequestsCookieJar()
    if not cookies:
        return jar
    for cookie in cookies:
        name = cookie.get("name")
        value = cookie.get("value")
        if not name:
            continue
        jar.set(
            name,
            value,
            domain=cookie.get("domain"),
            path=cookie.get("path", "/"),
        )
    return jar


def build_payload_from_form_fields(fields):
    if not fields:
        return None
    payload = {}
    for field in fields:
        name = field.get("name")
        if not name:
            continue
        tag = (field.get("tag") or "").lower()
        input_type = (field.get("type") or "text").lower()
        value = field.get("value")

        if tag == "select":
            options = field.get("options") or []
            selected = next((opt for opt in options if opt.get("selected")), None)
            value = selected.get("value") if selected else (options[0].get("value") if options else "")
        elif tag == "textarea":
            if value is None:
                value = "test"
        else:
            if value is None:
                if input_type == "email":
                    value = "test@example.com"
                elif input_type == "password":
                    value = "Password123!"
                elif input_type in {"number", "range"}:
                    value = "1"
                elif input_type in {"checkbox", "radio"}:
                    if field.get("required"):
                        value = field.get("value") or "on"
                    else:
                        continue
                else:
                    value = field.get("placeholder") or "test"

        payload[name] = value if value is not None else ""

    return payload if payload else None


def infer_form_payload_from_html(html: str, target_url: str):
    if not html or not target_url:
        return None

    try:
        soup = BeautifulSoup(html, "html.parser")
    except Exception:
        return None

    target_form = None
    for form in soup.find_all("form"):
        action = form.get("action")
        if action:
            absolute_action = urljoin(target_url, action)
        else:
            absolute_action = target_url
        if absolute_action == target_url:
            target_form = form
            break

    if not target_form:
        return None

    payload = {}
    for input_tag in target_form.find_all(["input", "textarea", "select"]):
        name = input_tag.get("name") or input_tag.get("id")
        if not name:
            continue

        tag_name = input_tag.name.lower()
        if tag_name == "select":
            option = input_tag.find("option", selected=True) or input_tag.find("option")
            value = option.get("value") if option else ""
        elif tag_name == "textarea":
            value = input_tag.text or input_tag.get("value") or ""
        else:
            input_type = (input_tag.get("type") or "text").lower()
            value = input_tag.get("value") or ""
            if not value:
                if input_type == "email":
                    value = "test@example.com"
                elif input_type == "password":
                    value = "Password123!"
                elif input_type in {"number", "range"}:
                    value = "1"
                elif input_type in {"checkbox", "radio"}:
                    if input_tag.has_attr("checked"):
                        value = input_tag.get("value") or "on"
                    else:
                        continue
                else:
                    value = "test"

        payload[name] = value

    return payload if payload else None


def _filter_successful_conversations(conversations):
    if not conversations:
        return []
    filtered = []
    for convo in conversations:
        response = convo.get("response") or {}
        if response.get("error"):
            continue
        filtered.append(convo)
    return filtered


def _dedupe_conversations(conversations):
    if not conversations:
        return []
    seen = set()
    deduped = []
    for convo in conversations:
        request = convo.get("request") or {}
        method = (request.get("method") or "GET").upper()
        url = _normalize_url_for_key(request.get("url") or "")
        key = f"{method} {url}"
        if key in seen:
            continue
        seen.add(key)
        deduped.append(convo)
    return deduped


def replay_filtered_requests(filtered_log, cookies, timeout: int = 20, verify_tls: bool = False):
    """Fetches live responses for each filtered request, capturing Burp-style conversations."""
    if not filtered_log:
        return []

    print("[+] Replaying filtered requests to capture full responses...")
    session = requests.Session()
    session.verify = verify_tls
    session.cookies.update(_build_cookie_jar(cookies))

    enriched = []
    total = len(filtered_log)

    parent_html_cache = {}

    for idx, interaction in enumerate(filtered_log, start=1):
        method = (interaction.get('method') or 'GET').upper()
        url = interaction.get('url')
        headers = _sanitize_headers(interaction.get('headers') or {})
        body = interaction.get('postData')
        if isinstance(body, (dict, list)):
            body = json.dumps(body)

        if method in {"POST", "PUT", "PATCH", "DELETE"}:
            if not body:
                fields = interaction.get('form_fields') or []
                inferred_payload = build_payload_from_form_fields(fields)
                if not inferred_payload:
                    parent_url = interaction.get('parent_url')
                    if parent_url:
                        if parent_url not in parent_html_cache:
                            try:
                                resp_parent = session.get(parent_url, timeout=timeout, allow_redirects=True)
                                parent_html_cache[parent_url] = resp_parent.text if resp_parent.status_code == 200 else ""
                            except Exception:
                                parent_html_cache[parent_url] = ""
                        html = parent_html_cache.get(parent_url) or ""
                        inferred_payload = infer_form_payload_from_html(html, url)
                if inferred_payload:
                    headers.setdefault("Content-Type", "application/x-www-form-urlencoded")
                    if isinstance(inferred_payload, dict):
                        body = requests.compat.urlencode(inferred_payload)
                    else:
                        body = inferred_payload

        print(f"[Replay] [{idx}/{total}] {method} {url}")

        record = {
            "request": {
                "method": method,
                "url": url,
                "headers": headers,
                "body": body,
                "resource_type": interaction.get('resource_type')
            },
            "response": {
                "status": None,
                "headers": {},
                "body": None,
                "body_encoding": "text",
                "error": None,
                "final_url": None
            }
        }

        try:
            resp = session.request(
                method,
                url,
                headers=headers,
                data=body,
                timeout=timeout,
                allow_redirects=True
            )
            record["response"]["status"] = resp.status_code
            record["response"]["headers"] = dict(resp.headers)
            record["response"]["final_url"] = resp.url

            content_type = resp.headers.get('Content-Type', '')
            if _is_textual_content(content_type):
                text_body = resp.text or ""
                truncated = False
                if len(text_body) > MAX_CAPTURE_BODY_CHARS:
                    text_body = text_body[:MAX_CAPTURE_BODY_CHARS]
                    truncated = True
                record["response"]["body"] = text_body
                if truncated:
                    record["response"]["truncated"] = True
            else:
                encoded = base64.b64encode(resp.content or b"").decode('ascii')
                truncated = False
                if len(encoded) > MAX_CAPTURE_BODY_CHARS:
                    encoded = encoded[:MAX_CAPTURE_BODY_CHARS]
                    truncated = True
                record["response"]["body"] = encoded
                record["response"]["body_encoding"] = "base64"
                if truncated:
                    record["response"]["truncated"] = True

        except Exception as e:
            record["response"]["error"] = str(e)

        enriched.append(record)

    print(f"[+] Captured live responses for {len(enriched)} filtered requests.")
    return enriched

requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

def filter_http_traffic(traffic_log: list) -> list:
    """
    Filters and deduplicates the captured HTTP traffic to reduce noise and
    focus on unique business logic endpoints before sending to the LLM.

    Also mines JS responses for potential hardcoded endpoints (fetch/XHR/absolute URLs)
    and includes them (same-domain only) as synthetic GET interactions.
    """
    filtered_log = []
    seen_patterns = set()
    discovered_urls = set()

    # Common static file extensions to ignore (keep .js to analyze embedded endpoints)
    ignored_extensions = [
        '.css', '.png', '.jpg', '.jpeg', '.gif', '.svg', 
        '.woff', '.woff2', '.ttf', '.eot', '.ico'
    ]

    for interaction in traffic_log:
        url = interaction.get('url', '')
        parsed_url = urlparse(url)

        # Rule 1: Ignore requests to common static files
        if any(parsed_url.path.lower().endswith(ext) for ext in ignored_extensions):
            continue

        # Rule 2: Normalize and deduplicate by METHOD + URL
        normalized_url = _normalize_url_for_key(url)

        method = interaction.get('method', 'GET').upper()
        dedup_key = f"{method} {normalized_url}"

        if dedup_key in seen_patterns:
            continue

        seen_patterns.add(dedup_key)
        filtered_log.append({
            'method': method,
            'url': url,
            'headers': interaction.get('headers') or {},
            'postData': interaction.get('postData'),
            'resource_type': interaction.get('resource_type'),
            'parent_url': interaction.get('parent_url')
        })

        # Rule 3: If this is a script with response_body, mine for URLs
        resource_type = interaction.get('resource_type')
        body = interaction.get('response_body')
        if resource_type == 'script' and body:
            base = f"{parsed_url.scheme}://{parsed_url.netloc}"
            # Match absolute URLs and relative paths
            for m in re.findall(r"https?://[^\s\'\"<>]+|(?<![\w:])(\/[^\s\'\"<>]+)", body):
                if not m:
                    continue
                candidate = m if isinstance(m, str) and m.startswith(('http://','https://')) else urljoin(base, m)
                cu = urlparse(candidate)
                if cu.scheme in ('http','https') and cu.netloc == parsed_url.netloc:
                    discovered_urls.add(candidate)

    # Add discovered endpoints as synthetic GET interactions if not already seen
    for u in sorted(discovered_urls):
        norm = _normalize_url_for_key(u)
        key = f"GET {norm}"
        if key in seen_patterns:
            continue
        seen_patterns.add(key)
        filtered_log.append({
            'method': 'GET',
            'url': u,
            'headers': {},
            'postData': None,
            'resource_type': 'discovered',
            'parent_url': None
        })
        
    return filtered_log


def main():
    """
    Main function to orchestrate the business logic testing process.
    """
    print("="*60)
    print("          LogiScythe - Business Logic Testing Tool")
    print("              by dangnosuy (Dang) & Gemini")
    print("="*60)

    parser = argparse.ArgumentParser(description="A semi-automated tool to find business logic vulnerabilities.")
    
    parser.add_argument("--url", "-u", required=True, type=str, help="The starting URL to crawl (e.g., https://example.com/login).")
    parser.add_argument("--apikey", "-k", required=True, type=str, help="Your Google Gemini API Key.")
    parser.add_argument("--model", "-m", type=str, default="gemini-2.5-pro", help="The Gemini model to use (e.g., gemini-1.5-pro).")
    parser.add_argument("--headless", action="store_true", help="Run the browser in headless mode (no GUI).")
    parser.add_argument("--cache-file", type=str, help="Path to store or load cached crawl data (JSON). Defaults to crawl-cache-<domain>.json.")
    parser.add_argument("--use-cache", action="store_true", help="Skip crawling and reuse the cached HTTP log from --cache-file.")
    parser.add_argument("--skip-cache-save", action="store_true", help="Do not write a new cache file after crawling.")
    parser.add_argument("--dashboard", action="store_true", help="Enable the web dashboard.")
    parser.add_argument("--port", type=int, default=5000, help="Port for the dashboard (default: 5000).")
    
    args = parser.parse_args()

    # --- Start Dashboard (Optional) ---
    if args.dashboard:
        print(f"[+] Starting Dashboard on http://localhost:{args.port}")
        # Run Flask in a separate thread
        dashboard_thread = threading.Thread(target=lambda: socketio.run(app, host="0.0.0.0", port=args.port, allow_unsafe_werkzeug=True))
        dashboard_thread.daemon = True
        dashboard_thread.start()
        DashboardLogger.update_status("initializing")
        time.sleep(2) # Give it a moment to start

    # --- 1. Input Validation ---
    print(f"[+] Validating target URL: {args.url}")
    parsed_url = urlparse(args.url)
    if not all([parsed_url.scheme, parsed_url.netloc]):
        print(f"[!] Invalid URL: {args.url}. Please provide a full URL (e.g., https://example.com).")
        sys.exit(1)
    
    target_domain = parsed_url.netloc
    print(f"[+] Target domain identified: {target_domain}")
    print(f"[+] Using model: {args.model}")
    print(f"[+] Headless mode: {'Enabled' if args.headless else 'Disabled'}")
    cache_path = args.cache_file or f"crawl-cache-{target_domain}.json"
    print(f"[+] Crawl cache file: {cache_path}")
    
    try:
        analysis_ready_log = []
        cookies = []

        # --- 2. Crawling Phase (or Cache Load) ---
        if args.use_cache:
            print("\n" + "-"*25 + " Phase 1: Cached Conversations " + "-"*25)
            analysis_ready_log, cookies = BrowserAgent.load_cache(cache_path)
            print(f"[+] Loaded {len(analysis_ready_log)} cached request/response pairs from '{cache_path}'.")
            if not cookies:
                print("[!] Cache file does not contain cookies. Subsequent authenticated requests may fail.")
            else:
                print(f"[+] Cached cookies: {[c['name'] for c in cookies]}")

            successful_conversations = _filter_successful_conversations(analysis_ready_log)
            if not successful_conversations:
                print("[!] Cached data does not contain successful responses. Exiting.")
                sys.exit(1)

            analysis_ready_log = _dedupe_conversations(successful_conversations)
            print(f"[+] Using {len(analysis_ready_log)} unique conversations from cache for analysis.")
        else:
            print("\n" + "-"*25 + " Phase 1: Crawling " + "-"*25)
            browser_agent = BrowserAgent(headless=args.headless)
            raw_http_traffic, cookies = browser_agent.crawl(args.url, target_domain)

            if not raw_http_traffic:
                print("[!] Crawling did not capture any relevant HTTP traffic. Exiting.")
                sys.exit(1)

            print(f"[+] Crawling finished. Captured {len(raw_http_traffic)} interactions.")

            # --- External Link Handling (Merged from LogiScythe-raw) ---
            external_links = browser_agent.external_links
            if external_links:
                # Group by domain
                external_domains = {}
                for link in external_links:
                    domain = urlparse(link).netloc
                    if domain not in external_domains:
                        external_domains[domain] = []
                    external_domains[domain].append(link)
                
                print(f"\n[+] Found {len(external_links)} external links across {len(external_domains)} domain(s):")
                domain_list = list(external_domains.keys())
                for idx, domain in enumerate(domain_list, start=1):
                    link_count = len(external_domains[domain])
                    print(f"  [{idx}] {domain} ({link_count} link(s))")
                    # Show first 3 example links per domain
                    for example_link in external_domains[domain][:3]:
                        print(f"       - {example_link}")
                    if link_count > 3:
                        print(f"       ... and {link_count - 3} more")
                
                print("\n[?] Would you like to crawl any of these external domains?")
                print("    Enter domain numbers separated by commas (e.g., 1,3), or press Enter to skip: ", end="")
                try:
                    # Use a non-blocking input method or default to skip if running automated
                    # For now, we'll use standard input but wrap in try/except for safety
                    if not args.headless: # Only ask in interactive mode (implied by not headless, though headless refers to browser)
                         # Actually, headless arg is for browser. We can check if stdin is interactive.
                         pass
                    
                    # Simple input for now
                    user_input = input().strip()
                    if user_input:
                        selected_indices = [int(x.strip()) for x in user_input.split(",") if x.strip().isdigit()]
                        selected_domains = [domain_list[i-1] for i in selected_indices if 1 <= i <= len(domain_list)]
                        
                        if selected_domains:
                            print(f"\n[+] Crawling {len(selected_domains)} additional domain(s)...")
                            for ext_domain in selected_domains:
                                # Use first link from domain as starting point
                                start_link = external_domains[ext_domain][0]
                                print(f"\n[+] Starting crawl for external domain: {ext_domain}")
                                print(f"    Starting URL: {start_link}")
                                
                                ext_agent = BrowserAgent(headless=args.headless)
                                ext_traffic, ext_cookies = ext_agent.crawl(start_link, ext_domain)
                                
                                if ext_traffic:
                                    print(f"[+] Captured {len(ext_traffic)} interactions from {ext_domain}")
                                    raw_http_traffic.extend(ext_traffic)
                                    # Merge cookies (avoid duplicates by name+domain)
                                    existing_cookie_keys = {(c['name'], c.get('domain', '')) for c in cookies}
                                    for c in ext_cookies:
                                        if (c['name'], c.get('domain', '')) not in existing_cookie_keys:
                                            cookies.append(c)
                except (KeyboardInterrupt, EOFError):
                    print("\n[!] Skipping external domain crawl.")
                except Exception as e:
                    print(f"\n[!] Error reading input: {e}. Skipping external crawl.")

            # --- Filtering Step ---
            print("[+] Filtering and deduplicating captured traffic...")
            filtered_log = filter_http_traffic(raw_http_traffic)
            print(f"[+] Filtering complete. Reduced interactions from {len(raw_http_traffic)} to {len(filtered_log)}.")

            if filtered_log:
                print("[+] Final requests selected for replay:")
                for interaction in filtered_log:
                    rt = interaction.get('resource_type')
                    rt_str = f" [type={rt}]" if rt else ""
                    print(f"  - {interaction.get('method')} {interaction.get('url')}{rt_str}")
            else:
                print("[!] Filtering removed all interactions. Exiting.")
                sys.exit(1)

            print(f"[+] Captured cookies: {[c['name'] for c in cookies]}")

            # --- Replay Step ---
            analysis_ready_log = replay_filtered_requests(filtered_log, cookies)

            if not analysis_ready_log:
                print("[!] Failed to capture responses for filtered requests. Exiting.")
                sys.exit(1)

            successful_conversations = _filter_successful_conversations(analysis_ready_log)
            if not successful_conversations:
                print("[!] All replay attempts failed. Exiting.")
                sys.exit(1)

            deduped_conversations = _dedupe_conversations(successful_conversations)
            dropped = len(successful_conversations) - len(deduped_conversations)
            if dropped:
                print(f"[+] Removed {dropped} duplicate request(s) after replay.")

            analysis_ready_log = deduped_conversations
            print(f"[+] Prepared {len(analysis_ready_log)} unique conversations for analysis.")

            if not args.skip_cache_save:
                BrowserAgent.save_cache(cache_path, analysis_ready_log, cookies, source_url=args.url)

        if not analysis_ready_log:
            print("[!] No request/response pairs available. Exiting.")
            sys.exit(1)

        # --- 3. Analysis Phase ---
        print("\n" + "-"*25 + " Phase 2: Analysis " + "-"*25)
        if args.dashboard:
            DashboardLogger.update_status("analyzing")
            DashboardLogger.log("Starting analysis with Gemini...", "info")

        gemini_analyst = GeminiAnalyst(api_key=args.apikey, model=args.model)
        print(f"[+] Sending {len(analysis_ready_log)} conversations to Gemini for analysis.")
        analysis_result = gemini_analyst.analyze_flow(analysis_ready_log)
        
        print("[+] Analysis complete. Gemini's findings:")
        # A more elegant print will be added later with rich library
        print(json.dumps(analysis_result, indent=2))

        if args.dashboard:
            DashboardLogger.log("Analysis complete. Starting exploitation...", "success")
            DashboardLogger.update_status("testing")

        # --- 4. Exploitation Phase ---
        print("\n" + "-"*20 + " Phase 3: Flow Testing " + "-"*20)
        exploiter = Exploiter(cookies=cookies, target_domain=target_domain)
        
        flow_tests = analysis_result.get("flow_tests", [])
        value_tests = analysis_result.get("value_tests", [])
        manual_hints = analysis_result.get("manual_hints", [])
        
        all_test_results = []

        # Run flow tests (multi-step)
        if flow_tests:
            print(f"\n[+] Running {len(flow_tests)} flow test(s) with Iterative AI Loop...")
            for idx, flow in enumerate(flow_tests, start=1):
                name = flow.get('name', f'Flow Test #{idx}')
                description = flow.get('description', '')
                steps = flow.get('steps', [])
                
                print(f"\n[Flow {idx}/{len(flow_tests)}] {name}")
                print(f"    → {description}")
                
                if args.dashboard:
                    DashboardLogger.log(f"Starting Iterative Flow Test: {name}", "info")

                # --- Iterative Loop Start ---
                test_history = []
                last_result = {"command": "N/A", "stdout": "", "stderr": ""}
                max_iterations = 5
                
                # Include suggested steps in the description to guide the AI
                full_description = f"{name}: {description}\nSuggested Steps:\n{json.dumps(steps, indent=2)}"

                for i in range(max_iterations):
                    print(f"    [Step {i+1}/{max_iterations}] Asking Gemini for next move...")
                    
                    step_analysis = gemini_analyst.get_next_attack_step(
                        test_case_description=full_description,
                        test_history=test_history,
                        last_result=last_result
                    )
                    
                    assessment = step_analysis.get("assessment", "")
                    next_payload = step_analysis.get("next_payload")
                    status = step_analysis.get("status", "CONTINUE_TESTING")
                    
                    print(f"    [AI Assessment] {assessment}")
                    
                    if status == "VULNERABILITY_CONFIRMED":
                        print(f"    [!] VULNERABILITY CONFIRMED!")
                        if args.dashboard:
                            DashboardLogger.add_vulnerability({
                                "name": name,
                                "description": description,
                                "severity": "High",
                                "evidence": assessment
                            })
                        all_test_results.append({
                            "type": "flow",
                            "name": name,
                            "description": description,
                            "result": {"success": True, "history": test_history, "final_assessment": assessment}
                        })
                        break
                    
                    if status == "TEST_CASE_FAILED" or not next_payload:
                        print(f"    [-] Test case ended (Failed or Exhausted).")
                        all_test_results.append({
                            "type": "flow",
                            "name": name,
                            "description": description,
                            "result": {"success": False, "history": test_history, "final_assessment": assessment}
                        })
                        break
                        
                    # Execute the payload
                    method = next_payload.get('method', 'GET')
                    path = next_payload.get('path', '/')
                    print(f"    [Executing] {method} {path}")
                    execution_result = exploiter.run_single_attack(next_payload)
                    
                    # Update state
                    last_result = execution_result
                    test_history.append({
                        "step": i + 1,
                        "payload": next_payload,
                        "result": execution_result
                    })
                    
                    # Dashboard update
                    if args.dashboard:
                        DashboardLogger.log(f"Step {i+1}: {assessment}", "info")

                else:
                    print(f"    [-] Max iterations reached.")
                    all_test_results.append({
                        "type": "flow",
                        "name": name,
                        "description": description,
                        "result": {"success": False, "history": test_history, "final_assessment": "Max iterations reached"}
                    })
                # --- Iterative Loop End ---

        else:
            print("[+] No flow tests suggested.")

        # Run value manipulation tests (single request)
        if value_tests:
            print(f"\n[+] Running {len(value_tests)} value manipulation test(s)...")
            for idx, test in enumerate(value_tests, start=1):
                name = test.get('name', f'Value Test #{idx}')
                description = test.get('description', '')
                
                print(f"\n[Value {idx}/{len(value_tests)}] {name}")
                print(f"    → {description}")

                if args.dashboard:
                    DashboardLogger.log(f"Running Value Test: {name}", "info")
                
                result = exploiter.execute_request(test)
                all_test_results.append({
                    "type": "value",
                    "name": name,
                    "description": description,
                    "result": result
                })

                if args.dashboard:
                     # Simple heuristic for value test success/failure (needs refinement based on status codes)
                     status_code = result.get("response", {}).get("status")
                     if status_code and status_code >= 500:
                         DashboardLogger.add_vulnerability({
                             "name": name,
                             "description": description,
                             "severity": "Medium",
                             "evidence": f"Server Error {status_code}"
                         })

        else:
            print("[+] No value manipulation tests suggested.")

        # Display manual hints
        if manual_hints:
            print("\n" + "-"*20 + " Manual Testing Hints " + "-"*20)
            print(f"[+] {len(manual_hints)} kịch bản cần test thủ công:")
            for idx, hint in enumerate(manual_hints, start=1):
                name = hint.get('name', f'Scenario #{idx}')
                description = hint.get('description', '')
                steps = hint.get('steps', [])
                success_indicator = hint.get('success_indicator', '')
                
                print(f"\n[Hint #{idx}] {name}")
                print(f"  Mô tả: {description}")
                print("  Các bước:")
                for step_idx, step in enumerate(steps, start=1):
                    print(f"    {step_idx}. {step}")
                print(f"  Dấu hiệu thành công: {success_indicator}")

        # --- 5. Final Report Phase (LLM Call #2) ---
        if all_test_results or manual_hints:
            print("\n" + "-"*20 + " Phase 4: Evaluation & Report " + "-"*20)
            print("[+] Sending test results to Gemini for final evaluation...")
            
            final_report = gemini_analyst.generate_report(analysis_result, all_test_results)
            
            # Save the report to a file
            report_filename = f"report-{target_domain}.md"
            try:
                with open(report_filename, 'w') as f:
                    f.write(final_report)
                print(f"[+] Final report saved to: {report_filename}")
            except IOError as e:
                print(f"[!] Error saving report: {e}", file=sys.stderr)

            print("\n" + "="*28 + " BÁO CÁO CUỐI CÙNG " + "="*28)
            print(final_report)
            print("="*68)
        else:
            print("\n[+] No tests executed. Skipping report generation.")

    except Exception as e:
        print(f"[!!!] An unexpected error occurred: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
