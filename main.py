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
    
    args = parser.parse_args()

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
        gemini_analyst = GeminiAnalyst(api_key=args.apikey, model=args.model)
        print(f"[+] Sending {len(analysis_ready_log)} conversations to Gemini for analysis.")
        analysis_result = gemini_analyst.analyze_flow(analysis_ready_log)
        
        print("[+] Analysis complete. Gemini's findings:")
        # A more elegant print will be added later with rich library
        print(json.dumps(analysis_result, indent=2))

        # --- 4. Targeted Exploitation Phase (with Iterative Testing) ---
        print("\n" + "-"*20 + " Phase 3: Targeted Exploitation " + "-"*20)
        exploiter = Exploiter(cookies=cookies, target_domain=target_domain)
        test_cases = analysis_result.get("recommended_test_cases", [])
        exploitation_results = []

        if not test_cases:
            print("[+] No recommended test cases were suggested by the AI.")
        else:
            for idx, test_case in enumerate(test_cases, start=1):
                name = test_case.get('name', f'Test Case #{idx}')
                description = test_case.get('description', '')
                category = test_case.get('category', 'Business Logic')
                command = test_case.get('curl_command') or test_case.get('command')

                print(f"\n[!] Executing test case: {name} (Category: {category})")
                print(f"    -> Goal: {description}")

                if not command:
                    print("    -> Skipping: No curl command supplied by Gemini.")
                    continue

                # Iterative Testing Loop
                max_iterations = 3
                test_history = []
                final_status = "UNKNOWN"
                
                for iteration in range(1, max_iterations + 1):
                    print(f"\n    [Iteration {iteration}/{max_iterations}]")
                    
                    # Execute current command
                    result = exploiter.run_single_attack(command)
                    
                    # Log this attempt
                    attempt_record = {
                        "iteration": iteration,
                        "command": result.get("command", ""),
                        "stdout": result.get("stdout", ""),
                        "stderr": result.get("stderr", "")
                    }
                    test_history.append(attempt_record)
                    
                    print(f"    -> Executed: {result.get('command', 'N/A')[:80]}...")
                    
                    # Ask AI to analyze result and suggest next step
                    ai_decision = gemini_analyst.get_next_attack_step(
                        test_case_description=description,
                        test_history=test_history,
                        last_result=result
                    )
                    
                    assessment = ai_decision.get("assessment", "No assessment")
                    next_payload = ai_decision.get("next_payload", "")
                    final_status = ai_decision.get("status", "UNKNOWN")
                    
                    print(f"    -> AI Assessment: {assessment}")
                    print(f"    -> Status: {final_status}")
                    
                    # Check if we should continue
                    if final_status == "VULNERABILITY_CONFIRMED":
                        print(f"    -> ✅ Vulnerability CONFIRMED after {iteration} iteration(s)!")
                        break
                    elif final_status == "TEST_CASE_FAILED":
                        print(f"    -> ❌ Test case failed - moving to next test.")
                        break
                    elif final_status == "CONTINUE_TESTING" and next_payload:
                        print(f"    -> 🔄 Continuing with refined payload...")
                        command = next_payload
                    else:
                        print(f"    -> No next payload provided. Stopping.")
                        break

                # Record final result
                exploitation_results.append({
                    "test_case": name,
                    "category": category,
                    "description": description,
                    "status": final_status,
                    "iterations": len(test_history),
                    "test_history": test_history
                })

        # --- 5. Final Report Phase ---
        if exploitation_results:
            print("\n" + "-"*24 + " Phase 4: Final Report " + "-"*24)
            final_report = gemini_analyst.generate_report(analysis_result, exploitation_results)
            
            # Save the report to a file
            report_filename = f"report-{target_domain}.md"
            try:
                with open(report_filename, 'w') as f:
                    f.write(final_report)
                print(f"[+] Final report saved successfully to: {report_filename}")
            except IOError as e:
                print(f"[!] Error: Could not save report to file '{report_filename}'. Reason: {e}", file=sys.stderr)

            print("\n" + "="*28 + " Final Report " + "="*28)
            print(final_report)
            print("="*68)

        print("\n[+] LogiScythe run complete.")

    except Exception as e:
        print(f"[!!!] An unexpected error occurred: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
