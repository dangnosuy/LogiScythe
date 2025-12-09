# LogiScythe

**A semi-automated, LLM-powered tool for discovering business logic vulnerabilities.**

*Author: dangnosuy (Dang) & Gemini*

---

## Overview

CrawLLMentor was a great proof-of-concept, but it focused more on academic visualization than practical, actionable results for penetration testers. LogiScythe is the spiritual successor, built from the ground up with a pentester's workflow in mind.

Instead of generating complex graphs, LogiScythe captures a complete business flow (e.g., adding an item to a cart and checking out), sends the entire sequence of HTTP traffic to a powerful AI model (Google Gemini), and receives a direct analysis of potential business logic flaws, complete with ready-to-use `curl` commands for immediate testing.

## 🚀 New in v2.0 - Top 5 Features

LogiScythe v2.0 includes **5 major enhancements** for professional penetration testing:

1. **✅ Iterative Testing Loop**: AI performs multiple testing attempts, learning from failures and refining payloads automatically
2. **✅ Multi-User Role Crawling**: Test with multiple roles simultaneously to detect IDOR and privilege escalation
3. **✅ Automated Exploit Chains**: Create complex multi-step attack sequences with variable extraction
4. **✅ Response Validator**: Intelligent validation system to reduce false positives and increase confidence
5. **✅ Interactive Web Dashboard**: Real-time monitoring with live progress, vulnerabilities, and logs

See [FEATURES.md](FEATURES.md) for detailed documentation.

## How It Works

LogiScythe operates in three distinct phases:

### 1. Crawling (The Eyes & Hands)
-   **Module:** `crawler.py`
-   **Technology:** Playwright
-   The tool launches a browser instance and systematically navigates the target application, starting from the URL you provide.
-   It acts like a user, discovering and following all accessible links within the target domain.
-   Crucially, it intercepts and records every relevant HTTP request and response that occurs during this process, building a complete log of the application's behavior.
-   The raw crawl log stays local; only high-signal interactions continue forward so caches remain manageable.

-### 2. Conversation Capture (Burp-Style)
-   **Module:** `main.py` (Requests)
-   After filtering unique business actions, LogiScythe automatically replays each request with the captured session cookies.
-   Each replay stores the full HTTP request and the live server response (HTML, JSON, etc.), similar to BurpSuite's history view.
-   These conversations are what get cached to disk and sent to Gemini, so re-running analysis no longer requires crawling again.

### 3. Analysis (The Brain)
-   **Module:** `gemini_client.py`
-   **Technology:** Google Gemini
-   The replayed request/response dataset is sent to a Gemini model.
-   A highly specialized `SYSTEM_PROMPT` instructs the AI to act as an expert cybersecurity analyst. It analyzes the *entire conversation flow* for logical weaknesses, such as price tampering, IDOR, or workflow bypasses.
-   The AI returns a structured JSON object containing a summary of the flow and a list of potential vulnerabilities, each with a ready-to-run `curl` template (`name`, `description`, `curl_command`). Placeholders like `{target_domain}` and `{session_cookie}` are left for LogiScythe to fill automatically.

### 4. Exploitation (The Sword)
-   **Module:** `exploiter.py`
-   **Technology:** Python `subprocess`
-   For each vulnerability identified by the AI, LogiScythe extracts the suggested `curl` command payloads.
-   It then automatically executes these commands, using the session cookies captured during the crawl phase (or loaded from cache).
-   The raw output of each command is printed directly to the console, providing immediate feedback and proof-of-concept for the pentester.

### Conversation Caching

-   After each replay step, LogiScythe saves the conversation list (request + response) and cookies to a JSON cache file (default: `crawl-cache-<domain>.json`). Use `--skip-cache-save` if you don't want to overwrite the file.
-   To reuse a previous run, supply `--use-cache` (and optionally `--cache-file`). The tool will skip Playwright and replay entirely, loading the cached conversations instead.
-   Cache files include metadata (`source_url`, `target_domain`, timestamp) plus the deduplicated, successful conversation array and cookies, so downstream phases behave exactly like a fresh crawl.

## Setup

1.  **Clone the repository:**
    ```bash
    git clone <repository_url>
    cd LogiScythe
    ```

2.  **Install dependencies:**
    ```bash
    pip install -r requirements.txt
    ```

3.  **Install browser binaries for Playwright:**
    ```bash
    python -m playwright install
    ```

4.  **Get an API Key:**
    -   Obtain a Google Gemini API key from [Google AI Studio](https://aistudio.google.com/).

## Quick Start

### Basic Scan
```bash
python main.py --url "https://example.com/shop" --apikey "YOUR_API_KEY"
```

### With Interactive Dashboard
```bash
# Terminal 1: Start dashboard
python dashboard.py

# Terminal 2: Run scan (dashboard will update in real-time)
python main.py --url "https://example.com" --apikey "YOUR_API_KEY"

# Open browser: http://127.0.0.1:5000
```

### Complete Example (All Features)
```bash
python examples/complete_example.py
```

## Usage

Run the tool from your terminal, providing a starting URL and your API key.

```bash
python main.py --url "https://example.com/shop" --apikey "YOUR_GEMINI_API_KEY"
```

### Options

-   `--url`, `-u`: **(Required)** The starting URL to crawl.
-   `--apikey`, `-k`: **(Required)** Your Google Gemini API Key.
-   `--model`, `-m`: (Optional) The Gemini model to use. Defaults to `gemini-2.5-pro`.
-   `--headless`: (Optional) Run the browser in headless mode (no GUI). Recommended for servers.
-   `--cache-file`: (Optional) Custom path for the conversation cache JSON file. Defaults to `crawl-cache-<domain>.json`.
-   `--use-cache`: (Optional) Skip crawling/replay and load the cached request/response dataset + cookies.
-   `--skip-cache-save`: (Optional) Prevent overwriting the cache after capturing new conversations.

## 🎯 Advanced Usage

### Multi-Role Testing
```python
from multi_role import MultiRoleCrawler

crawler = MultiRoleCrawler()
crawler.load_roles_from_file("examples/roles.json")
findings = crawler.compare_access()
```

### Exploit Chains
```python
from exploit_chain import CommonChains

chain = CommonChains.price_manipulation_chain()
chain.set_global_variable("target_domain", "shop.example.com")
result = chain.execute_chain(exploiter)
```

### Response Validation
```python
from response_validator import ResponseValidator

validator = ResponseValidator()
result = validator.validate_response(response, "price_manipulation")
if result["is_vulnerability_confirmed"]:
    print(f"Confirmed with {result['confidence_score']:.1%} confidence")
```

## 📊 Project Structure

```
LogiScythe/
├── main.py                 # Main entry point
├── crawler.py              # Playwright-based crawler
├── exploiter.py            # Exploit execution engine
├── gemini_client.py        # AI analysis with Gemini
├── dashboard.py            # 🆕 Web dashboard server
├── multi_role.py           # 🆕 Multi-user role testing
├── exploit_chain.py        # 🆕 Automated exploit chains
├── response_validator.py   # 🆕 Response validation
├── requirements.txt
├── README.md
├── FEATURES.md             # 🆕 Detailed feature docs
├── templates/
│   └── dashboard.html      # 🆕 Dashboard UI
└── examples/
    ├── roles.json          # 🆕 Role configuration
    └── complete_example.py # 🆕 Full demo
```

## 🎓 Documentation

- **[FEATURES.md](FEATURES.md)**: Complete guide to all Top 5 features
- **[examples/](examples/)**: Example configurations and scripts

## 🐛 Troubleshooting

See [FEATURES.md](FEATURES.md) for detailed troubleshooting guide.

## 📝 Changelog

### v2.0.0 (2025-12-09)
- ✅ Iterative Testing Loop with AI learning
- ✅ Multi-User Role Crawling for IDOR detection
- ✅ Automated Exploit Chains with variable extraction
- ✅ Response Validator for false positive reduction
- ✅ Interactive Web Dashboard with real-time updates

### v1.0.0
- Initial release with basic crawling, analysis, and exploitation

---
*This tool is for educational and authorized security testing purposes only.*
