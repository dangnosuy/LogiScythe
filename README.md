# LogiScythe

**A semi-automated, LLM-powered tool for discovering business logic vulnerabilities.**

*Author: dangnosuy (Dang) & Gemini*

---

## Overview

CrawLLMentor was a great proof-of-concept, but it focused more on academic visualization than practical, actionable results for penetration testers. LogiScythe is the spiritual successor, built from the ground up with a pentester's workflow in mind.

Instead of generating complex graphs, LogiScythe captures a complete business flow (e.g., adding an item to a cart and checking out), sends the entire sequence of HTTP traffic to a powerful AI model (Google Gemini), and receives a direct analysis of potential business logic flaws, complete with ready-to-use `curl` commands for immediate testing.

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

## Usage

Run the tool from your terminal, providing a starting URL and your API key.

```bash
python main.py --url "https://example.com/shop" --apikey "YOUR_GEMINI_API_KEY"
```

### Options

-   `--url`, `-u`: **(Required)** The starting URL to crawl.
-   `--apikey`, `-k`: **(Required)** Your Google Gemini API Key.
-   `--model`, `-m`: (Optional) The Gemini model to use. Defaults to `gemini-1.5-flash`.
-   `--headless`: (Optional) Run the browser in headless mode (no GUI). Recommended for servers.
-   `--cache-file`: (Optional) Custom path for the conversation cache JSON file. Defaults to `crawl-cache-<domain>.json`.
-   `--use-cache`: (Optional) Skip crawling/replay and load the cached request/response dataset + cookies.
-   `--skip-cache-save`: (Optional) Prevent overwriting the cache after capturing new conversations.

---
*This tool is for educational and authorized security testing purposes only.*
