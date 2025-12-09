# LogiScythe - FEATURES.md
# New Features Documentation

## 🚀 Top 5 Quick Wins Implementation

This document describes the newly implemented features in LogiScythe v2.0.

---

## 1. ✅ Iterative Testing Loop

**Status**: ✅ Implemented

### Description
The AI now performs multiple testing attempts for each vulnerability, learning from previous results and refining payloads automatically.

### How It Works
- AI analyzes the result of each exploit attempt
- Suggests refined payloads based on server responses
- Continues testing up to 3 iterations per vulnerability
- Stops early if vulnerability is confirmed or test fails

### Usage
No configuration needed - automatically activated in `main.py`:

```python
# Iterative testing is now integrated in Phase 3
for iteration in range(1, max_iterations + 1):
    result = exploiter.run_single_attack(command)
    ai_decision = gemini_analyst.get_next_attack_step(
        test_case_description=description,
        test_history=test_history,
        last_result=result
    )
```

### Benefits
- **Higher accuracy**: AI learns from failures and adjusts
- **Fewer false positives**: Multiple confirmations
- **Deeper testing**: Discovers complex vulnerabilities

---

## 2. ✅ Multi-User Role Crawling

**Status**: ✅ Implemented

### Description
Test your application with multiple user roles simultaneously to detect IDOR and privilege escalation vulnerabilities.

### New Module: `multi_role.py`

### Features
- Define multiple user roles (admin, user, guest)
- Compare access patterns between roles
- Automatically detect:
  - IDOR (Insecure Direct Object Reference)
  - Privilege escalation
  - Unauthorized access

### Usage

#### 1. Create roles configuration file (`roles.json`):
```json
{
  "roles": [
    {
      "name": "Admin",
      "username": "admin@example.com",
      "password": "admin123",
      "cookies": [],
      "expected_access": ["/admin", "/users", "/settings"]
    },
    {
      "name": "Regular User",
      "username": "user@example.com",
      "password": "user123",
      "cookies": [],
      "expected_access": ["/profile", "/orders"]
    }
  ]
}
```

#### 2. Use in your script:
```python
from multi_role import MultiRoleCrawler

crawler = MultiRoleCrawler()
crawler.load_roles_from_file("roles.json")

# After crawling with each role...
crawler.save_role_results("Admin", admin_traffic)
crawler.save_role_results("Regular User", user_traffic)

# Compare access
findings = crawler.compare_access()
report = crawler.generate_role_comparison_report(findings)
```

### Benefits
- **Detect IDOR**: Find if users can access others' data
- **Privilege escalation**: Identify unauthorized admin access
- **Comprehensive testing**: Test all permission levels

---

## 3. ✅ Automated Exploit Chains

**Status**: ✅ Implemented

### Description
Create and execute complex multi-step exploit chains where later steps depend on earlier results.

### New Module: `exploit_chain.py`

### Features
- Define multi-step attack sequences
- Extract variables from responses (IDs, tokens, etc.)
- Validate each step with custom rules
- Pre-built common chains (price manipulation, IDOR)

### Usage

#### Basic Chain:
```python
from exploit_chain import ExploitChain

chain = ExploitChain(
    name="Price Manipulation Attack",
    description="Test price manipulation in checkout"
)

# Set global variables
chain.set_global_variable("target_domain", "example.com")
chain.set_global_variable("session_cookie", "session=abc123")

# Add steps
chain.add_step(
    name="Add to Cart",
    description="Add product with original price",
    curl_command="curl -X POST https://{target_domain}/api/cart/add ...",
    expected_status=200,
    extract_variables={
        "cart_id": r'"cart_id":\s*"?(\w+)"?',
        "original_price": r'"price":\s*(\d+\.?\d*)'
    }
)

chain.add_step(
    name="Manipulate Price",
    description="Change price to $0.01",
    curl_command="curl -X PUT https://{target_domain}/api/cart/{cart_id} -d '{\"price\": 0.01}'",
    expected_status=200
)

# Execute
result = chain.execute_chain(exploiter)
```

#### Use Pre-built Chains:
```python
from exploit_chain import CommonChains

# Price manipulation chain
chain = CommonChains.price_manipulation_chain()
chain.set_global_variable("target_domain", "shop.example.com")
chain.set_global_variable("session_cookie", "session=xyz")
result = chain.execute_chain(exploiter)

# IDOR chain
idor_chain = CommonChains.idor_chain()
result = idor_chain.execute_chain(exploiter)
```

### Benefits
- **Test complex flows**: Multi-step business logic
- **Variable extraction**: Reuse data between steps
- **Pre-built patterns**: Common attack chains ready to use

---

## 4. ✅ Response Validator

**Status**: ✅ Implemented

### Description
Automatically validate exploit responses to reduce false positives and increase confidence in findings.

### New Module: `response_validator.py`

### Features
- Generic validation checks (connection, HTTP status, etc.)
- Vulnerability-specific validators
- Confidence scoring system
- Detailed validation reports

### Usage

```python
from response_validator import ResponseValidator

validator = ResponseValidator()

# Add custom rules
validator.add_rule(
    name="Success Message Present",
    rule_type="contains",
    parameters={"text": "success"},
    severity="HIGH"
)

# Validate response
response = {
    "command": "curl ...",
    "stdout": "HTTP/1.1 200 OK\n{\"status\": \"success\", \"price\": 0.01}",
    "stderr": ""
}

result = validator.validate_response(
    response, 
    vulnerability_type="price_manipulation"
)

# Check results
if result["is_vulnerability_confirmed"]:
    print("✅ Vulnerability confirmed!")
    print(f"Confidence: {result['confidence_score']:.1%}")
```

### Built-in Validators

1. **Generic Checks**:
   - Non-empty response
   - No connection errors
   - Valid HTTP response
   - Not generic error page

2. **Price Manipulation**:
   - Price extracted from response
   - Suspicious low price detected
   - Transaction success indicators

3. **IDOR**:
   - User data exposed
   - Authorization checks bypassed

4. **Authentication Bypass**:
   - Session token obtained
   - Authentication success indicators

5. **Privilege Escalation**:
   - Elevated privilege indicators
   - Admin-only content access

### Benefits
- **Reduce false positives**: Only report confirmed vulnerabilities
- **Confidence scoring**: Know how reliable findings are
- **Custom validators**: Add your own validation logic

---

## 5. ✅ Interactive Web Dashboard

**Status**: ✅ Implemented

### Description
Real-time web dashboard to monitor scans, view vulnerabilities, and track progress.

### New Modules: `dashboard.py` + `templates/dashboard.html`

### Features
- **Real-time updates** via WebSockets
- **Live progress tracking**: Crawl, analysis, testing phases
- **Vulnerability browser**: See findings as they're discovered
- **Test results**: Monitor exploit execution
- **Live logs**: Console output in real-time
- **Statistics**: Success rates, counts, metrics

### Usage

#### Option 1: Standalone Dashboard
```bash
python dashboard.py
```
Then open http://127.0.0.1:5000 in your browser.

#### Option 2: Integrate with Main Script
```python
from dashboard import start_dashboard_thread, DashboardLogger

# Start dashboard in background
start_dashboard_thread(host='127.0.0.1', port=5000)

# Use logger throughout your code
DashboardLogger.update_status("crawling")
DashboardLogger.log("Starting crawl...", "info")
DashboardLogger.update_crawl_progress(urls_discovered=10)

# Add vulnerabilities
DashboardLogger.add_vulnerability({
    "name": "Price Manipulation",
    "severity": "CRITICAL",
    "category": "Business Logic",
    "description": "Product price can be manipulated",
    "url": "https://example.com/api/cart"
})

# Add test results
DashboardLogger.add_test_result({
    "test_case": "Test #1",
    "status": "success",
    "iterations": 3,
    "confidence": 0.95
})
```

### Dashboard Features

1. **Status Bar**: Shows current phase (idle, crawling, analyzing, testing, complete)
2. **Crawl Progress**: URLs discovered, visited, forms found, requests captured
3. **Analysis Progress**: AI model used, conversations analyzed, progress bar
4. **Statistics**: Vulnerabilities count, tests executed, success rate
5. **Vulnerabilities Panel**: Real-time list with severity badges
6. **Test Results Panel**: Execution results with status
7. **Live Logs**: Terminal-style output with color coding

### Benefits
- **Better UX**: Visual feedback during long scans
- **Real-time monitoring**: No need to wait for completion
- **Professional presentation**: Share with team/clients
- **Easy debugging**: See exactly what's happening

---

## 🎯 Integration Example

Here's how to use all 5 features together:

```python
from dashboard import start_dashboard_thread, DashboardLogger
from multi_role import MultiRoleCrawler
from exploit_chain import ExploitChain, CommonChains
from response_validator import ResponseValidator
from exploiter import Exploiter

# Start dashboard
start_dashboard_thread()
DashboardLogger.update_status("starting")

# Multi-role setup
role_crawler = MultiRoleCrawler()
role_crawler.load_roles_from_file("roles.json")

# Validator setup
validator = ResponseValidator()

# Create exploit chain
chain = CommonChains.price_manipulation_chain()
chain.set_global_variable("target_domain", "example.com")
chain.set_global_variable("session_cookie", "session=xyz")

# Execute with validation
exploiter = Exploiter(cookies, target_domain)
result = chain.execute_chain(exploiter)

# Validate final result
validation = validator.validate_response(
    result["steps"][-1]["result"],
    vulnerability_type="price_manipulation"
)

# Report to dashboard
if validation["is_vulnerability_confirmed"]:
    DashboardLogger.add_vulnerability({
        "name": chain.name,
        "severity": "CRITICAL",
        "category": "Business Logic",
        "description": chain.description,
        "url": target_url
    })

DashboardLogger.update_status("complete")
```

---

## 📦 Installation

Update your dependencies:

```bash
pip install -r requirements.txt
```

New dependencies added:
- `flask`: Web dashboard server
- `flask-socketio`: Real-time WebSocket communication
- `flask-cors`: CORS support for API

---

## 🔧 Configuration

No additional configuration needed! All features work out of the box.

Optional configurations:
- **Dashboard port**: Change in `dashboard.py` or pass to `start_dashboard_thread(port=8080)`
- **Max iterations**: Modify `max_iterations` in `main.py` (default: 3)
- **Validation rules**: Add custom rules to `response_validator.py`

---

## 📊 Performance Impact

| Feature | Performance Impact | Memory Impact |
|---------|-------------------|---------------|
| Iterative Testing | +2-3x test time (3 iterations) | Low |
| Multi-Role | +N x crawl time (N roles) | Medium |
| Exploit Chains | Minimal (sequential) | Low |
| Response Validator | <100ms per response | Low |
| Web Dashboard | Background thread | Low-Medium |

**Recommendation**: For large scans, use `--headless` mode and disable dashboard simulation.

---

## 🐛 Troubleshooting

### Dashboard not starting
```bash
# Check if port is in use
lsof -i :5000

# Use different port
python dashboard.py --port 8080
```

### Iterative testing too slow
```python
# Reduce max iterations in main.py
max_iterations = 2  # Instead of 3
```

### Multi-role crawling issues
- Ensure cookies are properly formatted
- Check authentication endpoints are correct
- Verify expected_access patterns match actual URLs

---

## 🎓 Next Steps

After implementing Top 5 features, consider:
- **Smart Form Fuzzing**: Boundary value testing
- **OAuth/SAML Support**: Complex authentication
- **State Machine Modeling**: Workflow bypass detection
- **Multi-Model AI**: Use multiple LLMs for comparison
- **Parallel Processing**: Speed up large scans

---

## 📝 Changelog

### v2.0.0 (2025-12-09)
- ✅ Added Iterative Testing Loop
- ✅ Added Multi-User Role Crawling
- ✅ Added Automated Exploit Chains
- ✅ Added Response Validator
- ✅ Added Interactive Web Dashboard

### v1.0.0 (Initial)
- Basic crawling with Playwright
- AI analysis with Gemini
- Simple exploitation
- Markdown reports

---

## 🙏 Credits

**Author**: dangnosuy (Dang) & Gemini  
**License**: MIT  
**Repository**: LogiScythe - Business Logic Testing Tool

---

**Happy Hunting! 🎯**
