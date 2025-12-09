#!/usr/bin/env python3
"""
Example: Complete LogiScythe v2.0 Usage
Demonstrates all Top 5 new features
"""

import sys
import time
from datetime import datetime

# Import all new modules
from dashboard import start_dashboard_thread, DashboardLogger
from multi_role import MultiRoleCrawler
from exploit_chain import ExploitChain, CommonChains
from response_validator import ResponseValidator
from exploiter import Exploiter

def example_full_scan():
    """Complete example using all Top 5 features"""
    
    print("="*60)
    print("LogiScythe v2.0 - Complete Example")
    print("="*60)
    print()
    
    # ============================================================
    # 1. START DASHBOARD (Feature #5)
    # ============================================================
    print("📊 Starting Interactive Dashboard...")
    start_dashboard_thread(host='127.0.0.1', port=5000)
    print("✅ Dashboard running at http://127.0.0.1:5000")
    print()
    time.sleep(1)
    
    DashboardLogger.log("LogiScythe v2.0 initialized", "info")
    DashboardLogger.update_status("starting")
    
    # ============================================================
    # 2. MULTI-ROLE SETUP (Feature #2)
    # ============================================================
    print("👥 Setting up Multi-Role Crawling...")
    role_crawler = MultiRoleCrawler()
    
    # Add roles
    admin = role_crawler.add_role(
        name="Admin",
        username="admin@example.com",
        password="admin123",
        expected_access=["/admin", "/users", "/settings"]
    )
    
    user = role_crawler.add_role(
        name="User",
        username="user@example.com",
        password="user123",
        expected_access=["/profile", "/orders"]
    )
    
    DashboardLogger.log(f"Added {len(role_crawler.roles)} user roles", "info")
    print()
    
    # ============================================================
    # 3. SIMULATE CRAWLING
    # ============================================================
    print("🕷️  Starting crawl phase...")
    DashboardLogger.update_status("crawling")
    
    # Simulate crawl progress
    for i in range(1, 11):
        DashboardLogger.update_crawl_progress(
            urls_discovered=i * 10,
            urls_visited=i * 7,
            forms_found=i * 2,
            requests_captured=i * 15
        )
        time.sleep(0.3)
    
    DashboardLogger.log("Crawling completed - 70 URLs visited", "success")
    print()
    
    # ============================================================
    # 4. RESPONSE VALIDATOR SETUP (Feature #4)
    # ============================================================
    print("✔️  Initializing Response Validator...")
    validator = ResponseValidator()
    
    # Add custom validation rules
    validator.add_rule(
        name="Price Validation",
        rule_type="regex",
        parameters={"pattern": r'"price":\s*\d+\.?\d*'},
        severity="HIGH",
        description="Ensure price field exists in response"
    )
    
    DashboardLogger.log("Response validator configured", "info")
    print()
    
    # ============================================================
    # 5. EXPLOIT CHAIN CREATION (Feature #3)
    # ============================================================
    print("🔗 Creating Exploit Chain...")
    
    # Use pre-built price manipulation chain
    chain = CommonChains.price_manipulation_chain()
    chain.set_global_variable("target_domain", "shop.example.com")
    chain.set_global_variable("session_cookie", "session=abc123xyz")
    
    DashboardLogger.log(f"Created chain: {chain.name}", "info")
    print(f"Chain: {chain.name}")
    print(f"Steps: {len(chain.steps)}")
    print()
    
    # ============================================================
    # 6. ANALYSIS PHASE
    # ============================================================
    print("🧠 Starting AI Analysis...")
    DashboardLogger.update_status("analyzing")
    
    for i in range(1, 11):
        DashboardLogger.update_analysis_progress(i, 10, "gemini-2.0-flash")
        time.sleep(0.2)
    
    DashboardLogger.log("AI analysis completed", "success")
    print()
    
    # ============================================================
    # 7. ITERATIVE TESTING (Feature #1)
    # ============================================================
    print("⚔️  Starting Iterative Testing...")
    DashboardLogger.update_status("testing")
    
    # Simulate iterative testing
    test_case = {
        "name": "Price Manipulation Test",
        "description": "Attempt to set product price to $0.01 during checkout",
        "initial_command": "curl -X POST https://shop.example.com/api/cart/update -d '{\"price\": 0.01}'"
    }
    
    print(f"Test Case: {test_case['name']}")
    print(f"Description: {test_case['description']}")
    print()
    
    max_iterations = 3
    for iteration in range(1, max_iterations + 1):
        print(f"  [Iteration {iteration}/{max_iterations}]")
        DashboardLogger.log(f"Testing iteration {iteration}/{max_iterations}", "info")
        
        # Simulate response
        mock_response = {
            "command": test_case["initial_command"],
            "stdout": 'HTTP/1.1 200 OK\n{"status": "success", "price": 0.01, "order_id": 12345}',
            "stderr": ""
        }
        
        # Validate response
        validation_result = validator.validate_response(
            mock_response,
            vulnerability_type="price_manipulation"
        )
        
        print(f"  → Confidence: {validation_result['confidence_score']:.1%}")
        print(f"  → Status: {validation_result['overall_result']}")
        
        if validation_result['is_vulnerability_confirmed']:
            print(f"  → ✅ Vulnerability CONFIRMED!")
            
            # Add to dashboard
            DashboardLogger.add_vulnerability({
                "name": "Price Manipulation Vulnerability",
                "severity": "CRITICAL",
                "category": "Business Logic",
                "description": "Product price can be manipulated to $0.01 during checkout flow",
                "url": "https://shop.example.com/api/cart/update"
            })
            
            DashboardLogger.add_test_result({
                "test_case": test_case["name"],
                "status": "success",
                "iterations": iteration,
                "confidence": validation_result['confidence_score']
            })
            
            break
        else:
            print(f"  → ⚠️  Needs more testing...")
        
        time.sleep(0.5)
    
    print()
    
    # ============================================================
    # 8. MULTI-ROLE COMPARISON
    # ============================================================
    print("🔍 Comparing Role Access...")
    
    # Simulate role traffic
    role_crawler.save_role_results("Admin", [
        {"url": "https://shop.example.com/admin/users/123", "response": {"status": 200}},
        {"url": "https://shop.example.com/api/orders/456", "response": {"status": 200}}
    ])
    
    role_crawler.save_role_results("User", [
        {"url": "https://shop.example.com/admin/users/123", "response": {"status": 403}},
        {"url": "https://shop.example.com/api/orders/456", "response": {"status": 200}}
    ])
    
    # Compare access
    findings = role_crawler.compare_access()
    
    if findings.get('idor_candidates'):
        print(f"  → Found {len(findings['idor_candidates'])} IDOR candidates")
        DashboardLogger.add_vulnerability({
            "name": "IDOR in Order Endpoint",
            "severity": "HIGH",
            "category": "Authorization",
            "description": "Users can access other users' orders",
            "url": "https://shop.example.com/api/orders/{id}"
        })
    
    if findings.get('privilege_escalation'):
        print(f"  → Found {len(findings['privilege_escalation'])} privilege escalation issues")
    
    print()
    
    # ============================================================
    # 9. FINAL REPORT
    # ============================================================
    print("📝 Generating Final Report...")
    DashboardLogger.update_status("complete")
    
    # Generate role comparison report
    role_report = role_crawler.generate_role_comparison_report(findings)
    
    # Save to file
    report_file = f"report-{datetime.now().strftime('%Y%m%d-%H%M%S')}.md"
    with open(report_file, 'w') as f:
        f.write("# LogiScythe v2.0 Security Report\n\n")
        f.write(f"**Target**: shop.example.com\n")
        f.write(f"**Date**: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")
        f.write("---\n\n")
        f.write(role_report)
        f.write("\n\n---\n\n")
        f.write(validator.generate_validation_report(validation_result))
    
    print(f"✅ Report saved to: {report_file}")
    DashboardLogger.log(f"Final report saved: {report_file}", "success")
    
    # ============================================================
    # 10. SUMMARY
    # ============================================================
    print()
    print("="*60)
    print("📊 SCAN SUMMARY")
    print("="*60)
    print(f"Vulnerabilities Found: 2")
    print(f"  - CRITICAL: 1 (Price Manipulation)")
    print(f"  - HIGH: 1 (IDOR)")
    print(f"Test Success Rate: 100%")
    print(f"Confidence Score: 95%")
    print()
    print("🎯 All Top 5 features demonstrated successfully!")
    print("📊 Dashboard: http://127.0.0.1:5000")
    print(f"📝 Report: {report_file}")
    print("="*60)
    
    DashboardLogger.log("Scan completed successfully!", "success")


if __name__ == "__main__":
    print("\n🚀 LogiScythe v2.0 - Top 5 Features Demo\n")
    
    try:
        example_full_scan()
        
        print("\n✅ Example completed!")
        print("💡 Keep the dashboard running to view results")
        print("   Press Ctrl+C to exit\n")
        
        # Keep running for dashboard
        while True:
            time.sleep(1)
            
    except KeyboardInterrupt:
        print("\n\n👋 Shutting down...")
        sys.exit(0)
