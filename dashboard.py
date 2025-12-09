# LogiScythe - dashboard.py
# Author: dangnosuy (Dang) & Gemini
# Interactive Web Dashboard for real-time monitoring

from flask import Flask, render_template, jsonify, request
from flask_socketio import SocketIO, emit
import json
import threading
import time
from datetime import datetime
from typing import Dict, List, Any
import os

app = Flask(__name__)
app.config['SECRET_KEY'] = 'logiscythe-dashboard-secret'
socketio = SocketIO(app, cors_allowed_origins="*")

# Global state
dashboard_state = {
    "status": "idle",  # idle, crawling, analyzing, testing, complete
    "target_url": "",
    "start_time": None,
    "crawl_progress": {
        "urls_discovered": 0,
        "urls_visited": 0,
        "forms_found": 0,
        "requests_captured": 0
    },
    "analysis_progress": {
        "conversations_analyzed": 0,
        "total_conversations": 0,
        "ai_model": ""
    },
    "vulnerabilities": [],
    "test_results": [],
    "logs": []
}


class DashboardLogger:
    """Logger that sends messages to the dashboard"""
    
    @staticmethod
    def log(message: str, level: str = "info"):
        """Log a message to dashboard"""
        log_entry = {
            "timestamp": datetime.now().strftime("%H:%M:%S"),
            "level": level,
            "message": message
        }
        dashboard_state["logs"].append(log_entry)
        
        # Keep only last 100 logs
        if len(dashboard_state["logs"]) > 100:
            dashboard_state["logs"] = dashboard_state["logs"][-100:]
        
        # Emit to all connected clients
        socketio.emit('new_log', log_entry)
        
        # Also print to console
        print(f"[{log_entry['timestamp']}] [{level.upper()}] {message}")

    @staticmethod
    def update_status(status: str):
        """Update overall status"""
        dashboard_state["status"] = status
        socketio.emit('status_update', {"status": status})
        DashboardLogger.log(f"Status changed to: {status}", "info")

    @staticmethod
    def update_crawl_progress(urls_discovered: int = None, urls_visited: int = None,
                             forms_found: int = None, requests_captured: int = None):
        """Update crawl progress"""
        if urls_discovered is not None:
            dashboard_state["crawl_progress"]["urls_discovered"] = urls_discovered
        if urls_visited is not None:
            dashboard_state["crawl_progress"]["urls_visited"] = urls_visited
        if forms_found is not None:
            dashboard_state["crawl_progress"]["forms_found"] = forms_found
        if requests_captured is not None:
            dashboard_state["crawl_progress"]["requests_captured"] = requests_captured
        
        socketio.emit('crawl_progress', dashboard_state["crawl_progress"])

    @staticmethod
    def update_analysis_progress(current: int, total: int, model: str = ""):
        """Update analysis progress"""
        dashboard_state["analysis_progress"]["conversations_analyzed"] = current
        dashboard_state["analysis_progress"]["total_conversations"] = total
        if model:
            dashboard_state["analysis_progress"]["ai_model"] = model
        
        socketio.emit('analysis_progress', dashboard_state["analysis_progress"])

    @staticmethod
    def add_vulnerability(vuln: Dict[str, Any]):
        """Add a discovered vulnerability"""
        vuln["id"] = len(dashboard_state["vulnerabilities"]) + 1
        vuln["timestamp"] = datetime.now().isoformat()
        dashboard_state["vulnerabilities"].append(vuln)
        socketio.emit('new_vulnerability', vuln)
        DashboardLogger.log(f"New vulnerability found: {vuln.get('name', 'Unknown')}", "warning")

    @staticmethod
    def add_test_result(result: Dict[str, Any]):
        """Add a test execution result"""
        result["id"] = len(dashboard_state["test_results"]) + 1
        result["timestamp"] = datetime.now().isoformat()
        dashboard_state["test_results"].append(result)
        socketio.emit('new_test_result', result)


# Flask Routes
@app.route('/')
def index():
    """Main dashboard page"""
    return render_template('dashboard.html')


@app.route('/api/state')
def get_state():
    """Get current dashboard state"""
    return jsonify(dashboard_state)


@app.route('/api/vulnerabilities')
def get_vulnerabilities():
    """Get all vulnerabilities"""
    return jsonify(dashboard_state["vulnerabilities"])


@app.route('/api/test_results')
def get_test_results():
    """Get all test results"""
    return jsonify(dashboard_state["test_results"])


@app.route('/api/logs')
def get_logs():
    """Get recent logs"""
    return jsonify(dashboard_state["logs"])


@app.route('/api/clear')
def clear_state():
    """Clear dashboard state"""
    global dashboard_state
    dashboard_state = {
        "status": "idle",
        "target_url": "",
        "start_time": None,
        "crawl_progress": {
            "urls_discovered": 0,
            "urls_visited": 0,
            "forms_found": 0,
            "requests_captured": 0
        },
        "analysis_progress": {
            "conversations_analyzed": 0,
            "total_conversations": 0,
            "ai_model": ""
        },
        "vulnerabilities": [],
        "test_results": [],
        "logs": []
    }
    socketio.emit('state_cleared', {})
    return jsonify({"success": True})


# WebSocket Events
@socketio.on('connect')
def handle_connect():
    """Handle client connection"""
    print("[Dashboard] Client connected")
    emit('initial_state', dashboard_state)


@socketio.on('disconnect')
def handle_disconnect():
    """Handle client disconnection"""
    print("[Dashboard] Client disconnected")


def run_dashboard(host: str = '127.0.0.1', port: int = 5000, debug: bool = False):
    """Start the dashboard server"""
    print(f"[Dashboard] Starting LogiScythe Dashboard on http://{host}:{port}")
    socketio.run(app, host=host, port=port, debug=debug, allow_unsafe_werkzeug=True)


def start_dashboard_thread(host: str = '127.0.0.1', port: int = 5000):
    """Start dashboard in a background thread"""
    dashboard_thread = threading.Thread(
        target=run_dashboard,
        args=(host, port, False),
        daemon=True
    )
    dashboard_thread.start()
    time.sleep(2)  # Wait for server to start
    print(f"[Dashboard] Dashboard is running at http://{host}:{port}")
    return dashboard_thread


# Example: Simulate a scan for testing
def simulate_scan():
    """Simulate a security scan for testing dashboard"""
    DashboardLogger.update_status("crawling")
    dashboard_state["target_url"] = "https://example.com"
    dashboard_state["start_time"] = datetime.now().isoformat()
    
    DashboardLogger.log("Starting crawl of https://example.com", "info")
    
    # Simulate crawling
    for i in range(1, 21):
        time.sleep(0.5)
        DashboardLogger.update_crawl_progress(
            urls_discovered=i * 5,
            urls_visited=i * 3,
            forms_found=i,
            requests_captured=i * 10
        )
        if i % 5 == 0:
            DashboardLogger.log(f"Crawled {i * 3} URLs...", "info")
    
    DashboardLogger.update_status("analyzing")
    DashboardLogger.log("Starting AI analysis with Gemini", "info")
    
    # Simulate analysis
    for i in range(1, 11):
        time.sleep(0.3)
        DashboardLogger.update_analysis_progress(i, 10, "gemini-2.0-flash")
    
    # Add some vulnerabilities
    DashboardLogger.add_vulnerability({
        "name": "Price Manipulation",
        "severity": "CRITICAL",
        "category": "Business Logic",
        "description": "Product price can be manipulated during checkout",
        "url": "https://example.com/api/cart/update"
    })
    
    DashboardLogger.add_vulnerability({
        "name": "IDOR in User Profile",
        "severity": "HIGH",
        "category": "Authorization",
        "description": "User can access other users' profiles",
        "url": "https://example.com/api/profile/{id}"
    })
    
    DashboardLogger.update_status("testing")
    DashboardLogger.log("Starting exploitation phase", "info")
    
    # Simulate testing
    for i in range(1, 4):
        time.sleep(1)
        DashboardLogger.add_test_result({
            "test_case": f"Test Case #{i}",
            "status": "success" if i % 2 == 0 else "failed",
            "iterations": i,
            "confidence": 0.85 if i % 2 == 0 else 0.3
        })
    
    DashboardLogger.update_status("complete")
    DashboardLogger.log("Scan completed successfully!", "success")


if __name__ == "__main__":
    # Create templates directory if it doesn't exist
    os.makedirs('templates', exist_ok=True)
    
    # Start dashboard
    print("[+] Starting LogiScythe Dashboard...")
    print("[+] Open http://127.0.0.1:5000 in your browser")
    
    # Start simulation in background
    sim_thread = threading.Thread(target=simulate_scan, daemon=True)
    sim_thread.start()
    
    # Run dashboard
    run_dashboard(debug=True)
