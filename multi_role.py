# LogiScythe - multi_role.py
# Author: dangnosuy (Dang) & Gemini
# Multi-user role crawling for detecting IDOR and privilege escalation

import json
from typing import List, Dict, Any, Optional
from urllib.parse import urlparse
from dataclasses import dataclass, asdict

@dataclass
class UserRole:
    """Represents a user role with credentials and permissions"""
    name: str
    username: str
    password: str
    cookies: List[Dict[str, Any]]
    expected_access: List[str]  # List of URL patterns this role should access
    
    def to_dict(self):
        return asdict(self)


class MultiRoleCrawler:
    """
    Manages crawling with multiple user roles to detect authorization issues.
    """
    def __init__(self):
        self.roles: List[UserRole] = []
        self.role_results: Dict[str, List[Dict[str, Any]]] = {}
        print("[MultiRole] Initialized Multi-Role Crawler")

    def add_role(self, name: str, username: str, password: str, 
                 cookies: List[Dict[str, Any]] = None, 
                 expected_access: List[str] = None) -> UserRole:
        """Add a new user role for testing"""
        role = UserRole(
            name=name,
            username=username,
            password=password,
            cookies=cookies or [],
            expected_access=expected_access or []
        )
        self.roles.append(role)
        print(f"[MultiRole] Added role: {name} (user: {username})")
        return role

    def load_roles_from_file(self, filepath: str):
        """Load multiple roles from a JSON configuration file"""
        try:
            with open(filepath, 'r') as f:
                roles_data = json.load(f)
            
            for role_data in roles_data.get('roles', []):
                self.add_role(
                    name=role_data['name'],
                    username=role_data['username'],
                    password=role_data['password'],
                    cookies=role_data.get('cookies', []),
                    expected_access=role_data.get('expected_access', [])
                )
            print(f"[MultiRole] Loaded {len(self.roles)} roles from {filepath}")
        except Exception as e:
            print(f"[!] Error loading roles file: {e}")

    def compare_access(self) -> Dict[str, Any]:
        """
        Compare access between different roles to detect authorization issues.
        Returns a report of potential IDOR and privilege escalation vulnerabilities.
        """
        if len(self.roles) < 2:
            print("[!] Need at least 2 roles to compare access.")
            return {}

        findings = {
            "idor_candidates": [],
            "privilege_escalation": [],
            "unauthorized_access": []
        }

        print("\n[MultiRole] Analyzing role-based access control...")

        # Compare each role with every other role
        for i, role_a in enumerate(self.roles):
            for role_b in self.roles[i+1:]:
                comparison = self._compare_two_roles(role_a, role_b)
                findings["idor_candidates"].extend(comparison["idor"])
                findings["privilege_escalation"].extend(comparison["privilege"])

        # Check unauthorized access
        for role in self.roles:
            role_traffic = self.role_results.get(role.name, [])
            for interaction in role_traffic:
                url = interaction.get('url', '')
                status = interaction.get('response', {}).get('status')
                
                # If role accessed URLs outside expected patterns with 200 OK
                if status == 200 and role.expected_access:
                    if not any(pattern in url for pattern in role.expected_access):
                        findings["unauthorized_access"].append({
                            "role": role.name,
                            "url": url,
                            "status": status,
                            "severity": "HIGH"
                        })

        print(f"[MultiRole] Found {len(findings['idor_candidates'])} IDOR candidates")
        print(f"[MultiRole] Found {len(findings['privilege_escalation'])} privilege escalation issues")
        print(f"[MultiRole] Found {len(findings['unauthorized_access'])} unauthorized access instances")

        return findings

    def _compare_two_roles(self, role_a: UserRole, role_b: UserRole) -> Dict[str, List[Dict]]:
        """Compare access patterns between two roles"""
        results = {"idor": [], "privilege": []}
        
        traffic_a = self.role_results.get(role_a.name, [])
        traffic_b = self.role_results.get(role_b.name, [])

        # Check if lower privilege role can access higher privilege endpoints
        for interaction_a in traffic_a:
            url_a = interaction_a.get('url', '')
            status_a = interaction_a.get('response', {}).get('status')
            
            for interaction_b in traffic_b:
                url_b = interaction_b.get('url', '')
                status_b = interaction_b.get('response', {}).get('status')
                
                # Same URL accessed by both roles with different expected permissions
                if self._urls_similar(url_a, url_b):
                    if status_a == 200 and status_b == 200:
                        # Both can access - potential IDOR if contains IDs
                        if self._contains_id_parameter(url_a):
                            results["idor"].append({
                                "url_pattern": self._normalize_url(url_a),
                                "role_a": role_a.name,
                                "role_b": role_b.name,
                                "description": f"Both {role_a.name} and {role_b.name} can access user-specific endpoint",
                                "severity": "HIGH"
                            })
                    elif status_a == 403 and status_b == 200:
                        # Role B can access but Role A cannot - expected
                        pass
                    elif status_a == 200 and status_b == 403:
                        # Role A can access but Role B cannot - potential privilege escalation
                        results["privilege"].append({
                            "url": url_a,
                            "lower_role": role_a.name,
                            "higher_role": role_b.name,
                            "description": f"{role_a.name} can access endpoint intended for {role_b.name}",
                            "severity": "CRITICAL"
                        })

        return results

    def _urls_similar(self, url1: str, url2: str) -> bool:
        """Check if two URLs are similar (same path pattern, different IDs)"""
        import re
        # Replace numeric IDs with placeholder
        pattern1 = re.sub(r'\d+', '{id}', url1)
        pattern2 = re.sub(r'\d+', '{id}', url2)
        return pattern1 == pattern2

    def _normalize_url(self, url: str) -> str:
        """Normalize URL by replacing IDs with placeholders"""
        import re
        return re.sub(r'\d+', '{id}', url)

    def _contains_id_parameter(self, url: str) -> bool:
        """Check if URL contains ID-like parameters"""
        import re
        # Check for numeric path segments or query params
        if re.search(r'/\d+', url):
            return True
        if re.search(r'[?&](id|user_id|account_id|order_id)=\d+', url):
            return True
        return False

    def generate_role_comparison_report(self, findings: Dict[str, Any]) -> str:
        """Generate a markdown report comparing role-based access"""
        report = "# Multi-Role Access Analysis Report\n\n"
        
        report += "## Summary\n\n"
        report += f"- **Roles Tested**: {len(self.roles)}\n"
        report += f"- **IDOR Candidates**: {len(findings.get('idor_candidates', []))}\n"
        report += f"- **Privilege Escalation Issues**: {len(findings.get('privilege_escalation', []))}\n"
        report += f"- **Unauthorized Access**: {len(findings.get('unauthorized_access', []))}\n\n"

        # IDOR Section
        if findings.get('idor_candidates'):
            report += "## 🔴 IDOR (Insecure Direct Object Reference) Candidates\n\n"
            for idx, idor in enumerate(findings['idor_candidates'], 1):
                report += f"### {idx}. {idor.get('url_pattern', 'Unknown')}\n"
                report += f"- **Severity**: {idor.get('severity', 'MEDIUM')}\n"
                report += f"- **Roles Affected**: {idor.get('role_a')} and {idor.get('role_b')}\n"
                report += f"- **Description**: {idor.get('description', '')}\n\n"

        # Privilege Escalation Section
        if findings.get('privilege_escalation'):
            report += "## 🔴 Privilege Escalation Vulnerabilities\n\n"
            for idx, priv in enumerate(findings['privilege_escalation'], 1):
                report += f"### {idx}. {priv.get('url', 'Unknown')}\n"
                report += f"- **Severity**: {priv.get('severity', 'HIGH')}\n"
                report += f"- **Lower Privilege Role**: {priv.get('lower_role')}\n"
                report += f"- **Higher Privilege Role**: {priv.get('higher_role')}\n"
                report += f"- **Description**: {priv.get('description', '')}\n\n"

        # Unauthorized Access Section
        if findings.get('unauthorized_access'):
            report += "## 🟡 Unauthorized Access Attempts\n\n"
            for idx, unauth in enumerate(findings['unauthorized_access'], 1):
                report += f"### {idx}. {unauth.get('url', 'Unknown')}\n"
                report += f"- **Role**: {unauth.get('role')}\n"
                report += f"- **Status**: {unauth.get('status')}\n"
                report += f"- **Severity**: {unauth.get('severity', 'MEDIUM')}\n\n"

        return report

    def save_role_results(self, role_name: str, traffic: List[Dict[str, Any]]):
        """Save crawl results for a specific role"""
        self.role_results[role_name] = traffic
        print(f"[MultiRole] Saved {len(traffic)} interactions for role: {role_name}")


# Example usage
if __name__ == "__main__":
    print("[+] Testing MultiRoleCrawler...")
    
    crawler = MultiRoleCrawler()
    
    # Add roles
    admin = crawler.add_role(
        name="Admin",
        username="admin@example.com",
        password="admin123",
        expected_access=["/admin", "/users", "/settings"]
    )
    
    user = crawler.add_role(
        name="Regular User",
        username="user@example.com",
        password="user123",
        expected_access=["/profile", "/orders"]
    )
    
    # Simulate traffic (in real usage, this comes from crawler)
    crawler.save_role_results("Admin", [
        {"url": "https://example.com/admin/users/123", "response": {"status": 200}},
        {"url": "https://example.com/profile/123", "response": {"status": 200}},
    ])
    
    crawler.save_role_results("Regular User", [
        {"url": "https://example.com/admin/users/123", "response": {"status": 403}},
        {"url": "https://example.com/profile/456", "response": {"status": 200}},
    ])
    
    # Compare access
    findings = crawler.compare_access()
    
    # Generate report
    report = crawler.generate_role_comparison_report(findings)
    print(report)
