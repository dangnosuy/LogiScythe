# LogiScythe - response_validator.py
# Author: dangnosuy (Dang) & Gemini
# Automated response validation to reduce false positives

import json
import re
from typing import Dict, Any, List, Optional, Callable
from dataclasses import dataclass
from enum import Enum

class ValidationResult(Enum):
    """Validation result states"""
    PASS = "pass"
    FAIL = "fail"
    WARNING = "warning"
    UNKNOWN = "unknown"


@dataclass
class ValidationRule:
    """Represents a single validation rule"""
    name: str
    rule_type: str
    parameters: Dict[str, Any]
    severity: str = "MEDIUM"  # LOW, MEDIUM, HIGH, CRITICAL
    description: str = ""


class ResponseValidator:
    """
    Validates exploit responses to determine if vulnerabilities are real.
    Helps reduce false positives by checking expected behaviors.
    """
    
    def __init__(self):
        self.rules: List[ValidationRule] = []
        print("[ResponseValidator] Initialized Response Validator")

    def add_rule(self, name: str, rule_type: str, parameters: Dict[str, Any],
                 severity: str = "MEDIUM", description: str = "") -> ValidationRule:
        """Add a validation rule"""
        rule = ValidationRule(
            name=name,
            rule_type=rule_type,
            parameters=parameters,
            severity=severity,
            description=description
        )
        self.rules.append(rule)
        return rule

    def validate_response(self, response: Dict[str, str], 
                         vulnerability_type: str = "generic") -> Dict[str, Any]:
        """
        Validate a response against all applicable rules.
        
        Args:
            response: Dictionary with 'command', 'stdout', 'stderr'
            vulnerability_type: Type of vulnerability being tested
            
        Returns:
            Validation report with pass/fail status and confidence score
        """
        stdout = response.get("stdout", "")
        stderr = response.get("stderr", "")
        command = response.get("command", "")

        validation_report = {
            "overall_result": ValidationResult.UNKNOWN.value,
            "confidence_score": 0.0,
            "rules_passed": 0,
            "rules_failed": 0,
            "details": [],
            "is_vulnerability_confirmed": False
        }

        # Apply generic rules first
        generic_checks = self._run_generic_checks(stdout, stderr)
        validation_report["details"].extend(generic_checks)

        # Apply specific validation rules
        for rule in self.rules:
            result = self._apply_rule(rule, stdout, stderr, command)
            validation_report["details"].append(result)
            
            if result["result"] == ValidationResult.PASS.value:
                validation_report["rules_passed"] += 1
            elif result["result"] == ValidationResult.FAIL.value:
                validation_report["rules_failed"] += 1

        # Apply vulnerability-specific validators
        specific_checks = self._run_vulnerability_specific_checks(
            vulnerability_type, stdout, stderr
        )
        validation_report["details"].extend(specific_checks)

        # Calculate confidence score
        total_checks = len(validation_report["details"])
        if total_checks > 0:
            passed = sum(1 for d in validation_report["details"] 
                        if d["result"] == ValidationResult.PASS.value)
            validation_report["confidence_score"] = passed / total_checks

        # Determine overall result
        if validation_report["confidence_score"] >= 0.7:
            validation_report["overall_result"] = ValidationResult.PASS.value
            validation_report["is_vulnerability_confirmed"] = True
        elif validation_report["confidence_score"] >= 0.4:
            validation_report["overall_result"] = ValidationResult.WARNING.value
        else:
            validation_report["overall_result"] = ValidationResult.FAIL.value

        return validation_report

    def _run_generic_checks(self, stdout: str, stderr: str) -> List[Dict[str, Any]]:
        """Run generic validation checks applicable to all responses"""
        checks = []

        # Check 1: Response not empty
        checks.append({
            "rule": "Non-empty Response",
            "result": ValidationResult.PASS.value if stdout else ValidationResult.FAIL.value,
            "message": "Response received" if stdout else "Empty response",
            "severity": "HIGH"
        })

        # Check 2: No connection errors
        connection_errors = ["Connection refused", "Could not resolve host", "timeout"]
        has_connection_error = any(err.lower() in stderr.lower() for err in connection_errors)
        checks.append({
            "rule": "No Connection Errors",
            "result": ValidationResult.FAIL.value if has_connection_error else ValidationResult.PASS.value,
            "message": "Connection error detected" if has_connection_error else "No connection errors",
            "severity": "HIGH"
        })

        # Check 3: HTTP status code present
        status_match = re.search(r'HTTP/[\d.]+\s+(\d+)', stdout)
        checks.append({
            "rule": "Valid HTTP Response",
            "result": ValidationResult.PASS.value if status_match else ValidationResult.FAIL.value,
            "message": f"Status code: {status_match.group(1)}" if status_match else "No HTTP status found",
            "severity": "MEDIUM"
        })

        # Check 4: Not a generic error page
        error_indicators = ["404 Not Found", "500 Internal Server", "403 Forbidden"]
        is_error_page = any(err in stdout for err in error_indicators)
        checks.append({
            "rule": "Not Generic Error Page",
            "result": ValidationResult.WARNING.value if is_error_page else ValidationResult.PASS.value,
            "message": "Generic error page detected" if is_error_page else "Valid response page",
            "severity": "MEDIUM"
        })

        return checks

    def _run_vulnerability_specific_checks(self, vuln_type: str, 
                                          stdout: str, stderr: str) -> List[Dict[str, Any]]:
        """Run checks specific to vulnerability type"""
        checks = []

        if vuln_type.lower() in ["price_manipulation", "price_tampering"]:
            checks.extend(self._validate_price_manipulation(stdout))
        elif vuln_type.lower() in ["idor", "insecure_direct_object_reference"]:
            checks.extend(self._validate_idor(stdout))
        elif vuln_type.lower() in ["auth_bypass", "authentication_bypass"]:
            checks.extend(self._validate_auth_bypass(stdout))
        elif vuln_type.lower() in ["privilege_escalation"]:
            checks.extend(self._validate_privilege_escalation(stdout))
        elif vuln_type.lower() in ["race_condition"]:
            checks.extend(self._validate_race_condition(stdout))

        return checks

    def _validate_price_manipulation(self, response: str) -> List[Dict[str, Any]]:
        """Specific validation for price manipulation vulnerabilities"""
        checks = []

        # Check for price in response
        price_match = re.search(r'"?(?:price|total|amount)"?\s*:\s*[\"]?(\d+\.?\d*)', response, re.IGNORECASE)
        if price_match:
            price = float(price_match.group(1))
            checks.append({
                "rule": "Price Extracted",
                "result": ValidationResult.PASS.value,
                "message": f"Found price: {price}",
                "severity": "HIGH",
                "extracted_value": price
            })

            # Check if price is suspiciously low
            if price < 1.0:
                checks.append({
                    "rule": "Suspicious Low Price",
                    "result": ValidationResult.PASS.value,
                    "message": f"Price is unusually low: {price} (possible manipulation success)",
                    "severity": "CRITICAL"
                })
        else:
            checks.append({
                "rule": "Price Extracted",
                "result": ValidationResult.FAIL.value,
                "message": "Could not extract price from response",
                "severity": "MEDIUM"
            })

        # Check for success indicators
        success_indicators = ["success", "order_confirmed", "payment_accepted", "transaction_complete"]
        has_success = any(indicator in response.lower() for indicator in success_indicators)
        checks.append({
            "rule": "Transaction Success Indicator",
            "result": ValidationResult.PASS.value if has_success else ValidationResult.FAIL.value,
            "message": "Transaction appears successful" if has_success else "No success indicator found",
            "severity": "HIGH"
        })

        return checks

    def _validate_idor(self, response: str) -> List[Dict[str, Any]]:
        """Specific validation for IDOR vulnerabilities"""
        checks = []

        # Check for user/profile data
        user_data_patterns = [
            r'"(?:user_id|userId|id)"\s*:\s*(\d+)',
            r'"(?:email|username)"\s*:\s*"([^"]+)"',
            r'"(?:name|full_name)"\s*:\s*"([^"]+)"'
        ]
        
        found_user_data = False
        for pattern in user_data_patterns:
            if re.search(pattern, response, re.IGNORECASE):
                found_user_data = True
                break

        checks.append({
            "rule": "User Data Exposed",
            "result": ValidationResult.PASS.value if found_user_data else ValidationResult.FAIL.value,
            "message": "Sensitive user data found in response" if found_user_data else "No user data found",
            "severity": "CRITICAL"
        })

        # Check for authorization errors (which would indicate IDOR is prevented)
        auth_errors = ["unauthorized", "forbidden", "access denied", "not authorized"]
        has_auth_error = any(err in response.lower() for err in auth_errors)
        checks.append({
            "rule": "Authorization Check Present",
            "result": ValidationResult.FAIL.value if has_auth_error else ValidationResult.PASS.value,
            "message": "Authorization blocked access (IDOR prevented)" if has_auth_error else "No authorization check detected (IDOR possible)",
            "severity": "CRITICAL"
        })

        return checks

    def _validate_auth_bypass(self, response: str) -> List[Dict[str, Any]]:
        """Specific validation for authentication bypass"""
        checks = []

        # Check for successful authentication indicators
        auth_success = ["logged in", "session", "token", "authenticated", "welcome"]
        has_auth_success = any(indicator in response.lower() for indicator in auth_success)
        checks.append({
            "rule": "Authentication Success",
            "result": ValidationResult.PASS.value if has_auth_success else ValidationResult.FAIL.value,
            "message": "Authentication bypass successful" if has_auth_success else "Authentication still required",
            "severity": "CRITICAL"
        })

        # Check for session token
        token_match = re.search(r'"?(?:token|session_id|auth)"?\s*:\s*"([^"]+)"', response)
        checks.append({
            "rule": "Session Token Obtained",
            "result": ValidationResult.PASS.value if token_match else ValidationResult.FAIL.value,
            "message": f"Token found: {token_match.group(1)[:20]}..." if token_match else "No session token",
            "severity": "CRITICAL"
        })

        return checks

    def _validate_privilege_escalation(self, response: str) -> List[Dict[str, Any]]:
        """Specific validation for privilege escalation"""
        checks = []

        # Check for admin/elevated privilege indicators
        privilege_indicators = ["admin", "administrator", "role", "superuser", "elevated"]
        has_privilege = any(indicator in response.lower() for indicator in privilege_indicators)
        checks.append({
            "rule": "Elevated Privilege Indicators",
            "result": ValidationResult.PASS.value if has_privilege else ValidationResult.FAIL.value,
            "message": "Elevated privileges detected" if has_privilege else "No privilege elevation detected",
            "severity": "CRITICAL"
        })

        # Check for admin-only content
        admin_content = ["delete user", "manage users", "system settings", "admin panel"]
        has_admin_content = any(content in response.lower() for content in admin_content)
        checks.append({
            "rule": "Admin-only Content Access",
            "result": ValidationResult.PASS.value if has_admin_content else ValidationResult.FAIL.value,
            "message": "Admin content accessible" if has_admin_content else "No admin content found",
            "severity": "HIGH"
        })

        return checks

    def _validate_race_condition(self, response: str) -> List[Dict[str, Any]]:
        """Specific validation for race condition vulnerabilities"""
        checks = []

        # Check for duplicate transactions/operations
        duplicate_indicators = ["duplicate", "already exists", "processed twice"]
        has_duplicate = any(indicator in response.lower() for indicator in duplicate_indicators)
        checks.append({
            "rule": "Duplicate Operation Detected",
            "result": ValidationResult.PASS.value if has_duplicate else ValidationResult.UNKNOWN.value,
            "message": "Duplicate operation detected" if has_duplicate else "No duplicate detected",
            "severity": "HIGH"
        })

        return checks

    def _apply_rule(self, rule: ValidationRule, stdout: str, 
                   stderr: str, command: str) -> Dict[str, Any]:
        """Apply a specific validation rule"""
        result = {
            "rule": rule.name,
            "result": ValidationResult.UNKNOWN.value,
            "message": "",
            "severity": rule.severity
        }

        try:
            if rule.rule_type == "contains":
                text = rule.parameters.get("text", "")
                if text in stdout:
                    result["result"] = ValidationResult.PASS.value
                    result["message"] = f"Found expected text: '{text}'"
                else:
                    result["result"] = ValidationResult.FAIL.value
                    result["message"] = f"Expected text not found: '{text}'"

            elif rule.rule_type == "not_contains":
                text = rule.parameters.get("text", "")
                if text not in stdout:
                    result["result"] = ValidationResult.PASS.value
                    result["message"] = f"Correctly does not contain: '{text}'"
                else:
                    result["result"] = ValidationResult.FAIL.value
                    result["message"] = f"Unexpectedly contains: '{text}'"

            elif rule.rule_type == "regex":
                pattern = rule.parameters.get("pattern", "")
                if re.search(pattern, stdout):
                    result["result"] = ValidationResult.PASS.value
                    result["message"] = f"Matches regex: {pattern}"
                else:
                    result["result"] = ValidationResult.FAIL.value
                    result["message"] = f"Does not match regex: {pattern}"

            elif rule.rule_type == "status_code":
                expected = rule.parameters.get("code", 200)
                status_match = re.search(r'HTTP/[\d.]+\s+(\d+)', stdout)
                if status_match:
                    actual = int(status_match.group(1))
                    if actual == expected:
                        result["result"] = ValidationResult.PASS.value
                        result["message"] = f"Status code matches: {actual}"
                    else:
                        result["result"] = ValidationResult.FAIL.value
                        result["message"] = f"Status code mismatch: {actual} (expected {expected})"
                else:
                    result["result"] = ValidationResult.FAIL.value
                    result["message"] = "Could not extract status code"

            elif rule.rule_type == "json_field":
                field = rule.parameters.get("field", "")
                expected = rule.parameters.get("value")
                try:
                    json_match = re.search(r'\{.*\}', stdout, re.DOTALL)
                    if json_match:
                        data = json.loads(json_match.group(0))
                        actual = self._get_nested_field(data, field)
                        if actual == expected:
                            result["result"] = ValidationResult.PASS.value
                            result["message"] = f"Field '{field}' matches expected value"
                        else:
                            result["result"] = ValidationResult.FAIL.value
                            result["message"] = f"Field '{field}' = {actual}, expected {expected}"
                    else:
                        result["result"] = ValidationResult.FAIL.value
                        result["message"] = "No JSON found in response"
                except Exception as e:
                    result["result"] = ValidationResult.FAIL.value
                    result["message"] = f"JSON validation error: {e}"

        except Exception as e:
            result["result"] = ValidationResult.UNKNOWN.value
            result["message"] = f"Rule execution error: {e}"

        return result

    def _get_nested_field(self, data: dict, field: str) -> Any:
        """Get nested field from dict using dot notation"""
        keys = field.split('.')
        value = data
        for key in keys:
            if isinstance(value, dict):
                value = value.get(key)
            else:
                return None
        return value

    def generate_validation_report(self, validation_result: Dict[str, Any]) -> str:
        """Generate a human-readable validation report"""
        report = "# Response Validation Report\n\n"
        
        report += f"**Overall Result**: {validation_result['overall_result'].upper()}\n"
        report += f"**Confidence Score**: {validation_result['confidence_score']:.1%}\n"
        report += f"**Vulnerability Confirmed**: {'✅ YES' if validation_result['is_vulnerability_confirmed'] else '❌ NO'}\n\n"

        report += "## Validation Checks\n\n"
        
        for detail in validation_result['details']:
            icon = "✅" if detail['result'] == ValidationResult.PASS.value else "❌"
            report += f"- {icon} **{detail['rule']}** ({detail['severity']})\n"
            report += f"  - {detail['message']}\n\n"

        return report


# Example usage
if __name__ == "__main__":
    print("[+] Testing ResponseValidator...")
    
    validator = ResponseValidator()
    
    # Add custom rules
    validator.add_rule(
        name="Success Message Present",
        rule_type="contains",
        parameters={"text": "success"},
        severity="HIGH"
    )
    
    validator.add_rule(
        name="No Error Message",
        rule_type="not_contains",
        parameters={"text": "error"},
        severity="MEDIUM"
    )
    
    # Test response
    test_response = {
        "command": "curl -X POST https://example.com/api/order",
        "stdout": 'HTTP/1.1 200 OK\n{"status": "success", "price": 0.01, "order_id": 12345}',
        "stderr": ""
    }
    
    # Validate
    result = validator.validate_response(test_response, vulnerability_type="price_manipulation")
    
    # Generate report
    report = validator.generate_validation_report(result)
    print(report)
