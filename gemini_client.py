# LogiScythe - gemini_client.py
# Author: dangnosuy (Dang) & Gemini

import google.generativeai as genai
import json
from typing import List, Dict, Any, Optional
import sys
from google.api_core import exceptions as google_exceptions

# Phase 1: Analyze flow and generate test cases
ANALYSIS_SYSTEM_PROMPT = """
Bạn là chuyên gia phân tích bảo mật chuyên về lỗ hổng logic nghiệp vụ (business logic flaws).

**QUAN TRỌNG: Tất cả nội dung trả về phải bằng TIẾNG VIỆT.**

## Nhiệm vụ của bạn:

### 1. Phân tích luồng nghiệp vụ
Từ các HTTP conversations được cung cấp, xác định luồng nghiệp vụ chính:
- Liệt kê các bước theo thứ tự: A → B → C → D
- Mỗi bước = 1 endpoint quan trọng (bỏ qua static files, assets)
- Ghi chú mục đích của từng bước

### 2. Tạo Flow Test Cases (tối đa 5)
Đây là các test case kiểm tra luồng nghiệp vụ bằng cách:
- **Bỏ qua bước**: A → C (skip B) 
- **Đảo thứ tự**: C → B → A
- **Lặp lại bước**: A → B → B → C (apply coupon 2 lần)
- **Truy cập trực tiếp**: Vào thẳng bước cuối mà không qua các bước trước

Mỗi flow test phải có:
- Tên mô tả
- Lý do test (tại sao có thể là lỗ hổng)
- Danh sách các bước (steps) với method, path, body

### 3. Tạo Value Manipulation Tests (tối đa 3)
Các test đơn giản thay đổi giá trị:
- Số âm (quantity = -1, price = -100)
- Giá trị 0
- Giá trị cực lớn (999999)
- Thay đổi ID (user_id, order_id của người khác)

Mỗi test cần: method, path, body, description

### 4. Manual Hints (tối đa 2)
Các kịch bản phức tạp cần test thủ công (race condition, timing attacks, v.v.)

## Định dạng output JSON:

```json
{
    "business_flow": {
        "diagram": "A (GET /) → B (POST /login) → C (GET /cart) → D (POST /checkout)",
        "steps": [
            {"step": "A", "method": "GET", "path": "/", "purpose": "Trang chủ"},
            {"step": "B", "method": "POST", "path": "/login", "purpose": "Đăng nhập"},
            {"step": "C", "method": "GET", "path": "/cart", "purpose": "Xem giỏ hàng"},
            {"step": "D", "method": "POST", "path": "/checkout", "purpose": "Thanh toán"}
        ]
    },
    "flow_tests": [
        {
            "name": "Bỏ qua bước thêm vào giỏ hàng",
            "description": "Thử checkout trực tiếp mà không thêm sản phẩm vào giỏ",
            "vulnerability_type": "Broken Access Control",
            "steps": [
                {"method": "GET", "path": "/", "description": "Truy cập trang chủ"},
                {"method": "POST", "path": "/checkout", "body": {"productId": "1"}, "description": "Checkout trực tiếp"}
            ]
        }
    ],
    "value_tests": [
        {
            "name": "Số lượng âm",
            "description": "Thử đặt số lượng sản phẩm = -1",
            "method": "POST",
            "path": "/cart/add",
            "body": {"productId": "1", "quantity": -1}
        }
    ],
    "manual_hints": [
        {
            "name": "Race condition khi áp mã giảm giá",
            "description": "Gửi nhiều request áp coupon đồng thời",
            "steps": ["Mở 2 terminal", "Gửi POST /apply-coupon cùng lúc", "Kiểm tra tổng giảm giá"],
            "success_indicator": "Tổng giảm giá > 100% hoặc giá âm"
        }
    ]
}
```

## Lưu ý quan trọng:
- Chỉ sử dụng endpoints từ traffic được cung cấp, KHÔNG bịa endpoint
- Body phải dựa trên cấu trúc thực tế từ traffic
- Ưu tiên các test có khả năng phát hiện lỗ hổng cao
"""

# This is the new prompt template for the iterative testing loop.
ITERATIVE_TESTING_PROMPT_TEMPLATE = """
You are an expert cybersecurity analyst executing a penetration test. You are focused on a single test case.

**Test Case Goal**: {test_case_description}

**Test History So Far**:
{test_history}

**Last Attempt's Result**:
- Request Sent: `{command_executed}`
- Response Body:
```
{stdout}
```
- Response Status/Headers:
```
{stderr}
```

**Your Task**:
Analyze the result of the last attempt and decide the next action.
1.  **Assessment**: Briefly explain if the last attempt revealed anything interesting, succeeded, or failed.
2.  **Next Payload**: Provide the *exact* JSON object representing the next HTTP request to execute.
    The JSON object must have the following fields:
    - `method`: HTTP method (e.g., "GET", "POST").
    - `path`: The path of the URL (e.g., "/api/login"). Do NOT include the domain.
    - `headers`: A dictionary of HTTP headers.
    - `body`: The request body (can be a JSON object or a string).
    - `description`: A short description of what this request does.
    
    If you believe the test case is exhausted or successful, provide `null` for `next_payload`.

3.  **Status**: Triage the current state of this test case. Choose ONE of the following statuses:
    - `CONTINUE_TESTING`: If you are providing a new payload to continue probing.
    - `VULNERABILITY_CONFIRMED`: If the last attempt's result proves the vulnerability exists.
    - `TEST_CASE_FAILED`: If you believe this line of attack is not fruitful and we should stop.

You MUST return your response as a single, valid JSON object.
{
    "assessment": "Your brief analysis of the last result.",
    "next_payload": {
        "method": "POST",
        "path": "/example",
        "headers": {"Content-Type": "application/json"},
        "body": {"key": "value"},
        "description": "Testing X"
    },
    "status": "CONTINUE_TESTING | VULNERABILITY_CONFIRMED | TEST_CASE_FAILED"
}
"""


REPORTING_PROMPT = """
Bạn là chuyên gia phân tích bảo mật đang hoàn thiện báo cáo kiểm thử xâm nhập.

**QUAN TRỌNG: Toàn bộ báo cáo phải được viết bằng TIẾNG VIỆT.**

## Dữ liệu đầu vào:

1. **Phân tích luồng nghiệp vụ ban đầu**: Bao gồm sơ đồ luồng và các test cases đã được đề xuất
2. **Kết quả thực thi test**: Kết quả HTTP response từ việc chạy các test cases

## Yêu cầu báo cáo:

### 1. Tóm tắt điều hành (Executive Summary)
- Tổng quan ngắn gọn về cuộc kiểm thử
- Số lượng lỗ hổng phát hiện theo mức độ nghiêm trọng (Cao/Trung bình/Thấp)
- Kết luận chính

### 2. Luồng nghiệp vụ đã kiểm thử
- Sơ đồ luồng: A → B → C → D
- Mô tả mục đích từng bước

### 3. Kết quả kiểm thử luồng (Flow Tests)
Với mỗi flow test đã thực hiện:
- **Tên test**: [Tên]
- **Mô tả**: [Mục đích test]
- **Kết quả**: ✅ Đã xác nhận lỗ hổng / ⚠️ Nghi ngờ / ❌ Không tìm thấy
- **Phân tích**: Giải thích dựa trên HTTP response (status code, body content)
- **Mức độ nghiêm trọng**: Cao/Trung bình/Thấp (nếu là lỗ hổng)

### 4. Kết quả kiểm thử giá trị (Value Tests)
Tương tự như trên

### 5. Hướng dẫn test thủ công
Với mỗi manual hint:
- [ ] Tên kịch bản
- Các bước thực hiện
- Dấu hiệu thành công

### 6. Khuyến nghị khắc phục
- Liệt kê cụ thể cho từng lỗ hổng đã xác nhận
- Ưu tiên theo mức độ nghiêm trọng

### 7. Kết luận
- Đánh giá tổng thể về bảo mật logic nghiệp vụ
- Điểm số bảo mật (nếu có thể ước lượng)

Định dạng output: Markdown với các tiêu đề rõ ràng, bảng biểu khi cần thiết.
"""

class GeminiAnalyst:
    """
    The GeminiAnalyst is the "brain" of the tool. It communicates with the 
    Google Gemini API to analyze the captured HTTP traffic for business logic flaws.
    """
    def __init__(self, api_key: str, model: str = "gemini-2.0-flash"):
        print(f"[GeminiClient] Initializing Gemini Analyst with model: {model}")
        self.api_key = api_key
        self.model_name = model
        genai.configure(api_key=self.api_key)
        # The model for the initial, high-level analysis
        self.analysis_model = genai.GenerativeModel(
            model_name=self.model_name,
            system_instruction=ANALYSIS_SYSTEM_PROMPT
        )
        # The model for the step-by-step testing loop (no system instruction needed, it's in the prompt)
        self.testing_model = genai.GenerativeModel(model_name=self.model_name)
        # A separate model configuration for reporting
        self.reporting_model = genai.GenerativeModel(
            model_name=self.model_name,
            system_instruction=REPORTING_PROMPT
        )

    def _clean_response(self, raw_response: str) -> Dict[str, Any]:
        """
        Cleans the raw string response from the LLM to extract only the valid JSON object.
        """
        print("[GeminiClient] Cleaning raw LLM response...")
        
        json_start = raw_response.find('{')
        json_end = raw_response.rfind('}') + 1

        if json_start == -1 or json_end == 0:
            print("[!] Error: Could not find a JSON object in the LLM's response.")
            raise ValueError("Invalid response format from LLM: No JSON object found.")

        json_string = raw_response[json_start:json_end]
        
        try:
            return json.loads(json_string)
        except json.JSONDecodeError as e:
            print(f"[!] Error: Failed to decode JSON from LLM response: {e}")
            print(f"--- Raw Response Snippet ---\n{json_string}\n--------------------------")
            raise

    def analyze_flow(self, http_traffic: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        Sends the captured HTTP traffic to the Gemini model for an initial analysis
        and to get a list of recommended test cases.
        """
        print(f"[GeminiClient] Analyzing a flow with {len(http_traffic)} captured interactions for a test strategy.")
        
        traffic_json = json.dumps(http_traffic, indent=2)
        prompt = f"Here is the captured HTTP traffic log:\n{traffic_json}"
        
        print("[GeminiClient] Sending request to Gemini API for initial analysis...")
        try:
            response = self.analysis_model.generate_content(prompt)
            print("[GeminiClient] Received response from API.")
            return self._clean_response(response.text)
            
        except google_exceptions.ResourceExhausted as e:
            print("[!] Gemini API Error (429): Rate limit exceeded. Please check your billing or wait.", file=sys.stderr)
            sys.exit(1)
        except (google_exceptions.ServiceUnavailable, google_exceptions.InternalServerError) as e:
            print(f"[!] Gemini API Error (5xx): Service unavailable. Please try again later. Details: {e}", file=sys.stderr)
            sys.exit(1)
        except google_exceptions.GoogleAPICallError as e:
            print(f"[!] An unexpected Gemini API error occurred: {e}", file=sys.stderr)
            sys.exit(1)
        except Exception as e:
            print(f"[!] A general error occurred during API communication: {e}", file=sys.stderr)
            sys.exit(1)

    def get_next_attack_step(
        self, 
        test_case_description: str,
        test_history: List[Dict[str, str]],
        last_result: Dict[str, str]
    ) -> Dict[str, Any]:
        """
        Executes one step in the iterative testing loop.
        """
        print("[GeminiClient] Getting next step from iterative testing loop...")

        history_str = json.dumps(test_history, indent=2) if test_history else "No previous attempts in this test case."
        
        prompt = ITERATIVE_TESTING_PROMPT_TEMPLATE.format(
            test_case_description=test_case_description,
            test_history=history_str,
            command_executed=last_result.get("command", "N/A"),
            stdout=last_result.get("stdout", "")[:5000], # Truncate to avoid token limits
            stderr=last_result.get("stderr", "")[:1000]
        )

        try:
            response = self.testing_model.generate_content(prompt)
            print("[GeminiClient] Received response from testing model.")
            return self._clean_response(response.text)

        except Exception as e:
            # For the loop, we don't want to exit on API errors, just report and let the main loop decide what to do
            error_response = {
                "assessment": f"An API error occurred: {e}",
                "next_payload": "",
                "status": "TEST_CASE_FAILED"
            }
            print(f"[!] An error occurred during API communication in test loop: {e}", file=sys.stderr)
            return error_response

    def generate_report(self, original_analysis: Dict[str, Any], exploitation_results: List[Dict[str, str]]) -> str:
        """
        Generates a final Markdown report based on the initial analysis and exploitation results.
        """
        print("[GeminiClient] Generating final report...")
        
        analysis_json = json.dumps(original_analysis, indent=2)
        results_json = json.dumps(exploitation_results, indent=2)
        
        prompt = f"""
Please generate a penetration test report based on the following data.

## 1. Initial Analysis

This was the initial analysis of the application, suggesting potential flaws:
```json
{analysis_json}
```

## 2. Execution Results

These are the results from running the suggested `curl` commands:
```json
{results_json}
```

Now, please provide the final report in Markdown format.
"""
        
        print("[GeminiClient] Sending request to Gemini API for final report... (This may take a moment)")
        try:
            response = self.reporting_model.generate_content(prompt)
            print("[GeminiClient] Received final report from API.")
            return response.text

        except google_exceptions.ResourceExhausted as e:
            print("[!] Gemini API Error (429): Rate limit exceeded or quota exhausted. Please check your billing account or wait and try again.", file=sys.stderr)
            sys.exit(1)
        except (google_exceptions.ServiceUnavailable, google_exceptions.InternalServerError) as e:
            print(f"[!] Gemini API Error (5xx): The service is temporarily unavailable. Please try again later. Details: {e}", file=sys.stderr)
            sys.exit(1)
        except google_exceptions.GoogleAPICallError as e:
            print(f"[!] An unexpected Gemini API error occurred: {e}", file=sys.stderr)
            sys.exit(1)
        except Exception as e:
            print(f"[!] A general error occurred during API communication: {e}", file=sys.stderr)
            sys.exit(1)

# Example usage (for testing this file directly)
if __name__ == '__main__':
    print("[+] Running gemini_client.py in standalone test mode.")
    
    import os
    api_key = os.environ.get("GEMINI_API_KEY")

    if not api_key:
        print("[!] GEMINI_API_KEY environment variable not set. Cannot run test.")
    else:
        # 1. Test the initial analysis
        dummy_traffic = [
            {"method": "POST", "url": "https://example.com/api/login", "postData": "user=test&pass=test"},
            {"method": "POST", "url": "https://example.com/api/cart/add", "postData": '{"item_id": "A-542", "quantity": 1, "price": 25.00}'}
        ]
        
        analyst = GeminiAnalyst(api_key=api_key)
        
        try:
            analysis = analyst.analyze_flow(dummy_traffic)
            print("\n" + "="*30 + " INITIAL ANALYSIS RESULTS " + "="*30)
            print(json.dumps(analysis, indent=2))

            # 2. Test the iterative loop (if analysis was successful)
            if analysis.get("recommended_test_cases"):
                first_test_case = analysis["recommended_test_cases"][0]
                print(f"\n[+] Testing first test case: {first_test_case['name']}")

                # Dummy first result (as if we tried something and got a response)
                dummy_last_result = {
                    "command": "curl -X POST https://example.com/api/cart/add -d '{\"price\": -999}'",
                    "stdout": "HTTP/1.1 200 OK\nContent-Type: application/json\n\n{\"status\": \"success\", \"item_added\": true}",
                    "stderr": ""
                }

                next_step = analyst.get_next_attack_step(
                    test_case_description=first_test_case['description'],
                    test_history=[],
                    last_result=dummy_last_result
                )
                print("\n" + "="*30 + " ITERATIVE STEP RESULTS " + "="*30)
                print(json.dumps(next_step, indent=2))

        except Exception as e:
            print(f"\n[!!!] An error occurred during the test: {e}")

