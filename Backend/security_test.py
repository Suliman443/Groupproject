"""
Security Testing Script
Demonstrates the enhanced security features implemented in the system
"""

import requests
import json
import time
import sys
from datetime import datetime

class SecurityTester:
    """Test the enhanced security features of the system"""
    
    def __init__(self, base_url="http://localhost:5000"):
        self.base_url = base_url
        self.session = requests.Session()
        self.test_results = []
    
    def log_test(self, test_name, success, details=""):
        """Log test results"""
        result = {
            'test': test_name,
            'success': success,
            'details': details,
            'timestamp': datetime.now().isoformat()
        }
        self.test_results.append(result)
        status = "✅ PASS" if success else "❌ FAIL"
        print(f"{status} {test_name}: {details}")
    
    def test_security_info_endpoint(self):
        """Test security information endpoint"""
        try:
            response = self.session.get(f"{self.base_url}/security-info")
            if response.status_code == 200:
                data = response.json()
                self.log_test("Security Info Endpoint", True, f"Found {len(data['security_features'])} security features")
                return True
            else:
                self.log_test("Security Info Endpoint", False, f"Status code: {response.status_code}")
                return False
        except Exception as e:
            self.log_test("Security Info Endpoint", False, f"Error: {str(e)}")
            return False
    
    def test_password_strength_validation(self):
        """Test password strength validation"""
        weak_passwords = [
            "123",  # Too short
            "password",  # No uppercase, digits, or special chars
            "PASSWORD",  # No lowercase, digits, or special chars
            "Password",  # No digits or special chars
            "Password1",  # No special chars
        ]
        
        strong_password = "SecurePass123!"
        
        try:
            # Test weak passwords
            for weak_pwd in weak_passwords:
                data = {
                    "email": "test@example.com",
                    "password": weak_pwd,
                    "fullname": "Test User"
                }
                response = self.session.post(f"{self.base_url}/api/auth/secure-signup", json=data)
                if response.status_code == 400:
                    self.log_test(f"Weak Password Rejection ({weak_pwd})", True, "Weak password correctly rejected")
                else:
                    self.log_test(f"Weak Password Rejection ({weak_pwd})", False, f"Status: {response.status_code}")
            
            # Test strong password
            data = {
                "email": "test@example.com",
                "password": strong_password,
                "fullname": "Test User"
            }
            response = self.session.post(f"{self.base_url}/api/auth/secure-signup", json=data)
            if response.status_code in [200, 201]:
                self.log_test("Strong Password Acceptance", True, "Strong password accepted")
                return True
            else:
                self.log_test("Strong Password Acceptance", False, f"Status: {response.status_code}")
                return False
                
        except Exception as e:
            self.log_test("Password Strength Validation", False, f"Error: {str(e)}")
            return False
    
    def test_rate_limiting(self):
        """Test rate limiting functionality"""
        try:
            # Make multiple rapid requests
            for i in range(10):
                data = {
                    "email": f"test{i}@example.com",
                    "password": "TestPass123!",
                    "fullname": f"Test User {i}"
                }
                response = self.session.post(f"{self.base_url}/api/auth/secure-signup", json=data)
                time.sleep(0.1)  # Small delay between requests
            
            # Check if rate limiting is working
            response = self.session.get(f"{self.base_url}/api/auth/security-status")
            if response.status_code == 429:
                self.log_test("Rate Limiting", True, "Rate limit correctly enforced")
                return True
            else:
                self.log_test("Rate Limiting", False, "Rate limiting not working")
                return False
                
        except Exception as e:
            self.log_test("Rate Limiting", False, f"Error: {str(e)}")
            return False
    
    def test_account_lockout(self):
        """Test account lockout after multiple failed login attempts"""
        try:
            # Attempt multiple failed logins
            for i in range(6):  # More than the limit
                data = {
                    "email": "test@example.com",
                    "password": "wrongpassword"
                }
                response = self.session.post(f"{self.base_url}/api/auth/secure-login", json=data)
                time.sleep(0.1)
            
            # Try one more login - should be locked
            data = {
                "email": "test@example.com",
                "password": "correctpassword"
            }
            response = self.session.post(f"{self.base_url}/api/auth/secure-login", json=data)
            
            if response.status_code == 423:  # Account locked
                self.log_test("Account Lockout", True, "Account correctly locked after failed attempts")
                return True
            else:
                self.log_test("Account Lockout", False, f"Status: {response.status_code}")
                return False
                
        except Exception as e:
            self.log_test("Account Lockout", False, f"Error: {str(e)}")
            return False
    
    def test_secure_token_creation(self):
        """Test secure token creation and validation"""
        try:
            # Create a user
            data = {
                "email": "token_test@example.com",
                "password": "SecurePass123!",
                "fullname": "Token Test User"
            }
            response = self.session.post(f"{self.base_url}/api/auth/secure-signup", json=data)
            
            if response.status_code in [200, 201]:
                token_data = response.json()
                access_token = token_data.get('access_token')
                
                if access_token:
                    # Test token validation
                    headers = {"Authorization": f"Bearer {access_token}"}
                    response = self.session.get(f"{self.base_url}/api/auth/secure-profile", headers=headers)
                    
                    if response.status_code == 200:
                        self.log_test("Secure Token Creation", True, "Token created and validated successfully")
                        return True
                    else:
                        self.log_test("Secure Token Creation", False, f"Token validation failed: {response.status_code}")
                        return False
                else:
                    self.log_test("Secure Token Creation", False, "No access token in response")
                    return False
            else:
                self.log_test("Secure Token Creation", False, f"User creation failed: {response.status_code}")
                return False
                
        except Exception as e:
            self.log_test("Secure Token Creation", False, f"Error: {str(e)}")
            return False
    
    def test_security_headers(self):
        """Test security headers are present"""
        try:
            response = self.session.get(f"{self.base_url}/")
            headers = response.headers
            
            security_headers = [
                'X-Content-Type-Options',
                'X-Frame-Options',
                'X-XSS-Protection',
                'Strict-Transport-Security',
                'Content-Security-Policy'
            ]
            
            found_headers = []
            for header in security_headers:
                if header in headers:
                    found_headers.append(header)
            
            if len(found_headers) >= 3:  # At least 3 security headers
                self.log_test("Security Headers", True, f"Found {len(found_headers)} security headers")
                return True
            else:
                self.log_test("Security Headers", False, f"Only found {len(found_headers)} security headers")
                return False
                
        except Exception as e:
            self.log_test("Security Headers", False, f"Error: {str(e)}")
            return False
    
    def test_input_sanitization(self):
        """Test input sanitization"""
        try:
            malicious_inputs = [
                "<script>alert('xss')</script>",
                "'; DROP TABLE users; --",
                "../../etc/passwd",
                "javascript:alert('xss')"
            ]
            
            for malicious_input in malicious_inputs:
                data = {
                    "email": f"test{malicious_input}@example.com",
                    "password": "SecurePass123!",
                    "fullname": malicious_input
                }
                response = self.session.post(f"{self.base_url}/api/auth/secure-signup", json=data)
                
                # Check if malicious input was sanitized
                if response.status_code == 400:  # Should be rejected
                    self.log_test(f"Input Sanitization ({malicious_input[:20]}...)", True, "Malicious input rejected")
                else:
                    self.log_test(f"Input Sanitization ({malicious_input[:20]}...)", False, f"Status: {response.status_code}")
            
            return True
            
        except Exception as e:
            self.log_test("Input Sanitization", False, f"Error: {str(e)}")
            return False
    
    def test_audit_logging(self):
        """Test audit logging functionality"""
        try:
            # Perform some actions that should be logged
            data = {
                "email": "audit_test@example.com",
                "password": "SecurePass123!",
                "fullname": "Audit Test User"
            }
            response = self.session.post(f"{self.base_url}/api/auth/secure-signup", json=data)
            
            if response.status_code in [200, 201]:
                # Check if we can retrieve security status (which includes audit logs)
                token_data = response.json()
                access_token = token_data.get('access_token')
                
                if access_token:
                    headers = {"Authorization": f"Bearer {access_token}"}
                    response = self.session.get(f"{self.base_url}/api/auth/security-status", headers=headers)
                    
                    if response.status_code == 200:
                        security_data = response.json()
                        if 'recent_security_events' in security_data:
                            self.log_test("Audit Logging", True, "Security events are being logged")
                            return True
                        else:
                            self.log_test("Audit Logging", False, "No security events found")
                            return False
                    else:
                        self.log_test("Audit Logging", False, f"Security status check failed: {response.status_code}")
                        return False
                else:
                    self.log_test("Audit Logging", False, "No access token for audit test")
                    return False
            else:
                self.log_test("Audit Logging", False, f"User creation failed: {response.status_code}")
                return False
                
        except Exception as e:
            self.log_test("Audit Logging", False, f"Error: {str(e)}")
            return False
    
    def run_all_tests(self):
        """Run all security tests"""
        print("🔒 Starting Security Tests...")
        print("=" * 50)
        
        tests = [
            self.test_security_info_endpoint,
            self.test_password_strength_validation,
            self.test_rate_limiting,
            self.test_account_lockout,
            self.test_secure_token_creation,
            self.test_security_headers,
            self.test_input_sanitization,
            self.test_audit_logging
        ]
        
        passed = 0
        total = len(tests)
        
        for test in tests:
            try:
                if test():
                    passed += 1
            except Exception as e:
                print(f"❌ ERROR in {test.__name__}: {str(e)}")
        
        print("=" * 50)
        print(f"📊 Test Results: {passed}/{total} tests passed")
        
        if passed == total:
            print("🎉 All security tests passed! System is secure.")
        else:
            print("⚠️  Some security tests failed. Review the implementation.")
        
        return passed, total
    
    def generate_report(self):
        """Generate a security test report"""
        report = {
            "test_summary": {
                "total_tests": len(self.test_results),
                "passed_tests": sum(1 for r in self.test_results if r['success']),
                "failed_tests": sum(1 for r in self.test_results if not r['success']),
                "timestamp": datetime.now().isoformat()
            },
            "test_details": self.test_results
        }
        
        with open("security_test_report.json", "w") as f:
            json.dump(report, f, indent=2)
        
        print(f"📄 Security test report saved to security_test_report.json")


def main():
    """Main function to run security tests"""
    if len(sys.argv) > 1:
        base_url = sys.argv[1]
    else:
        base_url = "http://localhost:5000"
    
    print(f"Testing security features at: {base_url}")
    
    tester = SecurityTester(base_url)
    passed, total = tester.run_all_tests()
    tester.generate_report()
    
    return passed == total


if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)



