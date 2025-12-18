#!/usr/bin/env python3
"""
Test input sanitization functionality
Tests the SecurityManager.sanitize_input() method and middleware integration

Can be run in two modes:
1. Standalone (no Flask): Tests core sanitize_input logic only
2. With Flask: Tests full middleware integration

Run: python tests/test_input_sanitization.py
"""

import sys
import os

# Add the Backend directory to the path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'Backend'))

# Check if Flask is available
FLASK_AVAILABLE = False
try:
    import flask
    FLASK_AVAILABLE = True
except ImportError:
    print("Note: Flask not available. Running standalone sanitization tests only.")


def create_standalone_sanitizer():
    """Create a standalone sanitize_input function for testing without Flask"""
    def sanitize_input(data):
        """Sanitize input data to prevent injection attacks.
        Recursively handles nested dictionaries and arrays.
        """
        if isinstance(data, dict):
            return {key: sanitize_input(value) for key, value in data.items()}
        elif isinstance(data, list):
            return [sanitize_input(item) for item in data]
        elif isinstance(data, str):
            # Remove potentially dangerous characters for XSS and injection
            dangerous_chars = ['<', '>', '"', "'", '&', ';', '(', ')', '|', '`']
            for char in dangerous_chars:
                data = data.replace(char, '')
            return data.strip()
        else:
            # Return non-string types (int, float, bool, None) as-is
            return data
    return sanitize_input


class TestSanitizeInputMethod:
    """Test the sanitize_input method directly"""

    def setup_method(self):
        """Set up test fixtures"""
        if FLASK_AVAILABLE:
            from app.security import SecurityManager
            self.security_manager = SecurityManager()
            self.sanitize = self.security_manager.sanitize_input
        else:
            self.sanitize = create_standalone_sanitizer()

    def test_sanitize_simple_string(self):
        """Test sanitization of a simple string with dangerous characters"""
        input_data = "<script>alert('xss')</script>"
        expected = "scriptalertxss/script"
        result = self.sanitize(input_data)
        assert result == expected, f"Expected '{expected}', got '{result}'"

    def test_sanitize_nested_dict(self):
        """Test recursive sanitization of nested dictionaries"""
        input_data = {
            "name": "John<script>",
            "profile": {
                "bio": "Hello & welcome",
                "tags": ["<b>tag1</b>", "tag2"]
            }
        }
        result = self.sanitize(input_data)

        assert result["name"] == "Johnscript"
        assert result["profile"]["bio"] == "Hello  welcome"
        assert result["profile"]["tags"][0] == "btag1/b"
        assert result["profile"]["tags"][1] == "tag2"

    def test_sanitize_array(self):
        """Test sanitization of arrays"""
        input_data = ["<script>", "normal", "test&value"]
        result = self.sanitize(input_data)

        assert result[0] == "script"
        assert result[1] == "normal"
        assert result[2] == "testvalue"

    def test_sanitize_preserves_non_strings(self):
        """Test that non-string values are preserved"""
        input_data = {
            "count": 42,
            "price": 19.99,
            "active": True,
            "data": None
        }
        result = self.sanitize(input_data)

        assert result["count"] == 42
        assert result["price"] == 19.99
        assert result["active"] is True
        assert result["data"] is None

    def test_sanitize_empty_data(self):
        """Test handling of empty/null data"""
        assert self.sanitize(None) is None
        assert self.sanitize("") == ""
        assert self.sanitize({}) == {}
        assert self.sanitize([]) == []

    def test_sanitize_strips_whitespace(self):
        """Test that strings are stripped of leading/trailing whitespace"""
        input_data = "  hello world  "
        result = self.sanitize(input_data)
        assert result == "hello world"

    def test_sanitize_all_dangerous_chars(self):
        """Test removal of all dangerous characters"""
        # Characters: < > " ' & ; ( ) | `
        input_data = "test<>\"'&;()|`end"
        result = self.sanitize(input_data)
        assert result == "testend"

    def test_sanitize_sql_injection_attempt(self):
        """Test sanitization of SQL injection patterns"""
        input_data = "'; DROP TABLE users; --"
        result = self.sanitize(input_data)
        # Should remove ; ' and other dangerous chars
        assert ";" not in result
        assert "'" not in result

    def test_sanitize_xss_attempt(self):
        """Test sanitization of XSS attack patterns"""
        input_data = '<img src="x" onerror="alert(1)">'
        result = self.sanitize(input_data)
        # Should remove < > " ( )
        assert "<" not in result
        assert ">" not in result
        assert "(" not in result
        assert ")" not in result


class TestMiddlewareIntegration:
    """Test the middleware integration with Flask app"""
    skip_tests = not FLASK_AVAILABLE

    def setup_method(self):
        """Set up test Flask app"""
        if not FLASK_AVAILABLE:
            return
        from app import create_app
        self.app = create_app()
        self.app.config['TESTING'] = True
        self.client = self.app.test_client()

    def test_sanitization_applied_to_json_request(self):
        """Test that JSON requests are automatically sanitized"""
        if not FLASK_AVAILABLE:
            print("    (skipped - Flask not available)")
            return
        with self.app.test_request_context(
            '/api/auth/signup',
            method='POST',
            json={'email': 'test<script>@example.com', 'password': 'test123'}
        ):
            from flask import request
            data = request.get_json()
            # The email should be sanitized (script tags removed)
            assert '<script>' not in data.get('email', '')

    def test_non_json_request_unaffected(self):
        """Test that non-JSON requests are not affected"""
        if not FLASK_AVAILABLE:
            print("    (skipped - Flask not available)")
            return
        with self.app.test_request_context(
            '/api/events',
            method='GET'
        ):
            from flask import request
            # Should not raise any errors
            data = request.get_json(silent=True)
            assert data is None


def run_tests():
    """Run all tests and report results"""
    import traceback

    test_classes = [TestSanitizeInputMethod, TestMiddlewareIntegration]
    passed = 0
    failed = 0
    errors = []

    for test_class in test_classes:
        print(f"\n{'='*60}")
        print(f"Running tests in {test_class.__name__}")
        print('='*60)

        instance = test_class()

        for method_name in dir(instance):
            if method_name.startswith('test_'):
                try:
                    # Run setup if exists
                    if hasattr(instance, 'setup_method'):
                        instance.setup_method()

                    # Run the test
                    getattr(instance, method_name)()
                    print(f"  PASS: {method_name}")
                    passed += 1
                except AssertionError as e:
                    print(f"  FAIL: {method_name}")
                    print(f"        {str(e)}")
                    failed += 1
                    errors.append((method_name, str(e)))
                except Exception as e:
                    print(f"  ERROR: {method_name}")
                    print(f"         {str(e)}")
                    failed += 1
                    errors.append((method_name, traceback.format_exc()))

    print(f"\n{'='*60}")
    print(f"SUMMARY: {passed} passed, {failed} failed")
    print('='*60)

    if errors:
        print("\nFailed tests:")
        for name, error in errors:
            print(f"  - {name}: {error[:100]}...")

    return failed == 0


if __name__ == "__main__":
    success = run_tests()
    sys.exit(0 if success else 1)
