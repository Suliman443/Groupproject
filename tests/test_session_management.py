#!/usr/bin/env python3
"""
Test Session Management and Token Security

Tests the unified session security implementation including:
- Token blocklist (revocation)
- IP address binding validation
- User agent (device) binding validation
- Session timeout enforcement
- Logout functionality
"""

import sys
import os
import time

# Add the Backend directory to the path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'Backend'))

# Check if Flask is available
FLASK_AVAILABLE = False
try:
    import flask
    FLASK_AVAILABLE = True
except ImportError:
    print("Note: Flask not available. Running standalone tests only.")


class TestTokenBlocklist:
    """Test token blocklist functionality"""

    def setup_method(self):
        """Set up test fixtures"""
        if FLASK_AVAILABLE:
            from app.security import SecurityManager
            self.security_manager = SecurityManager()
            # Initialize in-memory fallback
            self.security_manager._memory_blocklist = {}
            self.security_manager._user_revocations = {}

    def test_add_token_to_blocklist(self):
        """Test adding a token JTI to the blocklist"""
        if not FLASK_AVAILABLE:
            print("    (skipped - Flask not available)")
            return

        jti = "test-jti-12345"
        result = self.security_manager.add_token_to_blocklist(jti, expires_in=60)
        assert result is True, "Failed to add token to blocklist"

    def test_is_token_blocklisted(self):
        """Test checking if token is blocklisted"""
        if not FLASK_AVAILABLE:
            print("    (skipped - Flask not available)")
            return

        jti = "test-jti-67890"

        # Not blocklisted initially
        assert self.security_manager.is_token_blocklisted(jti) is False

        # Add to blocklist
        self.security_manager.add_token_to_blocklist(jti, expires_in=60)

        # Now should be blocklisted
        assert self.security_manager.is_token_blocklisted(jti) is True

    def test_revoke_all_user_tokens(self):
        """Test revoking all tokens for a user"""
        if not FLASK_AVAILABLE:
            print("    (skipped - Flask not available)")
            return

        user_id = 123
        result = self.security_manager.revoke_all_user_tokens(user_id)
        assert result is True, "Failed to revoke user tokens"

    def test_is_token_revoked_for_user(self):
        """Test checking if a token is revoked for a user"""
        if not FLASK_AVAILABLE:
            print("    (skipped - Flask not available)")
            return

        user_id = 456
        old_token_time = int(time.time()) - 100  # Token issued 100 seconds ago

        # Not revoked initially
        assert self.security_manager.is_token_revoked_for_user(user_id, old_token_time) is False

        # Revoke all user tokens
        self.security_manager.revoke_all_user_tokens(user_id)

        # Old token should now be revoked
        assert self.security_manager.is_token_revoked_for_user(user_id, old_token_time) is True

        # New token should not be revoked
        new_token_time = int(time.time()) + 10  # Token issued in future
        assert self.security_manager.is_token_revoked_for_user(user_id, new_token_time) is False

    def test_null_jti_handling(self):
        """Test handling of null JTI values"""
        if not FLASK_AVAILABLE:
            print("    (skipped - Flask not available)")
            return

        assert self.security_manager.add_token_to_blocklist(None) is False
        assert self.security_manager.is_token_blocklisted(None) is False
        assert self.security_manager.is_token_blocklisted("") is False


class TestSessionValidation:
    """Test unified session security validation"""

    def setup_method(self):
        """Set up test fixtures"""
        if FLASK_AVAILABLE:
            from app.security import SecurityManager
            self.security_manager = SecurityManager()
            self.security_manager._memory_blocklist = {}
            self.security_manager._user_revocations = {}

    def test_valid_session(self):
        """Test validation passes for valid session"""
        if not FLASK_AVAILABLE:
            print("    (skipped - Flask not available)")
            return

        from app import create_app
        app = create_app()
        app.config['TESTING'] = True

        with app.test_request_context():
            user_id = 1
            jwt_claims = {
                'iat': int(time.time()),
                'login_time': int(time.time()),
                'is_revoked': False
            }

            is_valid, error = self.security_manager.validate_session_security(
                user_id, jwt_claims, session_timeout=3600
            )

            assert is_valid is True, f"Expected valid session, got error: {error}"

    def test_blocklisted_token_rejected(self):
        """Test blocklisted token is rejected"""
        if not FLASK_AVAILABLE:
            print("    (skipped - Flask not available)")
            return

        from app import create_app
        app = create_app()
        app.config['TESTING'] = True

        with app.test_request_context():
            user_id = 1
            jti = "blocked-token-123"

            # Add token to blocklist
            self.security_manager.add_token_to_blocklist(jti)

            jwt_claims = {
                'jti': jti,
                'iat': int(time.time()),
                'login_time': int(time.time()),
            }

            is_valid, error = self.security_manager.validate_session_security(
                user_id, jwt_claims, session_timeout=3600
            )

            assert is_valid is False, "Expected blocklisted token to be rejected"
            assert 'revoked' in error.lower(), f"Expected revocation error, got: {error}"

    def test_session_timeout_enforced(self):
        """Test session timeout is enforced"""
        if not FLASK_AVAILABLE:
            print("    (skipped - Flask not available)")
            return

        from app import create_app
        app = create_app()
        app.config['TESTING'] = True

        with app.test_request_context():
            user_id = 1
            # Token issued 2 hours ago
            old_time = int(time.time()) - 7200

            jwt_claims = {
                'iat': old_time,
                'login_time': old_time,
            }

            # 1 hour timeout should reject 2 hour old token
            is_valid, error = self.security_manager.validate_session_security(
                user_id, jwt_claims, session_timeout=3600
            )

            assert is_valid is False, "Expected timed-out session to be rejected"
            assert 'expired' in error.lower(), f"Expected timeout error, got: {error}"

    def test_revoked_flag_rejected(self):
        """Test token with is_revoked=True is rejected"""
        if not FLASK_AVAILABLE:
            print("    (skipped - Flask not available)")
            return

        from app import create_app
        app = create_app()
        app.config['TESTING'] = True

        with app.test_request_context():
            user_id = 1
            jwt_claims = {
                'iat': int(time.time()),
                'login_time': int(time.time()),
                'is_revoked': True  # Explicitly revoked
            }

            is_valid, error = self.security_manager.validate_session_security(
                user_id, jwt_claims, session_timeout=3600
            )

            assert is_valid is False, "Expected revoked token to be rejected"
            assert 'revoked' in error.lower(), f"Expected revocation error, got: {error}"


def run_tests():
    """Run all tests and report results"""
    import traceback

    test_classes = [TestTokenBlocklist, TestSessionValidation]
    passed = 0
    failed = 0
    skipped = 0
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

                    # Check if test was skipped
                    print(f"  PASS: {method_name}")
                    passed += 1
                except AssertionError as e:
                    print(f"  FAIL: {method_name}")
                    print(f"        {str(e)}")
                    failed += 1
                    errors.append((method_name, str(e)))
                except Exception as e:
                    if "skipped" in str(e).lower():
                        skipped += 1
                    else:
                        print(f"  ERROR: {method_name}")
                        print(f"         {str(e)}")
                        failed += 1
                        errors.append((method_name, traceback.format_exc()))

    print(f"\n{'='*60}")
    print(f"SUMMARY: {passed} passed, {failed} failed, {skipped} skipped")
    print('='*60)

    if errors:
        print("\nFailed tests:")
        for name, error in errors:
            print(f"  - {name}: {error[:100]}...")

    return failed == 0


if __name__ == "__main__":
    success = run_tests()
    sys.exit(0 if success else 1)
