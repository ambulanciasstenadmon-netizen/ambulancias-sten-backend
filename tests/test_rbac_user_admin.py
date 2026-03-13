"""
CareFleet - RBAC, User Administration, 2FA, Sessions, and Security Tests
Tests for: Authentication, Admin User CRUD, 2FA setup, Sessions, Password strength, Finance access control
"""
import pytest
import requests
import os
import uuid
from datetime import datetime

# Get BASE_URL from environment (PUBLIC URL for testing)
BASE_URL = os.environ.get('EXPO_PUBLIC_BACKEND_URL', 'https://sten-ambulance-dev.preview.emergentagent.com').rstrip('/')

# Test credentials (coordinador role - has admin access)
TEST_EMAIL = "test@test.com"
TEST_PASSWORD = "admin123"


class TestAuthentication:
    """Test authentication with coordinador credentials"""
    
    def test_login_success(self):
        """Test login with test@test.com / admin123"""
        response = requests.post(f"{BASE_URL}/api/auth/login", json={
            "email": TEST_EMAIL,
            "password": TEST_PASSWORD
        })
        assert response.status_code == 200, f"Login failed: {response.text}"
        
        data = response.json()
        assert "access_token" in data, "Missing access_token in response"
        assert "user" in data, "Missing user in response"
        assert data["user"]["email"] == TEST_EMAIL
        # Verify role is coordinador
        assert data["user"]["role"] == "coordinador", f"Expected coordinador role, got {data['user']['role']}"
        print(f"Login successful: user role = {data['user']['role']}")
        
    def test_login_returns_2fa_flags(self):
        """Test login response includes 2FA and password flags"""
        response = requests.post(f"{BASE_URL}/api/auth/login", json={
            "email": TEST_EMAIL,
            "password": TEST_PASSWORD
        })
        assert response.status_code == 200
        
        data = response.json()
        # Check 2FA and password flags are present
        assert "requires_2fa" in data, "Missing requires_2fa flag"
        assert "requires_password_change" in data, "Missing requires_password_change flag"
        assert "password_expiring_soon" in data, "Missing password_expiring_soon flag"
        print(f"2FA required: {data.get('requires_2fa')}, Password change: {data.get('requires_password_change')}")


@pytest.fixture(scope="module")
def auth_token():
    """Get authentication token for tests"""
    response = requests.post(f"{BASE_URL}/api/auth/login", json={
        "email": TEST_EMAIL,
        "password": TEST_PASSWORD
    })
    if response.status_code != 200:
        pytest.skip(f"Authentication failed - skipping authenticated tests: {response.text}")
    return response.json()["access_token"]


@pytest.fixture
def auth_headers(auth_token):
    """Return headers with authentication token"""
    return {"Authorization": f"Bearer {auth_token}"}


class TestAdminUsersEndpoints:
    """Test /api/admin/users endpoints for coordinador role"""
    
    def test_get_all_users(self, auth_headers):
        """GET /api/admin/users - should return list of users for coordinador role"""
        response = requests.get(f"{BASE_URL}/api/admin/users", headers=auth_headers)
        assert response.status_code == 200, f"Failed to get users: {response.text}"
        
        data = response.json()
        assert isinstance(data, list), "Expected list of users"
        assert len(data) >= 1, "Should have at least 1 user"
        
        # Verify user structure
        if len(data) > 0:
            user = data[0]
            assert "id" in user, "User should have id"
            assert "email" in user, "User should have email"
            assert "role" in user, "User should have role"
            assert "is_active" in user, "User should have is_active"
            assert "active_sessions_count" in user, "User should have active_sessions_count"
            print(f"Total users: {len(data)}")
    
    def test_get_users_with_search_filter(self, auth_headers):
        """GET /api/admin/users?search=test - should filter users"""
        response = requests.get(
            f"{BASE_URL}/api/admin/users?search=test", 
            headers=auth_headers
        )
        assert response.status_code == 200, f"Search filter failed: {response.text}"
        
        data = response.json()
        assert isinstance(data, list), "Expected list of users"
        print(f"Users matching 'test': {len(data)}")
    
    def test_get_users_with_role_filter(self, auth_headers):
        """GET /api/admin/users?role=coordinador - should filter by role"""
        response = requests.get(
            f"{BASE_URL}/api/admin/users?role=coordinador", 
            headers=auth_headers
        )
        assert response.status_code == 200, f"Role filter failed: {response.text}"
        
        data = response.json()
        for user in data:
            assert user["role"] == "coordinador", f"Expected coordinador role, got {user['role']}"
        print(f"Coordinadores: {len(data)}")
    
    def test_get_user_detail(self, auth_headers):
        """GET /api/admin/users/{id} - should return user detail with sessions and history"""
        # First get list of users
        response = requests.get(f"{BASE_URL}/api/admin/users", headers=auth_headers)
        assert response.status_code == 200
        users = response.json()
        
        if len(users) > 0:
            user_id = users[0]["id"]
            detail_response = requests.get(
                f"{BASE_URL}/api/admin/users/{user_id}", 
                headers=auth_headers
            )
            assert detail_response.status_code == 200, f"Failed to get user detail: {detail_response.text}"
            
            data = detail_response.json()
            # Verify detail structure
            assert "user" in data, "Should have user object"
            assert "active_sessions" in data, "Should have active_sessions"
            assert "login_history" in data, "Should have login_history"
            assert "audit_history" in data, "Should have audit_history"
            
            user = data["user"]
            assert "id" in user
            assert "email" in user
            assert "two_fa_enabled" in user
            assert "failed_login_attempts" in user
            print(f"User detail loaded: {user['email']}, 2FA: {user['two_fa_enabled']}, Sessions: {len(data['active_sessions'])}")
    
    def test_create_user(self, auth_headers):
        """POST /api/admin/users - create new user"""
        unique_id = str(uuid.uuid4())[:8]
        test_email = f"TEST_user_{unique_id}@test.com"
        
        response = requests.post(
            f"{BASE_URL}/api/admin/users",
            json={
                "email": test_email,
                "full_name": f"TEST_User {unique_id}",
                "role": "operador",
                "password": "TestPass123!",  # Valid strong password
                "phone": "5551234567",
                "is_active": True
            },
            headers=auth_headers
        )
        assert response.status_code == 200, f"Failed to create user: {response.text}"
        
        data = response.json()
        assert "user_id" in data, "Should return user_id"
        assert "message" in data, "Should return message"
        print(f"Created user: {test_email}, ID: {data.get('user_id')}")
        
        # Return user_id for cleanup
        return data.get("user_id")
    
    def test_create_user_weak_password_rejected(self, auth_headers):
        """POST /api/admin/users - weak password should be rejected"""
        unique_id = str(uuid.uuid4())[:8]
        
        # Try weak password
        response = requests.post(
            f"{BASE_URL}/api/admin/users",
            json={
                "email": f"TEST_weak_{unique_id}@test.com",
                "full_name": f"TEST_Weak {unique_id}",
                "role": "operador",
                "password": "weak",  # Too weak
                "is_active": True
            },
            headers=auth_headers
        )
        assert response.status_code == 400, f"Weak password should be rejected, got {response.status_code}"
        print(f"Weak password rejected: {response.json().get('detail')}")
    
    def test_update_user(self, auth_headers):
        """PUT /api/admin/users/{id} - update user"""
        # First create a test user
        unique_id = str(uuid.uuid4())[:8]
        test_email = f"TEST_update_{unique_id}@test.com"
        
        create_response = requests.post(
            f"{BASE_URL}/api/admin/users",
            json={
                "email": test_email,
                "full_name": f"TEST_Update {unique_id}",
                "role": "operador",
                "password": "TestPass123!",
                "is_active": True
            },
            headers=auth_headers
        )
        assert create_response.status_code == 200
        user_id = create_response.json().get("user_id")
        
        # Update the user
        update_response = requests.put(
            f"{BASE_URL}/api/admin/users/{user_id}",
            json={
                "full_name": "TEST_Updated Name",
                "phone": "5559999999"
            },
            headers=auth_headers
        )
        assert update_response.status_code == 200, f"Failed to update user: {update_response.text}"
        print(f"User {user_id} updated successfully")
    
    def test_reset_password(self, auth_headers):
        """POST /api/admin/users/{id}/reset-password - reset password"""
        # First create a test user
        unique_id = str(uuid.uuid4())[:8]
        test_email = f"TEST_reset_{unique_id}@test.com"
        
        create_response = requests.post(
            f"{BASE_URL}/api/admin/users",
            json={
                "email": test_email,
                "full_name": f"TEST_Reset {unique_id}",
                "role": "operador",
                "password": "TestPass123!",
                "is_active": True
            },
            headers=auth_headers
        )
        assert create_response.status_code == 200
        user_id = create_response.json().get("user_id")
        
        # Reset password
        reset_response = requests.post(
            f"{BASE_URL}/api/admin/users/{user_id}/reset-password",
            json={"new_password": "NewTestPass456!"},
            headers=auth_headers
        )
        assert reset_response.status_code == 200, f"Failed to reset password: {reset_response.text}"
        print(f"Password reset for user {user_id}")
    
    def test_reset_password_weak_rejected(self, auth_headers):
        """POST /api/admin/users/{id}/reset-password - weak password rejected"""
        # First get a user to test
        response = requests.get(f"{BASE_URL}/api/admin/users", headers=auth_headers)
        users = response.json()
        
        # Find test user
        test_users = [u for u in users if "TEST_" in u.get("full_name", "")]
        if len(test_users) > 0:
            user_id = test_users[0]["id"]
            
            # Try weak password reset
            reset_response = requests.post(
                f"{BASE_URL}/api/admin/users/{user_id}/reset-password",
                json={"new_password": "weak"},
                headers=auth_headers
            )
            assert reset_response.status_code == 400, f"Weak password should be rejected"
            print(f"Weak password rejected in reset: {reset_response.json().get('detail')}")


class TestTwoFactorAuth:
    """Test 2FA setup endpoints"""
    
    def test_2fa_setup_returns_qr(self, auth_headers):
        """POST /api/auth/2fa/setup - should generate QR code and secret"""
        response = requests.post(
            f"{BASE_URL}/api/auth/2fa/setup",
            headers=auth_headers
        )
        assert response.status_code == 200, f"Failed to setup 2FA: {response.text}"
        
        data = response.json()
        assert "secret" in data, "Should return TOTP secret"
        assert "qr_code" in data, "Should return QR code"
        assert "uri" in data, "Should return provisioning URI"
        
        # Verify QR code is base64 PNG
        assert data["qr_code"].startswith("data:image/png;base64,"), "QR code should be base64 PNG"
        # Verify secret is valid base32
        assert len(data["secret"]) >= 16, "Secret should be at least 16 chars"
        print(f"2FA setup successful, secret length: {len(data['secret'])}")


class TestSessionManagement:
    """Test session management endpoints"""
    
    def test_get_active_sessions(self, auth_headers):
        """GET /api/auth/sessions - should return active sessions"""
        response = requests.get(
            f"{BASE_URL}/api/auth/sessions",
            headers=auth_headers
        )
        assert response.status_code == 200, f"Failed to get sessions: {response.text}"
        
        data = response.json()
        assert isinstance(data, list), "Expected list of sessions"
        
        if len(data) > 0:
            session = data[0]
            assert "id" in session, "Session should have id"
            assert "created_at" in session, "Session should have created_at"
            print(f"Active sessions: {len(data)}, first session IP: {session.get('ip_address')}")
    
    def test_close_specific_session(self, auth_headers):
        """DELETE /api/auth/sessions/{id} - should close specific session"""
        # Get sessions first
        get_response = requests.get(
            f"{BASE_URL}/api/auth/sessions",
            headers=auth_headers
        )
        sessions = get_response.json()
        
        # We won't close current session, but verify the endpoint works
        if len(sessions) > 1:
            # Close the first non-current session
            session_id = sessions[1]["id"]
            close_response = requests.delete(
                f"{BASE_URL}/api/auth/sessions/{session_id}",
                headers=auth_headers
            )
            # Could be 200 or 404 if session already closed
            assert close_response.status_code in [200, 404], f"Unexpected status: {close_response.text}"
            print(f"Session close attempt: {close_response.status_code}")


class TestFinanceAccessControl:
    """Test finance access control - paramédico should get 403"""
    
    def test_coordinador_can_access_finances(self, auth_headers):
        """GET /api/finances - coordinador should have access"""
        response = requests.get(
            f"{BASE_URL}/api/finances",
            headers=auth_headers
        )
        assert response.status_code == 200, f"Coordinador should access finances: {response.text}"
        print("Coordinador can access finances: PASS")
    
    def test_paramedico_cannot_access_finances(self, auth_headers):
        """Create paramedico and verify 403 on /api/finances"""
        unique_id = str(uuid.uuid4())[:8]
        paramedico_email = f"TEST_paramedico_{unique_id}@test.com"
        
        # Create paramedico user
        create_response = requests.post(
            f"{BASE_URL}/api/admin/users",
            json={
                "email": paramedico_email,
                "full_name": f"TEST_Paramedico {unique_id}",
                "role": "paramedico",
                "password": "ParaPass123!",
                "is_active": True
            },
            headers=auth_headers
        )
        assert create_response.status_code == 200, f"Failed to create paramedico: {create_response.text}"
        print(f"Created paramedico: {paramedico_email}")
        
        # Login as paramedico
        login_response = requests.post(
            f"{BASE_URL}/api/auth/login",
            json={
                "email": paramedico_email,
                "password": "ParaPass123!"
            }
        )
        assert login_response.status_code == 200, f"Paramedico login failed: {login_response.text}"
        
        paramedico_token = login_response.json()["access_token"]
        paramedico_headers = {"Authorization": f"Bearer {paramedico_token}"}
        
        # Try to access finances - should get 403
        finance_response = requests.get(
            f"{BASE_URL}/api/finances",
            headers=paramedico_headers
        )
        assert finance_response.status_code == 403, f"Paramedico should get 403, got {finance_response.status_code}"
        print(f"Paramedico finance access denied: {finance_response.json().get('detail')}")


class TestNotificationsAlerts:
    """Test notification check alerts endpoint"""
    
    def test_check_alerts(self, auth_headers):
        """POST /api/notifications/check-alerts - should work"""
        response = requests.post(
            f"{BASE_URL}/api/notifications/check-alerts",
            headers=auth_headers
        )
        assert response.status_code == 200, f"Failed to check alerts: {response.text}"
        
        data = response.json()
        assert "low_stock_alerts" in data, "Should have low_stock_alerts"
        assert "oxygen_alerts" in data, "Should have oxygen_alerts"
        assert "checked_at" in data, "Should have checked_at"
        print(f"Alerts check: stock={data.get('low_stock_alerts')}, oxygen={data.get('oxygen_alerts')}")


class TestPasswordStrengthValidation:
    """Test password strength validation"""
    
    def test_password_min_length(self, auth_headers):
        """Password must be at least 8 characters"""
        unique_id = str(uuid.uuid4())[:8]
        
        response = requests.post(
            f"{BASE_URL}/api/admin/users",
            json={
                "email": f"TEST_short_{unique_id}@test.com",
                "full_name": "TEST_Short Password",
                "role": "operador",
                "password": "Ab1!",  # Too short
                "is_active": True
            },
            headers=auth_headers
        )
        assert response.status_code == 400
        assert "8 caracteres" in response.json().get("detail", "")
        print("Short password rejected: PASS")
    
    def test_password_needs_uppercase(self, auth_headers):
        """Password must have uppercase"""
        unique_id = str(uuid.uuid4())[:8]
        
        response = requests.post(
            f"{BASE_URL}/api/admin/users",
            json={
                "email": f"TEST_nocase_{unique_id}@test.com",
                "full_name": "TEST_No Uppercase",
                "role": "operador",
                "password": "testpass123!",  # No uppercase
                "is_active": True
            },
            headers=auth_headers
        )
        assert response.status_code == 400
        assert "mayúscula" in response.json().get("detail", "")
        print("No uppercase rejected: PASS")
    
    def test_password_needs_number(self, auth_headers):
        """Password must have number"""
        unique_id = str(uuid.uuid4())[:8]
        
        response = requests.post(
            f"{BASE_URL}/api/admin/users",
            json={
                "email": f"TEST_nonum_{unique_id}@test.com",
                "full_name": "TEST_No Number",
                "role": "operador",
                "password": "TestPass!!",  # No number
                "is_active": True
            },
            headers=auth_headers
        )
        assert response.status_code == 400
        assert "número" in response.json().get("detail", "")
        print("No number rejected: PASS")
    
    def test_password_needs_special_char(self, auth_headers):
        """Password must have special character"""
        unique_id = str(uuid.uuid4())[:8]
        
        response = requests.post(
            f"{BASE_URL}/api/admin/users",
            json={
                "email": f"TEST_nospec_{unique_id}@test.com",
                "full_name": "TEST_No Special",
                "role": "operador",
                "password": "TestPass123",  # No special char
                "is_active": True
            },
            headers=auth_headers
        )
        assert response.status_code == 400
        assert "especial" in response.json().get("detail", "")
        print("No special char rejected: PASS")


class TestCleanup:
    """Cleanup test data"""
    
    def test_cleanup_test_users(self, auth_headers):
        """Remove TEST_ prefixed users"""
        response = requests.get(f"{BASE_URL}/api/admin/users", headers=auth_headers)
        if response.status_code != 200:
            return
        
        users = response.json()
        test_users = [u for u in users if "TEST_" in u.get("full_name", "") or "TEST_" in u.get("email", "")]
        
        print(f"Found {len(test_users)} test users to cleanup")
        
        for user in test_users:
            # Deactivate test users
            requests.put(
                f"{BASE_URL}/api/admin/users/{user['id']}",
                json={"is_active": False},
                headers=auth_headers
            )
        
        print(f"Cleaned up {len(test_users)} test users")


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
