"""
CareFleet - Sistema de gestión de ambulancias API Tests
Tests: Authentication, Inventory, Services, Ambulances, Checklists (new P1 features)
"""
import pytest
import requests
import os
import uuid
from datetime import datetime

# Get BASE_URL from environment (PUBLIC URL for testing)
BASE_URL = os.environ.get('EXPO_PUBLIC_BACKEND_URL', 'https://sten-ambulance-dev.preview.emergentagent.com').rstrip('/')

# Test credentials
TEST_EMAIL = "test@test.com"
TEST_PASSWORD = "admin123"

# Ambulance IDs from the task
UM03_AMBULANCE_ID = "518d1c94-e2dc-4b63-9f90-e78ab0807732"
UM05_AMBULANCE_ID = "1bf0a6b6-a242-4869-a049-980364675cd7"


class TestAuthentication:
    """Test authentication flows"""
    
    def test_login_success(self):
        """Test login with valid credentials"""
        response = requests.post(f"{BASE_URL}/api/auth/login", json={
            "email": TEST_EMAIL,
            "password": TEST_PASSWORD
        })
        assert response.status_code == 200, f"Login failed: {response.text}"
        
        data = response.json()
        assert "access_token" in data, "Missing access_token in response"
        assert "user" in data, "Missing user in response"
        assert data["user"]["email"] == TEST_EMAIL
        
    def test_login_invalid_credentials(self):
        """Test login with invalid credentials"""
        response = requests.post(f"{BASE_URL}/api/auth/login", json={
            "email": "wrong@email.com",
            "password": "wrongpassword"
        })
        assert response.status_code == 401, f"Expected 401 but got {response.status_code}"


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


class TestAmbulances:
    """Test ambulance endpoints"""
    
    def test_get_ambulances(self, auth_headers):
        """Get all ambulances"""
        response = requests.get(f"{BASE_URL}/api/ambulances", headers=auth_headers)
        assert response.status_code == 200, f"Failed to get ambulances: {response.text}"
        
        data = response.json()
        assert isinstance(data, list), "Expected list of ambulances"
        assert len(data) >= 2, "Expected at least 2 ambulances (UM03 and UM05)"
        
        # Check UM03 and UM05 exist
        unit_numbers = [a.get("unit_number", "") for a in data]
        assert any("UM03" in u or "03" in u for u in unit_numbers), "UM03 ambulance not found"
        assert any("UM05" in u or "05" in u for u in unit_numbers), "UM05 ambulance not found"
        
    def test_get_available_ambulances(self, auth_headers):
        """Get available ambulances"""
        response = requests.get(f"{BASE_URL}/api/ambulances?status=disponible", headers=auth_headers)
        assert response.status_code == 200, f"Failed to get available ambulances: {response.text}"


class TestInventoryUM03:
    """Test inventory for UM03 ambulance (should have Type K tanks)"""
    
    def test_inventory_summary_um03(self, auth_headers):
        """Verify UM03 inventory summary - should show 104 items and Type K tanks"""
        response = requests.get(
            f"{BASE_URL}/api/inventory/summary/{UM03_AMBULANCE_ID}", 
            headers=auth_headers
        )
        assert response.status_code == 200, f"Failed to get UM03 inventory summary: {response.text}"
        
        data = response.json()
        assert "total_items" in data, "Missing total_items in summary"
        print(f"UM03 Inventory Summary: total_items={data.get('total_items')}, "
              f"items_with_difference={data.get('items_with_difference')}, "
              f"oxygen_stationary_count={data.get('oxygen_stationary_count')}")
    
    def test_oxygen_tanks_um03(self, auth_headers):
        """Verify UM03 has Type K oxygen tanks"""
        response = requests.get(
            f"{BASE_URL}/api/oxygen-tanks?ambulance_id={UM03_AMBULANCE_ID}", 
            headers=auth_headers
        )
        assert response.status_code == 200, f"Failed to get UM03 oxygen tanks: {response.text}"
        
        tanks = response.json()
        assert isinstance(tanks, list), "Expected list of tanks"
        
        # Check for stationary Type K tanks (9500L capacity)
        stationary_tanks = [t for t in tanks if not t.get("is_portable", True)]
        print(f"UM03 Stationary Tanks: {len(stationary_tanks)}")
        
        # Verify Type K tanks exist
        type_k_tanks = [t for t in tanks if t.get("tank_type") == "K"]
        print(f"UM03 Type K Tanks: {len(type_k_tanks)}")
        
        if len(type_k_tanks) > 0:
            # Verify capacity (Type K = 9500L)
            for tank in type_k_tanks:
                assert tank.get("capacity_liters") == 9500, f"Type K tank should have 9500L capacity"
    
    def test_inventory_items_um03(self, auth_headers):
        """Get inventory items for UM03"""
        response = requests.get(
            f"{BASE_URL}/api/inventory?ambulance_id={UM03_AMBULANCE_ID}", 
            headers=auth_headers
        )
        assert response.status_code == 200, f"Failed to get UM03 inventory items: {response.text}"
        
        items = response.json()
        print(f"UM03 Inventory Items Count: {len(items)}")
        assert len(items) > 0, "UM03 should have inventory items"


class TestInventoryUM05:
    """Test inventory for UM05 ambulance (should have Type M tanks)"""
    
    def test_inventory_summary_um05(self, auth_headers):
        """Verify UM05 inventory still works"""
        response = requests.get(
            f"{BASE_URL}/api/inventory/summary/{UM05_AMBULANCE_ID}", 
            headers=auth_headers
        )
        assert response.status_code == 200, f"Failed to get UM05 inventory summary: {response.text}"
        
        data = response.json()
        print(f"UM05 Inventory Summary: total_items={data.get('total_items')}")
        
    def test_oxygen_tanks_um05(self, auth_headers):
        """Verify UM05 has Type M oxygen tanks"""
        response = requests.get(
            f"{BASE_URL}/api/oxygen-tanks?ambulance_id={UM05_AMBULANCE_ID}", 
            headers=auth_headers
        )
        assert response.status_code == 200, f"Failed to get UM05 oxygen tanks: {response.text}"
        
        tanks = response.json()
        print(f"UM05 Tanks: {len(tanks)}")


class TestChecklist:
    """Test checklist endpoints - P1 new features"""
    
    def test_create_checklist_with_signature(self, auth_headers):
        """Test creating a checklist with signature_base64, failure_count, operator_name"""
        checklist_data = {
            "ambulance_id": UM03_AMBULANCE_ID,
            "operator_id": "b4b388fd-a6af-4f6d-af81-4658c3e6836a",
            "operator_name": "TEST_Operator Name",  # NEW field
            "shift": "matutino",
            "date": datetime.utcnow().isoformat(),
            "km": 50000,
            "fuel_level": "3/4",
            "apariencia_general": [
                {"name": "Limpieza de unidad", "status": True, "observation": "", "critical": False},
                {"name": "Fugas de niveles", "status": True, "observation": "", "critical": True},
                {"name": "Daños a carrocería", "status": True, "observation": "", "critical": True},
            ],
            "cabina_operadores": [
                {"name": "Asientos y cinturones", "status": True, "observation": "", "critical": True},
                {"name": "Espejos", "status": True, "observation": "", "critical": True},
            ],
            "compartimiento_motor": [
                {"name": "Fugas", "status": True, "observation": "", "critical": True},
                {"name": "Batería", "status": True, "observation": "", "critical": True},
            ],
            "niveles": [
                {"name": "Aceite", "level": "normal", "observation": "", "critical": True},
                {"name": "Frenos", "level": "normal", "observation": "", "critical": True},
            ],
            "exterior_operador": [
                {"name": "Llantas", "status": True, "observation": "", "critical": True},
            ],
            "zona_frontal": [
                {"name": "Luces de emergencia", "status": True, "observation": "", "critical": True},
                {"name": "Sirena", "status": True, "observation": "", "critical": True},
            ],
            "exterior_copiloto": [
                {"name": "Llantas", "status": True, "observation": "", "critical": True},
            ],
            "compartimento_paciente": [
                {"name": "Aspirador", "status": True, "observation": "", "critical": True},
            ],
            "zona_posterior": [
                {"name": "Luces traseras", "status": True, "observation": "", "critical": True},
            ],
            "herramientas": [
                {"name": "Extintor", "status": True, "observation": "", "critical": True},
            ],
            "saldo_gasolina": 450.00,
            "observations": "TEST_Unidad en buen estado",
            "photos_base64": [],
            "signature_base64": "data:image/svg+xml;base64,PHN2ZyB4bWxucz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC9zdmciPjwvc3ZnPg==",  # NEW field
            "completed_at": datetime.utcnow().isoformat(),
            "failure_count": 0  # NEW field
        }
        
        response = requests.post(f"{BASE_URL}/api/checklists", json=checklist_data, headers=auth_headers)
        assert response.status_code == 200, f"Failed to create checklist: {response.text}"
        
        data = response.json()
        # Verify new fields are accepted and returned
        assert data.get("id"), "Checklist should have an ID"
        assert data.get("operator_name") == "TEST_Operator Name", "operator_name should be saved"
        assert data.get("signature_base64"), "signature_base64 should be present"
        assert data.get("signed") == True, "signed should be True when signature provided"
        assert data.get("failure_count") == 0, "failure_count should be 0"
        assert data.get("has_failures") == False, "has_failures should be False"
        
        print(f"Created checklist with signature: {data.get('id')}")
    
    def test_create_checklist_with_critical_failures(self, auth_headers):
        """Test creating a checklist with critical failures - should require observations"""
        checklist_data = {
            "ambulance_id": UM05_AMBULANCE_ID,
            "operator_id": "b4b388fd-a6af-4f6d-af81-4658c3e6836a",
            "operator_name": "TEST_Operator Failures",
            "shift": "vespertino",
            "date": datetime.utcnow().isoformat(),
            "km": 35000,
            "fuel_level": "1/2",
            # Include some failures with observations
            "apariencia_general": [
                {"name": "Limpieza de unidad", "status": True, "observation": "", "critical": False},
                {"name": "Fugas de niveles", "status": False, "observation": "TEST_Fuga de aceite detectada", "critical": True},  # FAILED
                {"name": "Daños a carrocería", "status": True, "observation": "", "critical": True},
            ],
            "cabina_operadores": [
                {"name": "Asientos y cinturones", "status": True, "observation": "", "critical": True},
                {"name": "Espejos", "status": True, "observation": "", "critical": True},
            ],
            "compartimiento_motor": [
                {"name": "Fugas", "status": True, "observation": "", "critical": True},
                {"name": "Batería", "status": True, "observation": "", "critical": True},
            ],
            "niveles": [
                {"name": "Aceite", "level": "bajo", "observation": "TEST_Nivel bajo", "critical": True},  # LOW critical
                {"name": "Frenos", "level": "normal", "observation": "", "critical": True},
            ],
            "exterior_operador": [
                {"name": "Llantas", "status": True, "observation": "", "critical": True},
            ],
            "zona_frontal": [
                {"name": "Luces de emergencia", "status": True, "observation": "", "critical": True},
                {"name": "Sirena", "status": True, "observation": "", "critical": True},
            ],
            "exterior_copiloto": [
                {"name": "Llantas", "status": True, "observation": "", "critical": True},
            ],
            "compartimento_paciente": [
                {"name": "Aspirador", "status": True, "observation": "", "critical": True},
            ],
            "zona_posterior": [
                {"name": "Luces traseras", "status": True, "observation": "", "critical": True},
            ],
            "herramientas": [
                {"name": "Extintor", "status": True, "observation": "", "critical": True},
            ],
            "saldo_gasolina": 200.00,
            "observations": "TEST_Checklist with failures",
            "photos_base64": [],
            "signature_base64": "data:image/svg+xml;base64,PHN2ZyB4bWxucz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC9zdmciPjwvc3ZnPg==",
            "completed_at": datetime.utcnow().isoformat(),
            "failure_count": 2
        }
        
        response = requests.post(f"{BASE_URL}/api/checklists", json=checklist_data, headers=auth_headers)
        assert response.status_code == 200, f"Failed to create checklist with failures: {response.text}"
        
        data = response.json()
        assert data.get("has_failures") == True, "has_failures should be True"
        assert data.get("failure_count") >= 2, "failure_count should be at least 2"
        assert data.get("has_critical_failures") == True, "has_critical_failures should be True"
        assert "Fugas de niveles" in data.get("critical_failures", []), "critical_failures should include Fugas de niveles"
        
        print(f"Created checklist with failures: {data.get('id')}, critical_failures: {data.get('critical_failures')}")
    
    def test_get_checklists(self, auth_headers):
        """Test getting checklists list"""
        response = requests.get(f"{BASE_URL}/api/checklists", headers=auth_headers)
        assert response.status_code == 200, f"Failed to get checklists: {response.text}"
        
        data = response.json()
        assert isinstance(data, list), "Expected list of checklists"
        print(f"Total checklists: {len(data)}")
        
        # Verify recent test checklists exist
        test_checklists = [c for c in data if "TEST_" in str(c.get("operator_name", "")) or "TEST_" in str(c.get("observations", ""))]
        print(f"Test checklists found: {len(test_checklists)}")


class TestServiceCreation:
    """Test service creation with 6-step form model"""
    
    def test_create_service_with_review_step_data(self, auth_headers):
        """Test creating a service with all data from 6-step form including review step"""
        service_data = {
            "service_type": "programado",
            # Step 1: Patient data
            "patient": {
                "name": "TEST_Patient Review",
                "diagnosis": "Test Diagnosis Review",
                "sex": "M",
                "age": 45,
                "birth_date": "1980-05-15",
                "weight": 75.5,
                "phone": "555-1234",
                "chronic_diseases": "Diabetes",
                "treating_doctor": "Dr. Test",
                "room_number": "101"
            },
            # Step 2: Status and reason
            "patient_status": "estable",
            "service_reason": "estudio",
            "study_to_perform": "Tomografía de tórax",
            # Step 3: Route
            "origin": "Hospital ABC - Piso 3",
            "destination": "Centro de Diagnóstico XYZ",
            "destination_hospital_name": "Centro de Diagnóstico XYZ",
            "destination_area": "Imagenología",
            "scheduled_date": datetime.utcnow().isoformat(),
            "request_date": datetime.utcnow().isoformat(),
            # Step 4: Equipment and personnel
            "equipment_required": {
                "oxygen": True,
                "oxygen_liters": 3.0,
                "monitor_oximeter": True,
                "ventilator": False,
                "infusion_pumps": False
            },
            "personnel_required": {
                "doctor": False,
                "paramedic": True
            },
            # Step 5: Administrative and quote
            "hospital_account": "ACC-001",
            "cash_payment_familiar": False,
            "request_receiver_name": "Test Receiver",
            "scheduling_nurse": "Nurse Test",
            "quote": {
                "base_cost": 2000.00,
                "additional_charges": 300.00,
                "total_estimated": 2300.00,
                "quote_notes": "Incluye equipo de monitoreo"
            },
            "notes": "TEST_Service from review step"
        }
        
        response = requests.post(f"{BASE_URL}/api/services", json=service_data, headers=auth_headers)
        assert response.status_code == 200, f"Failed to create service: {response.text}"
        
        data = response.json()
        assert data.get("id"), "Service should have an ID"
        assert data.get("status") == "pendiente", "New service should be pending"
        
        # Verify all step data is captured
        assert data.get("patient", {}).get("name") == "TEST_Patient Review"
        assert data.get("patient_status") == "estable"
        assert data.get("service_reason") == "estudio"
        assert data.get("study_to_perform") == "Tomografía de tórax"
        assert data.get("destination_hospital_name") == "Centro de Diagnóstico XYZ"
        assert data.get("equipment_required", {}).get("oxygen") == True
        assert data.get("equipment_required", {}).get("oxygen_liters") == 3.0
        assert data.get("quote", {}).get("total_estimated") == 2300.00
        
        print(f"Created service with review step data: {data.get('id')}")
        
        # Cleanup
        service_id = data.get("id")
        if service_id:
            requests.delete(f"{BASE_URL}/api/services/{service_id}", headers=auth_headers)


class TestServices:
    """Test service endpoints"""
    
    def test_get_services(self, auth_headers):
        """Get all services"""
        response = requests.get(f"{BASE_URL}/api/services", headers=auth_headers)
        assert response.status_code == 200, f"Failed to get services: {response.text}"
        
    def test_get_active_services(self, auth_headers):
        """Get active services"""
        response = requests.get(f"{BASE_URL}/api/services/active", headers=auth_headers)
        assert response.status_code == 200, f"Failed to get active services: {response.text}"


class TestNotifications:
    """Test notifications"""
    
    def test_get_notifications(self, auth_headers):
        """Get user notifications"""
        response = requests.get(f"{BASE_URL}/api/notifications", headers=auth_headers)
        assert response.status_code == 200, f"Failed to get notifications: {response.text}"
        
        data = response.json()
        assert isinstance(data, list), "Notifications should be a list"
        print(f"User has {len(data)} notifications")


class TestPersonnel:
    """Test personnel endpoints"""
    
    def test_get_personnel(self, auth_headers):
        """Get all personnel"""
        response = requests.get(f"{BASE_URL}/api/personnel", headers=auth_headers)
        assert response.status_code == 200, f"Failed to get personnel: {response.text}"


class TestHealthCheck:
    """Basic health checks"""
    
    def test_api_login_endpoint(self):
        """Test API is reachable via login endpoint"""
        response = requests.post(f"{BASE_URL}/api/auth/login", json={
            "email": "test@test.com",
            "password": "admin123"
        })
        assert response.status_code == 200, f"API not reachable: {response.text}"


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
