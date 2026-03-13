# Authentication and Authorization Module
# Sistema completo de RBAC, sesiones, 2FA y control de usuarios

import pyotp
import qrcode
import io
import base64
import hashlib
from datetime import datetime, timedelta
from typing import Optional, List, Dict, Any, Set
from pydantic import BaseModel, EmailStr
from enum import Enum
from functools import wraps
from fastapi import HTTPException, Request

# ====== CONFIGURACIÓN DEL SISTEMA ======

class SystemConfig:
    """Configuración global del sistema - valores por defecto"""
    MAX_ACTIVE_USERS = 20  # Límite configurable
    PASSWORD_EXPIRY_DAYS = 90
    PASSWORD_EXPIRY_WARNING_DAYS = 7
    PASSWORD_HISTORY_COUNT = 3
    MAX_FAILED_LOGIN_ATTEMPTS = 5
    LOCKOUT_DURATION_MINUTES = 30
    SESSION_TIMEOUT_HOURS = 24
    MAX_SESSIONS_PER_USER = 5
    TWO_FA_APP_NAME = "CareFleet-STEN"
    TWO_FA_ISSUER = "Ambulancias STEN"


# ====== ROLES Y PERMISOS ======

class UserRole(str, Enum):
    ADMINISTRADOR = "administrador"
    COORDINADOR = "coordinador"
    SUPERVISOR = "supervisor"
    PARAMEDICO = "paramedico"
    OPERADOR = "operador"


# Roles con acceso total
FULL_ACCESS_ROLES: Set[str] = {
    UserRole.ADMINISTRADOR.value,
    UserRole.COORDINADOR.value,
    UserRole.SUPERVISOR.value,
}

# Roles que pueden administrar usuarios
ADMIN_ROLES: Set[str] = {
    UserRole.ADMINISTRADOR.value,
    UserRole.COORDINADOR.value,
    UserRole.SUPERVISOR.value,
}

# Roles que requieren 2FA obligatorio
TWO_FA_REQUIRED_ROLES: Set[str] = {
    UserRole.ADMINISTRADOR.value,
    UserRole.COORDINADOR.value,
    UserRole.SUPERVISOR.value,
}

# Permisos por módulo
class Permission(str, Enum):
    # Servicios
    VIEW_ALL_SERVICES = "view_all_services"
    VIEW_ASSIGNED_SERVICES = "view_assigned_services"
    CREATE_SERVICE = "create_service"
    EDIT_SERVICE = "edit_service"
    DELETE_SERVICE = "delete_service"
    
    # Inventario
    VIEW_ALL_INVENTORY = "view_all_inventory"
    VIEW_UNIT_INVENTORY = "view_unit_inventory"
    MANAGE_INVENTORY = "manage_inventory"
    
    # Checklist
    VIEW_ALL_CHECKLISTS = "view_all_checklists"
    VIEW_UNIT_CHECKLIST = "view_unit_checklist"
    CREATE_CHECKLIST = "create_checklist"
    
    # Finanzas
    VIEW_FINANCES = "view_finances"
    MANAGE_FINANCES = "manage_finances"
    VIEW_SERVICE_AMOUNT = "view_service_amount"
    
    # Reportes
    VIEW_REPORTS = "view_reports"
    EXPORT_REPORTS = "export_reports"
    
    # Usuarios
    VIEW_USERS = "view_users"
    MANAGE_USERS = "manage_users"
    
    # Auditoría
    VIEW_AUDIT = "view_audit"
    VIEW_OWN_AUDIT = "view_own_audit"
    
    # Notificaciones
    VIEW_ALL_NOTIFICATIONS = "view_all_notifications"
    VIEW_OWN_NOTIFICATIONS = "view_own_notifications"
    
    # Configuración
    MANAGE_CONFIG = "manage_config"


# Mapeo de roles a permisos
ROLE_PERMISSIONS: Dict[str, Set[Permission]] = {
    UserRole.ADMINISTRADOR.value: {p for p in Permission},  # Todos los permisos
    
    UserRole.COORDINADOR.value: {p for p in Permission},  # Todos los permisos
    
    UserRole.SUPERVISOR.value: {p for p in Permission},  # Todos los permisos
    
    UserRole.PARAMEDICO.value: {
        Permission.VIEW_ASSIGNED_SERVICES,
        Permission.VIEW_UNIT_INVENTORY,
        Permission.VIEW_UNIT_CHECKLIST,
        Permission.CREATE_CHECKLIST,
        Permission.VIEW_SERVICE_AMOUNT,
        Permission.VIEW_OWN_NOTIFICATIONS,
        Permission.VIEW_OWN_AUDIT,
    },
    
    UserRole.OPERADOR.value: {
        Permission.VIEW_ASSIGNED_SERVICES,
        Permission.VIEW_UNIT_INVENTORY,
        Permission.VIEW_UNIT_CHECKLIST,
        Permission.CREATE_CHECKLIST,
        Permission.VIEW_OWN_NOTIFICATIONS,
        Permission.VIEW_OWN_AUDIT,
    },
}


def has_permission(role: str, permission: Permission) -> bool:
    """Verifica si un rol tiene un permiso específico"""
    role_perms = ROLE_PERMISSIONS.get(role, set())
    return permission in role_perms


def has_any_permission(role: str, permissions: List[Permission]) -> bool:
    """Verifica si un rol tiene al menos uno de los permisos"""
    role_perms = ROLE_PERMISSIONS.get(role, set())
    return any(p in role_perms for p in permissions)


def has_full_access(role: str) -> bool:
    """Verifica si el rol tiene acceso total"""
    return role in FULL_ACCESS_ROLES


def can_manage_users(role: str) -> bool:
    """Verifica si el rol puede gestionar usuarios"""
    return role in ADMIN_ROLES


def requires_2fa(role: str) -> bool:
    """Verifica si el rol requiere 2FA obligatorio"""
    return role in TWO_FA_REQUIRED_ROLES


# ====== MODELOS DE DATOS ======

class UserSession(BaseModel):
    id: str
    user_id: str
    token_hash: str
    ip_address: Optional[str] = None
    user_agent: Optional[str] = None
    device_info: Optional[str] = None
    created_at: datetime
    last_activity: datetime
    expires_at: datetime
    is_active: bool = True


class PasswordHistory(BaseModel):
    password_hash: str
    created_at: datetime


class UserExtended(BaseModel):
    id: str
    email: EmailStr
    full_name: str
    role: UserRole
    phone: Optional[str] = None
    is_active: bool = True
    created_at: datetime
    
    # Campos de seguridad
    password_hash: str
    password_expires_at: Optional[datetime] = None
    password_history: List[PasswordHistory] = []
    must_change_password: bool = False
    
    # 2FA
    two_fa_enabled: bool = False
    two_fa_secret: Optional[str] = None
    two_fa_verified: bool = False
    
    # Sesiones
    failed_login_attempts: int = 0
    locked_until: Optional[datetime] = None
    last_login: Optional[datetime] = None
    last_login_ip: Optional[str] = None
    
    # Asignación
    assigned_ambulance_id: Optional[str] = None
    
    # Metadata
    created_by: Optional[str] = None
    updated_at: Optional[datetime] = None
    updated_by: Optional[str] = None


class LoginAttempt(BaseModel):
    user_id: Optional[str]
    email: str
    ip_address: Optional[str]
    user_agent: Optional[str]
    success: bool
    failure_reason: Optional[str] = None
    timestamp: datetime


# ====== FUNCIONES 2FA ======

def generate_2fa_secret() -> str:
    """Genera un secreto para 2FA TOTP"""
    return pyotp.random_base32()


def get_totp_uri(secret: str, email: str) -> str:
    """Genera URI para configurar app autenticadora"""
    totp = pyotp.TOTP(secret)
    return totp.provisioning_uri(
        name=email,
        issuer_name=SystemConfig.TWO_FA_ISSUER
    )


def generate_qr_code_base64(uri: str) -> str:
    """Genera código QR en base64 para la URI TOTP"""
    qr = qrcode.QRCode(version=1, box_size=10, border=4)
    qr.add_data(uri)
    qr.make(fit=True)
    
    img = qr.make_image(fill_color="black", back_color="white")
    buffer = io.BytesIO()
    img.save(buffer, format='PNG')
    buffer.seek(0)
    
    return f"data:image/png;base64,{base64.b64encode(buffer.getvalue()).decode()}"


def verify_totp(secret: str, code: str) -> bool:
    """Verifica un código TOTP"""
    if not secret or not code:
        return False
    totp = pyotp.TOTP(secret)
    return totp.verify(code, valid_window=1)  # Permite 30 segundos de margen


def generate_backup_codes(count: int = 10) -> List[str]:
    """Genera códigos de respaldo para 2FA"""
    import secrets
    return [secrets.token_hex(4).upper() for _ in range(count)]


# ====== FUNCIONES DE CONTRASEÑA ======

def hash_password(password: str) -> str:
    """Hash de contraseña usando bcrypt"""
    import bcrypt
    return bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()


def verify_password(password: str, password_hash: str) -> bool:
    """Verifica contraseña contra hash"""
    import bcrypt
    try:
        return bcrypt.checkpw(password.encode(), password_hash.encode())
    except:
        return False


def hash_token(token: str) -> str:
    """Hash de token para almacenamiento seguro"""
    return hashlib.sha256(token.encode()).hexdigest()


def is_password_in_history(password: str, history: List[PasswordHistory]) -> bool:
    """Verifica si la contraseña está en el historial reciente"""
    for entry in history[-SystemConfig.PASSWORD_HISTORY_COUNT:]:
        if verify_password(password, entry.password_hash):
            return True
    return False


def calculate_password_expiry() -> datetime:
    """Calcula fecha de expiración de contraseña"""
    return datetime.utcnow() + timedelta(days=SystemConfig.PASSWORD_EXPIRY_DAYS)


def is_password_expiring_soon(expires_at: Optional[datetime]) -> bool:
    """Verifica si la contraseña expira pronto"""
    if not expires_at:
        return False
    warning_date = datetime.utcnow() + timedelta(days=SystemConfig.PASSWORD_EXPIRY_WARNING_DAYS)
    return expires_at <= warning_date


def is_password_expired(expires_at: Optional[datetime]) -> bool:
    """Verifica si la contraseña ha expirado"""
    if not expires_at:
        return False
    return datetime.utcnow() >= expires_at


# ====== FUNCIONES DE SESIÓN ======

def create_session_data(
    user_id: str,
    token: str,
    request: Optional[Request] = None
) -> dict:
    """Crea datos de sesión"""
    import uuid
    now = datetime.utcnow()
    
    ip_address = None
    user_agent = None
    
    if request:
        ip_address = request.client.host if request.client else None
        user_agent = request.headers.get("user-agent", "")[:500]
    
    return {
        "id": str(uuid.uuid4()),
        "user_id": user_id,
        "token_hash": hash_token(token),
        "ip_address": ip_address,
        "user_agent": user_agent,
        "device_info": parse_device_info(user_agent) if user_agent else None,
        "created_at": now,
        "last_activity": now,
        "expires_at": now + timedelta(hours=SystemConfig.SESSION_TIMEOUT_HOURS),
        "is_active": True,
    }


def parse_device_info(user_agent: str) -> str:
    """Extrae información básica del dispositivo del user agent"""
    ua = user_agent.lower()
    
    # Sistema operativo
    if "windows" in ua:
        os_info = "Windows"
    elif "macintosh" in ua or "mac os" in ua:
        os_info = "macOS"
    elif "linux" in ua:
        os_info = "Linux"
    elif "android" in ua:
        os_info = "Android"
    elif "iphone" in ua or "ipad" in ua:
        os_info = "iOS"
    else:
        os_info = "Desconocido"
    
    # Navegador
    if "chrome" in ua and "edg" not in ua:
        browser = "Chrome"
    elif "firefox" in ua:
        browser = "Firefox"
    elif "safari" in ua and "chrome" not in ua:
        browser = "Safari"
    elif "edg" in ua:
        browser = "Edge"
    else:
        browser = "Otro"
    
    return f"{browser} en {os_info}"


def is_session_valid(session: dict) -> bool:
    """Verifica si una sesión es válida"""
    if not session.get("is_active", False):
        return False
    
    expires_at = session.get("expires_at")
    if expires_at:
        if isinstance(expires_at, str):
            expires_at = datetime.fromisoformat(expires_at.replace("Z", "+00:00"))
        if datetime.utcnow() > expires_at:
            return False
    
    return True


# ====== VALIDACIONES ======

def validate_password_strength(password: str) -> tuple[bool, str]:
    """Valida la fortaleza de una contraseña"""
    if len(password) < 8:
        return False, "La contraseña debe tener al menos 8 caracteres"
    
    if not any(c.isupper() for c in password):
        return False, "La contraseña debe contener al menos una mayúscula"
    
    if not any(c.islower() for c in password):
        return False, "La contraseña debe contener al menos una minúscula"
    
    if not any(c.isdigit() for c in password):
        return False, "La contraseña debe contener al menos un número"
    
    special_chars = "!@#$%^&*()_+-=[]{}|;:,.<>?"
    if not any(c in special_chars for c in password):
        return False, "La contraseña debe contener al menos un carácter especial"
    
    return True, "OK"


# ====== AUDIT HELPERS ======

class AuditAction(str, Enum):
    # Usuarios
    USER_CREATED = "user_created"
    USER_UPDATED = "user_updated"
    USER_ROLE_CHANGED = "user_role_changed"
    USER_EMAIL_CHANGED = "user_email_changed"
    USER_ACTIVATED = "user_activated"
    USER_DEACTIVATED = "user_deactivated"
    USER_PASSWORD_CHANGED = "user_password_changed"
    USER_PASSWORD_RESET = "user_password_reset"
    
    # Sesiones
    LOGIN_SUCCESS = "login_success"
    LOGIN_FAILED = "login_failed"
    LOGOUT = "logout"
    SESSION_CLOSED_REMOTE = "session_closed_remote"
    ALL_SESSIONS_CLOSED = "all_sessions_closed"
    
    # 2FA
    TWO_FA_ENABLED = "two_fa_enabled"
    TWO_FA_DISABLED = "two_fa_disabled"
    TWO_FA_VERIFIED = "two_fa_verified"
    
    # Finanzas
    FINANCE_VIEWED = "finance_viewed"
    FINANCE_CREATED = "finance_created"
    FINANCE_UPDATED = "finance_updated"
    FINANCE_DELETED = "finance_deleted"
    
    # Inventario
    INVENTORY_CRITICAL_ADJUSTMENT = "inventory_critical_adjustment"
    
    # Acceso denegado
    ACCESS_DENIED = "access_denied"


def create_audit_entry(
    action: AuditAction,
    user_id: str,
    user_name: str,
    target_type: str,
    target_id: Optional[str] = None,
    details: Optional[dict] = None,
    ip_address: Optional[str] = None
) -> dict:
    """Crea una entrada de auditoría"""
    import uuid
    return {
        "id": str(uuid.uuid4()),
        "action": action.value,
        "user_id": user_id,
        "user_name": user_name,
        "target_type": target_type,
        "target_id": target_id,
        "details": details or {},
        "ip_address": ip_address,
        "timestamp": datetime.utcnow(),
    }
