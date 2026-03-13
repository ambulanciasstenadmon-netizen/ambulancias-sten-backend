# Firebase Cloud Messaging Module
# Este módulo está preparado para enviar notificaciones push una vez configurado
# Requiere credenciales de Firebase (firebase_credentials.json)

import os
import json
from typing import Optional, List, Dict, Any
from datetime import datetime

# Flag para saber si FCM está configurado
FCM_CONFIGURED = False
FCM_CREDENTIALS_PATH = os.path.join(os.path.dirname(__file__), 'firebase_credentials.json')

# Intentar cargar Firebase Admin SDK si está instalado y configurado
try:
    import firebase_admin
    from firebase_admin import credentials, messaging
    
    if os.path.exists(FCM_CREDENTIALS_PATH):
        cred = credentials.Certificate(FCM_CREDENTIALS_PATH)
        firebase_admin.initialize_app(cred)
        FCM_CONFIGURED = True
        print("✅ Firebase Cloud Messaging configurado correctamente")
    else:
        print("⚠️ Firebase Cloud Messaging no configurado - archivo firebase_credentials.json no encontrado")
except ImportError:
    print("⚠️ Firebase Admin SDK no instalado - pip install firebase-admin")
except Exception as e:
    print(f"⚠️ Error configurando Firebase: {e}")


def is_fcm_configured() -> bool:
    """Verifica si FCM está configurado y listo para usar"""
    return FCM_CONFIGURED


async def send_push_notification(
    token: str,
    title: str,
    body: str,
    priority: str = "normal",
    data: Optional[Dict[str, str]] = None
) -> bool:
    """
    Envía una notificación push a un dispositivo específico
    
    Args:
        token: Token FCM del dispositivo
        title: Título de la notificación
        body: Cuerpo del mensaje
        priority: "normal" | "alerta" | "critica"
        data: Datos adicionales a enviar (opcionales)
    
    Returns:
        bool: True si se envió correctamente
    """
    if not FCM_CONFIGURED:
        print(f"[FCM] Notificación no enviada (FCM no configurado): {title}")
        return False
    
    try:
        # Configurar prioridad Android
        android_priority = "normal"
        if priority in ["alerta", "critica"]:
            android_priority = "high"
        
        # Crear mensaje
        message = messaging.Message(
            notification=messaging.Notification(
                title=title,
                body=body,
            ),
            android=messaging.AndroidConfig(
                priority=android_priority,
                notification=messaging.AndroidNotification(
                    icon="notification_icon",
                    color="#E53935" if priority == "critica" else "#1976D2",
                    sound="default" if priority in ["alerta", "critica"] else None,
                    channel_id="high_priority" if priority == "critica" else "default",
                ),
            ),
            apns=messaging.APNSConfig(
                payload=messaging.APNSPayload(
                    aps=messaging.Aps(
                        alert=messaging.ApsAlert(
                            title=title,
                            body=body,
                        ),
                        sound="default" if priority in ["alerta", "critica"] else None,
                        badge=1,
                    ),
                ),
            ),
            data=data or {},
            token=token,
        )
        
        response = messaging.send(message)
        print(f"[FCM] ✅ Notificación enviada: {response}")
        return True
        
    except messaging.UnregisteredError:
        print(f"[FCM] ⚠️ Token no válido o dispositivo desregistrado")
        return False
    except Exception as e:
        print(f"[FCM] ❌ Error enviando notificación: {e}")
        return False


async def send_push_to_multiple(
    tokens: List[str],
    title: str,
    body: str,
    priority: str = "normal",
    data: Optional[Dict[str, str]] = None
) -> Dict[str, Any]:
    """
    Envía una notificación push a múltiples dispositivos
    
    Returns:
        Dict con success_count, failure_count y tokens_invalidos
    """
    if not FCM_CONFIGURED:
        print(f"[FCM] Notificaciones no enviadas (FCM no configurado): {title}")
        return {"success_count": 0, "failure_count": len(tokens), "invalid_tokens": []}
    
    if not tokens:
        return {"success_count": 0, "failure_count": 0, "invalid_tokens": []}
    
    try:
        # Configurar prioridad
        android_priority = "high" if priority in ["alerta", "critica"] else "normal"
        
        message = messaging.MulticastMessage(
            notification=messaging.Notification(
                title=title,
                body=body,
            ),
            android=messaging.AndroidConfig(
                priority=android_priority,
                notification=messaging.AndroidNotification(
                    icon="notification_icon",
                    color="#E53935" if priority == "critica" else "#1976D2",
                    sound="default" if priority in ["alerta", "critica"] else None,
                ),
            ),
            data=data or {},
            tokens=tokens,
        )
        
        response = messaging.send_multicast(message)
        
        # Identificar tokens inválidos
        invalid_tokens = []
        if response.failure_count > 0:
            for idx, resp in enumerate(response.responses):
                if not resp.success:
                    invalid_tokens.append(tokens[idx])
        
        result = {
            "success_count": response.success_count,
            "failure_count": response.failure_count,
            "invalid_tokens": invalid_tokens
        }
        
        print(f"[FCM] Multicast: {response.success_count} exitosos, {response.failure_count} fallidos")
        return result
        
    except Exception as e:
        print(f"[FCM] ❌ Error en multicast: {e}")
        return {"success_count": 0, "failure_count": len(tokens), "invalid_tokens": []}


async def send_topic_notification(
    topic: str,
    title: str,
    body: str,
    priority: str = "normal",
    data: Optional[Dict[str, str]] = None
) -> bool:
    """
    Envía una notificación a todos los suscritos a un topic
    
    Topics sugeridos:
    - "coordinadores": Todos los coordinadores
    - "urgencias": Alertas de urgencias
    - "inventario": Alertas de inventario
    """
    if not FCM_CONFIGURED:
        print(f"[FCM] Topic notification no enviada (FCM no configurado): {topic}")
        return False
    
    try:
        android_priority = "high" if priority in ["alerta", "critica"] else "normal"
        
        message = messaging.Message(
            notification=messaging.Notification(
                title=title,
                body=body,
            ),
            android=messaging.AndroidConfig(
                priority=android_priority,
            ),
            data=data or {},
            topic=topic,
        )
        
        response = messaging.send(message)
        print(f"[FCM] ✅ Topic notification enviada a '{topic}': {response}")
        return True
        
    except Exception as e:
        print(f"[FCM] ❌ Error enviando topic notification: {e}")
        return False


async def subscribe_to_topic(tokens: List[str], topic: str) -> bool:
    """Suscribe dispositivos a un topic"""
    if not FCM_CONFIGURED:
        return False
    
    try:
        response = messaging.subscribe_to_topic(tokens, topic)
        print(f"[FCM] Suscritos a '{topic}': {response.success_count} exitosos")
        return response.success_count > 0
    except Exception as e:
        print(f"[FCM] Error suscribiendo a topic: {e}")
        return False


async def unsubscribe_from_topic(tokens: List[str], topic: str) -> bool:
    """Desuscribe dispositivos de un topic"""
    if not FCM_CONFIGURED:
        return False
    
    try:
        response = messaging.unsubscribe_from_topic(tokens, topic)
        print(f"[FCM] Desuscritos de '{topic}': {response.success_count} exitosos")
        return response.success_count > 0
    except Exception as e:
        print(f"[FCM] Error desuscribiendo de topic: {e}")
        return False


# Configuración de canales Android (para documentación)
ANDROID_CHANNELS = {
    "default": {
        "id": "default",
        "name": "Notificaciones Generales",
        "description": "Notificaciones del sistema"
    },
    "high_priority": {
        "id": "high_priority",
        "name": "Alertas Críticas",
        "description": "Alertas que requieren atención inmediata",
        "importance": "high"
    },
    "services": {
        "id": "services",
        "name": "Servicios",
        "description": "Notificaciones sobre servicios"
    }
}


def get_fcm_status() -> Dict[str, Any]:
    """Obtiene el estado de configuración de FCM"""
    return {
        "configured": FCM_CONFIGURED,
        "credentials_path": FCM_CREDENTIALS_PATH,
        "credentials_exist": os.path.exists(FCM_CREDENTIALS_PATH),
        "channels": ANDROID_CHANNELS
    }
