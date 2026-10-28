"""Base de conocimiento: categorías, tácticas ATT&CK, impacto y playbooks de respuesta.

Los textos usan marcadores {users}, {hosts}, {ext_ips}, {iocs} que se rellenan
con las entidades reales del incidente, de modo que el plan de acción siempre
habla de los activos que aparecen en los logs.
"""

from __future__ import annotations

import re

# Orden = posición en la cadena de ataque (para líneas de tiempo y títulos).
CATEGORIES: dict[str, dict] = {
    "ataque_web": {
        "label": "Ataque a aplicación web",
        "tactic": "Acceso inicial",
        "icon": "🌐",
    },
    "fuerza_bruta": {
        "label": "Fuerza bruta / ataque de credenciales",
        "tactic": "Acceso a credenciales",
        "icon": "🔑",
    },
    "inicio_sospechoso": {
        "label": "Inicio de sesión sospechoso",
        "tactic": "Acceso inicial",
        "icon": "🚪",
    },
    "escalamiento": {
        "label": "Escalamiento de privilegios",
        "tactic": "Escalamiento de privilegios",
        "icon": "⬆️",
    },
    "comandos": {
        "label": "Comandos y procesos sospechosos",
        "tactic": "Ejecución",
        "icon": "⚙️",
    },
    "persistencia": {
        "label": "Persistencia",
        "tactic": "Persistencia",
        "icon": "📌",
    },
    "movimiento_lateral": {
        "label": "Movimiento lateral",
        "tactic": "Movimiento lateral",
        "icon": "↔️",
    },
    "exfiltracion": {
        "label": "Recolección y exfiltración de datos",
        "tactic": "Recolección / Exfiltración",
        "icon": "📤",
    },
    "anomalia": {
        "label": "Otras anomalías",
        "tactic": "Evasión / Anomalía",
        "icon": "❓",
    },
}
CATEGORY_ORDER = list(CATEGORIES)


def category_label(cat: str) -> str:
    return CATEGORIES.get(cat, {}).get("label", cat)


# Rol de un host deducido de su nombre (heurística común en nomenclaturas corporativas).
_HOST_ROLES = [
    (r"^DC", "controlador de dominio (identidades y autenticación de toda la organización)"),
    (r"^(FS|FILE)", "servidor de archivos (información compartida de negocio)"),
    (r"^(DB|SQL)", "servidor de base de datos"),
    (r"^(WEB|IIS|WWW)", "servidor web expuesto"),
    (r"^APP", "servidor de aplicaciones"),
    (r"^(WS|PC|LT|DESKTOP)", "estación de trabajo"),
]
CRITICAL_HOST_PATTERN = re.compile(r"^(DC|FS|FILE|DB|SQL)", re.I)


def host_role(host: str) -> str:
    for pattern, role in _HOST_ROLES:
        if re.match(pattern, host or "", re.I):
            return role
    return "equipo"


def is_critical_host(host: str) -> bool:
    return bool(CRITICAL_HOST_PATTERN.match(host or ""))


SENSITIVE_DATA_PATTERN = re.compile(
    r"finan|legal|budget|presupuesto|rrhh|\bhr\b|payroll|nomina|contrat|confiden|secret",
    re.I,
)

# Impacto potencial por categoría.
IMPACT: dict[str, str] = {
    "fuerza_bruta": "Riesgo de toma de control de cuentas corporativas y bloqueo de usuarios legítimos "
                    "por intentos fallidos repetidos.",
    "inicio_sospechoso": "Un actor no autorizado puede operar con la identidad de {users}, con el mismo "
                         "nivel de acceso que el usuario legítimo.",
    "escalamiento": "Con privilegios elevados el atacante puede desactivar controles, crear cuentas, "
                    "acceder a cualquier dato del equipo y preparar ataques de mayor alcance.",
    "comandos": "La ejecución de código arbitrario en {hosts} permite instalar herramientas, robar "
                "credenciales o desplegar cargas destructivas.",
    "persistencia": "El atacante conserva acceso aunque se cambien contraseñas o se reinicien los equipos, "
                    "lo que prolonga el compromiso.",
    "movimiento_lateral": "El compromiso se extiende desde el punto de entrada hacia otros sistemas "
                          "({hosts}), ampliando la superficie afectada.",
    "exfiltracion": "Posible acceso indebido o fuga de información confidencial con consecuencias legales (p. ej. "
                    "notificación según GDPR si hay datos personales), contractuales y reputacionales.",
    "ataque_web": "Compromiso del servidor web expuesto a Internet; puede servir de puerta de entrada a "
                  "la red interna y exponer datos de la aplicación.",
    "anomalia": "Entidades no inventariadas o con nombres que imitan activos legítimos dificultan la "
                "detección y pueden ocultar actividad maliciosa.",
}

# Playbooks: (investigar, contener, remediar) por categoría.
PLAYBOOKS: dict[str, dict[str, list[str]]] = {
    "fuerza_bruta": {
        "investigar": [
            "Revisar todos los intentos desde {ext_ips} y confirmar si alguna cuenta objetivo inició sesión con éxito.",
            "Consultar reputación de {ext_ips} en fuentes de inteligencia de amenazas.",
        ],
        "contener": [
            "Bloquear {ext_ips} en firewall perimetral y VPN.",
            "Forzar el cambio de contraseña de las cuentas objetivo: {users}.",
        ],
        "remediar": [
            "Aplicar MFA a todos los accesos remotos y cuentas privilegiadas.",
            "Configurar bloqueo de cuenta tras N intentos fallidos y alertas de password spraying en el SIEM.",
        ],
    },
    "inicio_sospechoso": {
        "investigar": [
            "Reconstruir la sesión completa de {users} (logon/logoff, procesos, accesos) desde el inicio sospechoso.",
            "Validar con el usuario si reconoce la actividad y el origen {ext_ips}.",
        ],
        "contener": [
            "Deshabilitar temporalmente {users} y revocar sesiones y tickets Kerberos activos.",
        ],
        "remediar": [
            "Restablecer credenciales de {users} y revisar sus permisos.",
            "Restringir RDP/acceso remoto desde Internet; publicar solo vía VPN con MFA.",
        ],
    },
    "escalamiento": {
        "investigar": [
            "Revisar los grupos privilegiados y cambios de pertenencia recientes en {hosts}.",
            "Identificar qué acciones se realizaron con los privilegios asignados a {users}.",
        ],
        "contener": [
            "Retirar privilegios administrativos innecesarios de {users}.",
        ],
        "remediar": [
            "Implantar modelo de privilegio mínimo y administración por niveles (tiering) y LAPS.",
        ],
    },
    "comandos": {
        "investigar": [
            "Adquirir memoria y artefactos forenses de {hosts}; decodificar los comandos ofuscados.",
            "Buscar los mismos comandos o hashes en el resto del parque (threat hunting).",
        ],
        "contener": [
            "Aislar de la red los equipos {hosts} mediante el EDR.",
        ],
        "remediar": [
            "Habilitar PowerShell Constrained Language Mode, Script Block Logging y AMSI.",
            "Aplicar reglas ASR / AppLocker para bloquear ejecución desde rutas de usuario.",
        ],
    },
    "persistencia": {
        "investigar": [
            "Inventariar tareas programadas, servicios y binarios creados en {hosts}; obtener hashes.",
        ],
        "contener": [
            "Deshabilitar y eliminar las tareas/servicios maliciosos y poner en cuarentena los binarios.",
        ],
        "remediar": [
            "Monitorear eventos 4698/7045 con alertas y restringir quién puede crear servicios.",
        ],
    },
    "movimiento_lateral": {
        "investigar": [
            "Trazar todos los accesos de {users} entre sistemas y los recursos tocados en cada uno.",
        ],
        "contener": [
            "Bloquear SMB/RDP entre segmentos no necesarios y aislar {hosts} si hay evidencia de compromiso.",
        ],
        "remediar": [
            "Segmentar la red, limitar cuentas administrativas por nivel y deshabilitar NTLM donde sea posible.",
        ],
    },
    "exfiltracion": {
        "investigar": [
            "Determinar el volumen y contenido exacto de los datos accedidos o enviados.",
            "Evaluar con Legal/DPO si hay datos personales y si aplica notificación (GDPR, 72 h).",
        ],
        "contener": [
            "Bloquear los destinos externos ({dest_ips}) en proxy y firewall.",
            "Revocar acceso de {users} a los recursos compartidos afectados.",
        ],
        "remediar": [
            "Implantar DLP y alertas de volumen saliente anómalo; revisar permisos de carpetas sensibles.",
        ],
    },
    "ataque_web": {
        "investigar": [
            "Revisar el árbol de directorios web (p. ej. /uploads) en {hosts} en busca de webshells.",
            "Analizar todas las peticiones de {ext_ips} y los datos devueltos por los endpoints expuestos.",
        ],
        "contener": [
            "Bloquear {ext_ips} en el WAF/firewall y retirar los archivos maliciosos del servidor.",
        ],
        "remediar": [
            "Corregir la carga de archivos (validación de tipo, almacenamiento fuera del webroot) y "
            "restringir /admin y APIs de exportación con autenticación fuerte.",
            "Ejecutar el application pool con privilegios mínimos.",
        ],
    },
    "anomalia": {
        "investigar": [
            "Validar contra el inventario (CMDB) y Active Directory la legitimidad de: {entities}.",
        ],
        "contener": [
            "Si no son legítimas, deshabilitar las cuentas y aislar los equipos no inventariados.",
        ],
        "remediar": [
            "Establecer convención de nombres y alertas de creación de cuentas/equipos nuevos.",
        ],
    },
}

GENERAL_RECOMMENDATIONS = [
    "Implantar MFA en todos los accesos remotos, cuentas privilegiadas y servicios expuestos a Internet.",
    "No exponer RDP directamente a Internet; centralizar accesos remotos en VPN o bastión con MFA.",
    "Aplicar el principio de privilegio mínimo y separar cuentas administrativas de las de uso diario.",
    "Desplegar EDR en servidores y estaciones con capacidad de aislamiento remoto.",
    "Habilitar PowerShell Script Block Logging, Module Logging y AMSI en todo el parque.",
    "Segmentar la red (servidores críticos, estaciones, DMZ web) y filtrar SMB/RDP entre segmentos.",
    "Implantar DLP y alertas por volumen de datos salientes anómalo en el proxy.",
    "Mantener copias de seguridad inmutables/offline y probar su restauración periódicamente.",
    "Mantener inventario actualizado de activos y cuentas (CMDB) y normalizar nombres en el SIEM.",
    "Endurecer aplicaciones web: validación de cargas de archivos, WAF y revisión de endpoints administrativos.",
    "Crear casos de uso en el SIEM para cada patrón detectado en este informe y revisarlos periódicamente.",
    "Formar al personal en ciberseguridad y realizar ejercicios de respuesta a incidentes.",
]


def fill(template: str, ctx: dict[str, str]) -> str | None:
    """Rellena marcadores con entidades reales; None si alguna no existe (el paso no aplica)."""
    keys = re.findall(r"\{(\w+)\}", template)
    if any(not ctx.get(k) for k in keys):
        return None
    return re.sub(r"\{(\w+)\}", lambda m: ctx[m.group(1)], template)
