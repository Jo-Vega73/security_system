# config.py
import os

# Rutas de archivos
LOG_DIR = "logs"
REPORT_DIR = "reports"
LOG_FILE = os.path.join(LOG_DIR, "incidentes_seguridad.log")

# Configuración de Red
SCAPY_DISPONIBLE = False
try:
    import scapy.all
    SCAPY_DISPONIBLE = True
except ImportError:
    pass

# Reglas de Detección
PUERTOS_PELIGROSOS = [21, 23, 445, 3389]
VERSIONES_OBSOLETAS = {
    "OpenSSH": ["v1.0", "v1.1"],
    "SMB": ["v1"],
    "PowerShell": ["1.0", "2.0"],
    "Windows": ["winxp", "vista"]
}



PATRONES_WEB = {
    "SQL Injection": r"('|%27|--|\bOR\b|\bAND\b)",
    "XSS": r"<script>|</script>",
    "Command Injection": r"(;|\|\||&&|\bwhoami\b|\bls\b|\bcat\b)"
}


PATRONES_LOGS = [
    r"failed login", 
    r"error de autenticación", 
    r"password incorrect",
    r"sudo:.*command not found"
]