# alerter.py
import logging
import datetime
from config import LOG_FILE

class GestorAlertas:
    def __init__(self):
        # Configuración del log centralizado
        logging.basicConfig(
            filename=LOG_FILE,
            level=logging.WARNING,
            format='%(asctime)s - %(levelname)s - %(message)s'
        )

    def nueva_alerta(self, nivel, modulo, mensaje):
        """
        Procesa una alerta entrante de cualquier módulo.
        Niveles: 'INFO', 'WARNING', 'CRITICAL'
        """
        timestamp = datetime.datetime.now().strftime("%H:%M:%S")
        texto_completo = f"[{modulo.upper()}] {mensaje}"
        
        # 1. Notificación en Tiempo Real (Consola)
        # Simula un dashboard de seguridad
        icono = "ℹ️"
        if nivel == "WARNING": icono = "⚠️"
        if nivel == "CRITICAL": icono = "🚨"
        
        print(f"    {icono} [{timestamp}] {texto_completo}")

        # 2. Registro de Incidentes (Persistencia)
        if nivel == "CRITICAL":
            logging.critical(texto_completo)
            self._enviar_email_simulado(texto_completo) # Solo lo crítico envía email
        else:
            logging.warning(texto_completo)

    def _enviar_email_simulado(self, cuerpo):
        """Simula el envío de un correo al CISO o equipo de seguridad."""
        print(f"    [📧 EMAIL ENVIADO] Para: seguridad@empresa.com | Asunto: INCIDENTE CRÍTICO")
        print(f"    [📧 CONTENIDO] {cuerpo}")