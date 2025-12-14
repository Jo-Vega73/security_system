# alerter.py
import logging
import datetime
from config import LOG_FILE


class GestorAlertas:
    def __init__(self):
        logging.basicConfig(
            filename=LOG_FILE,
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s'
        )

        # -------------------------------
        # Contadores de alertas
        # -------------------------------
        self.contador = {
            "INFO": 0,
            "WARNING": 0,
            "CRITICAL": 0
        }

        print("[+] Sistema de Alertas inicializado")

    def nueva_alerta(self, nivel, modulo, mensaje):
        nivel = nivel.upper()
        timestamp = datetime.datetime.now().strftime("%H:%M:%S")
        texto_completo = f"[{modulo.upper()}] {mensaje}"

        iconos = {
            "INFO": "ℹ️",
            "WARNING": "⚠️",
            "CRITICAL": "🚨"
        }
        icono = iconos.get(nivel, "ℹ️")

        # 1️⃣ Consola (dashboard en tiempo real)
        print(f"    {icono} [{timestamp}] {texto_completo}")

        # 2️⃣ Contador interno
        if nivel in self.contador:
            self.contador[nivel] += 1

        # 3️⃣ Logging + notificaciones
        if nivel == "INFO":
            logging.info(texto_completo)
        elif nivel == "WARNING":
            logging.warning(texto_completo)
        elif nivel == "CRITICAL":
            logging.critical(texto_completo)
            self._enviar_email_simulado(texto_completo)

    def mostrar_resumen(self):
        print("\n==============================================")
        print("        RESUMEN FINAL DE SEGURIDAD")
        print("==============================================")
        print(f"  ℹ️  Alertas informativas : {self.contador['INFO']}")
        print(f"  ⚠️  Advertencias         : {self.contador['WARNING']}")
        print(f"  🚨 Incidentes críticos   : {self.contador['CRITICAL']}")

        if self.contador["CRITICAL"] > 0:
            print("\n  ⚠️  Estado del sistema: COMPROMETIDO")
        elif self.contador["WARNING"] > 0:
            print("\n  ⚠️  Estado del sistema: REQUIERE ATENCIÓN")
        else:
            print("\n  ✅ Estado del sistema: ESTABLE")

    def _enviar_email_simulado(self, cuerpo):
        print("    [📧 EMAIL ENVIADO] Para: seguridad@empresa.com | Asunto: INCIDENTE CRÍTICO")
        print(f"    [📧 CONTENIDO] {cuerpo}")
