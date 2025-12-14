# web_analyzer.py
import re
from urllib.parse import urlparse, parse_qs

from config import PATRONES_WEB


class AnalizadorWeb:
    def __init__(self, alerter):
        self.alerter = alerter

    # ==========================================================
    #            MÉTODO PRINCIPAL
    # ==========================================================
    def analizar_peticion(self, url, prevencion):
        print(f"\n[+] Analizando tráfico Web")
        print(f"    URL recibida: {url}")

        amenaza_detectada = False

        # Parsear URL
        parsed = urlparse(url)
        parametros = parse_qs(parsed.query)

        # Analizar URL completa
        if self._analizar_texto(url, prevencion, origen="URL"):
            amenaza_detectada = True

        # Analizar parámetros individualmente
        for param, valores in parametros.items():
            for valor in valores:
                if self._analizar_texto(
                    valor,
                    prevencion,
                    origen=f"Parámetro '{param}'"
                ):
                    amenaza_detectada = True

        if not amenaza_detectada:
            print("    ✔ Tráfico web limpio")

    # ==========================================================
    #              ANALIZADOR DE CONTENIDO
    # ==========================================================
    def _analizar_texto(self, texto, prevencion, origen):
        for tipo, patron in PATRONES_WEB.items():
            if re.search(patron, texto, re.IGNORECASE):
                self._detectar_ataque(tipo, texto, origen, prevencion)
                return True
        return False

    # ==========================================================
    #              RESPUESTA A ATAQUE
    # ==========================================================
    def _detectar_ataque(self, tipo, texto, origen, prevencion):
        print(f"    ⚠️ ATAQUE DETECTADO [{tipo}] en {origen}")

        # IP simulada
        ip_atacante = "192.168.1.66"

        # Alerta centralizada
        self.alerter.nueva_alerta(
            "WARNING",
            "WEB",
            f"Ataque {tipo} detectado en {origen}: {texto}"
        )

        # Prevención automática
        prevencion.bloquear_ip(
            ip_atacante,
            f"Ataque Web detectado: {tipo}"
        )
