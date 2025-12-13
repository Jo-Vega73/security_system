import re
from config import PATRONES_WEB

class AnalizadorWeb:

    def __init__(self, alerter):
        self.alerter = alerter
        
    def analizar_peticion(self, url, prevencion):
        print(f"\n[+] Analizando petición Web: {url}")
        amenaza = False
        
        for tipo, regex in PATRONES_WEB.items():
            if re.search(regex, url, re.IGNORECASE):
                print(f"    ⚠️  ATAQUE DETECTADO: {tipo}")
                # Extraer una IP ficticia para bloquear (simulación)
                ip_atacante = "192.168.1.66" 
                prevencion.bloquear_ip(ip_atacante, f"Ataque Web {tipo}")
                amenaza = True
        
        if not amenaza:
            print(" Petición limpia.")