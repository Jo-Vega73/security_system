from config import VERSIONES_OBSOLETAS

class EscanerVuln:
    def __init__(self, alerter):
        self.alerter = alerter
        
    def escanear_sistema(self, sistema_objetivo):
        print(f"\n[+] Escaneando vulnerabilidades en: {sistema_objetivo}")
        
        # Simulación de software instalado en el objetivo
        software_instalado = {
            "Apache Server": "v2.4.50",
            "OpenSSH": "v1.0",      # Obsoleto
            "Windows": "WinXP",     # Obsoleto
            "Python": "3.9"
        }
        
        vulnerables = []
        for soft, version in software_instalado.items():
            print(f"    Revisando {soft} ({version})...")
            if any(v in version for v in VERSIONES_OBSOLETAS):
                print(f"    🚨 VULNERABLE: {soft} versión {version} es obsoleta.")
                vulnerables.append(soft)
            else:
                print("    OK.")
        
        return vulnerables