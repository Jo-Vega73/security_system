import platform
import subprocess
import socket
import re


class EscanerVuln:
    def __init__(self, alerter):
        self.alerter = alerter
        self.sistema = platform.system()

    # ==========================================================
    #           MÉTODO PÚBLICO
    # ==========================================================
    def escanear(self, sistema_objetivo="Servidor_Produccion_01"):
        hostname_real = socket.gethostname()

        print("\n[+] Escaneando vulnerabilidades")
        print(f"    Target lógico : {sistema_objetivo}")
        print(f"    Hostname real : {hostname_real}")

        if self.sistema == "Windows":
            try:
                return self._escanear_windows_real()
            except Exception as e:
                print(f"    [!] Escaneo real falló: {e}")
                print("    → Activando escenario SIMULADO")
                return self._escanear_windows_simulado()
        else:
            print("    Sistema no Windows (pendiente)")
            return []

    # ==========================================================
    #              ESCANEO REAL (WINDOWS)
    # ==========================================================
    def _escanear_windows_real(self):
        vulnerables = []
        print("    Modo: ESCANEO REAL")

        # -----------------------------------------
        # 1. Sistema Operativo
        # -----------------------------------------
        salida = subprocess.check_output(
            ["systeminfo"],
            text=True,
            encoding="utf-8",
            errors="ignore"
        )

        if "Windows XP" in salida or "2008" in salida:
            msg = "Sistema operativo Windows sin soporte"
            self._alerta(msg)
            vulnerables.append(msg)
        else:
            print("    OS: OK")

        # -----------------------------------------
        # 2. SMBv1
        # -----------------------------------------
        salida = subprocess.check_output(
            [
                "powershell",
                "-Command",
                "Get-WindowsOptionalFeature -Online -FeatureName SMB1Protocol"
            ],
            text=True,
            encoding="utf-8",
            errors="ignore"
        )

        if "Enabled" in salida:
            msg = "SMBv1 habilitado (riesgo crítico)"
            self._alerta(msg)
            vulnerables.append(msg)
        else:
            print("    SMBv1: OK")

        # -----------------------------------------
        # 3. PowerShell
        # -----------------------------------------
        salida = subprocess.check_output(
            ["powershell", "-Command", "$PSVersionTable.PSVersion.Major"],
            text=True
        ).strip()

        if int(salida) < 5:
            msg = f"PowerShell versión {salida} obsoleta"
            self._alerta(msg)
            vulnerables.append(msg)
        else:
            print("    PowerShell: OK")

        # -----------------------------------------
        # 4. OpenSSH
        # -----------------------------------------
        try:
            salida = subprocess.check_output(
                ["ssh", "-V"],
                stderr=subprocess.STDOUT,
                text=True
            )

            match = re.search(r"OpenSSH_(\d+)", salida)
            if match and int(match.group(1)) < 8:
                msg = f"OpenSSH versión {match.group(1)} desactualizada"
                self._alerta(msg)
                vulnerables.append(msg)
            else:
                print("    OpenSSH: OK")

        except Exception:
            print("    OpenSSH no instalado")

        return vulnerables

    # ==========================================================
    #              ESCENARIO SIMULADO (WINDOWS)
    # ==========================================================
    def _escanear_windows_simulado(self):
        vulnerables = []
        print("    Modo: SIMULACIÓN CONTROLADA")

        simulacion = {
            "Windows": "WinXP",
            "SMBv1": "Enabled",
            "PowerShell": "2",
            "OpenSSH": "v1.0"
        }

        if simulacion["Windows"] == "WinXP":
            msg = "Sistema operativo Windows sin soporte (simulado)"
            self._alerta(msg)
            vulnerables.append(msg)

        if simulacion["SMBv1"] == "Enabled":
            msg = "SMBv1 habilitado (simulado)"
            self._alerta(msg)
            vulnerables.append(msg)

        if int(simulacion["PowerShell"]) < 5:
            msg = "PowerShell obsoleto (simulado)"
            self._alerta(msg)
            vulnerables.append(msg)

        if simulacion["OpenSSH"] == "v1.0":
            msg = "OpenSSH desactualizado (simulado)"
            self._alerta(msg)
            vulnerables.append(msg)

        return vulnerables

    # ==========================================================
    #              SISTEMA DE ALERTAS
    # ==========================================================
    def _alerta(self, mensaje):
        print(f"    🚨 {mensaje}")
        self.alerter.nueva_alerta(
            "CRITICAL",
            "VULNERABILIDAD",
            mensaje
        )
