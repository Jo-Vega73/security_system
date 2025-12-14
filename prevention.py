# prevention.py
import platform
import subprocess
import ipaddress


class SistemaPrevencion:
    def __init__(self, alerter, modo_real=False):
        self.alerter = alerter
        self.modo_real = modo_real
        self.sistema = platform.system()

        # -------------------------------
        # Estado interno
        # -------------------------------
        self.ips_bloqueadas = set()

        # -------------------------------
        # WHITELIST
        # -------------------------------
        self.whitelist = {
            "127.0.0.1",
            "::1",
            "192.168.1.1",     # Gateway típico
            "10.0.0.1"
        }

    # ==========================================================
    #               MÉTODO PÚBLICO
    # ==========================================================
    def bloquear_ip(self, ip, motivo):
        print("\n[+] [PREVENCION] Evaluando respuesta automática")

        modo = "REAL" if self.modo_real else "SIMULADO"
        print(f"    Modo de operación : {modo}")
        print(f"    IP evaluada       : {ip}")
        print(f"    Motivo            : {motivo}")

        # 1️⃣ Validar IP
        if not self._ip_valida(ip):
            print("    ❌ IP inválida → Acción cancelada")
            return

        # 2️⃣ Verificar whitelist
        if self._en_whitelist(ip):
            print("    🟢 Decisión: IP en WHITELIST → No se bloquea")
            self.alerter.nueva_alerta(
                "INFO",
                "PREVENCION",
                f"Intento de bloqueo evitado (whitelist): {ip}"
            )
            return

        # 3️⃣ Evitar duplicados
        if ip in self.ips_bloqueadas:
            print("    ℹ️ IP ya bloqueada previamente")
            return

        # 4️⃣ Aplicar bloqueo
        if self.modo_real:
            self._bloqueo_real(ip)
        else:
            self._bloqueo_simulado(ip)

        # 5️⃣ Registrar estado
        self.ips_bloqueadas.add(ip)

        print(f"    🚫 Acción aplicada : BLOQUEO {modo}")

        # 6️⃣ Generar alerta
        self.alerter.nueva_alerta(
            "CRITICAL",
            "PREVENCION",
            f"IP {ip} bloqueada. Motivo: {motivo}"
        )

    # ==========================================================
    #               BLOQUEO REAL
    # ==========================================================
    def _bloqueo_real(self, ip):
        print(f"    🔧 Aplicando bloqueo REAL para {ip}")

        try:
            if self.sistema == "Linux":
                subprocess.run(
                    ["iptables", "-A", "INPUT", "-s", ip, "-j", "DROP"],
                    check=True
                )

            elif self.sistema == "Windows":
                subprocess.run(
                    [
                        "netsh", "advfirewall", "firewall", "add", "rule",
                        f"name=Block {ip}",
                        "dir=in",
                        "action=block",
                        f"remoteip={ip}"
                    ],
                    check=True
                )

        except Exception as e:
            print(f"    [!] Error aplicando bloqueo real: {e}")

    # ==========================================================
    #             BLOQUEO SIMULADO
    # ==========================================================
    def _bloqueo_simulado(self, ip):
        print(f"    🔧 Bloqueo SIMULADO aplicado a {ip}")

    # ==========================================================
    #                UTILIDADES
    # ==========================================================
    def _ip_valida(self, ip):
        try:
            ipaddress.ip_address(ip)
            return True
        except ValueError:
            return False

    def _en_whitelist(self, ip):
        return ip in self.whitelist
