# net_monitor.py
import time
import random
import platform
from collections import defaultdict

from config import PUERTOS_PELIGROSOS, SCAPY_DISPONIBLE

WIN = platform.system() == "Windows"


# Intentar importar Scapy (si está disponible/npcap instalado)
if SCAPY_DISPONIBLE:
    try:
        from scapy.all import sniff, IP, TCP
    except Exception:
        SCAPY_DISPONIBLE = False


class MonitorRed:
    def __init__(self, sistema_prevencion, alerter):
        self.prevencion = sistema_prevencion
        self.alerter = alerter

        # Contador de conexiones por IP para detectar escaneos
        self.conexiones_por_ip = defaultdict(int)

        # Contador de puertos tocados por cada IP (SYN scan detection)
        self.puertos_por_ip = defaultdict(set)

    # ==============================================================
    #                MÉTODO PRINCIPAL LLAMADO DESDE main.py
    # ==============================================================
    def iniciar_monitoreo(self, duracion=10):
        print(f"\n[+] Iniciando Monitoreo de Red ({duracion}s)...")

        if SCAPY_DISPONIBLE and not WIN:
            print("    Modo: SCAPY | Captura real de tráfico (sniffing)")
            sniff(filter="tcp", prn=self._analizar_paquete, timeout=duracion)
        else:
            print("    Modo: SIMULACIÓN (Windows o Scapy no disponible)")
            self._simular_trafico(duracion)

    # ==============================================================
    #                   ANALIZADOR DE PAQUETES (SCAPY)
    # ==============================================================
    def _analizar_paquete(self, paquete):
        if paquete.haslayer(IP) and paquete.haslayer(TCP):
            ip = paquete[IP].src
            puerto = paquete[TCP].dport

            self._procesar_evento(ip, puerto)

    # ==============================================================
    #                   SIMULACIÓN DE TRÁFICO
    # ==============================================================
    def _simular_trafico(self, duracion):
        ips = [
            "192.168.1.50",
            "10.0.0.5",
            "203.0.113.44",
            "185.12.33.91",
            "102.54.22.10"
        ]

        puertos = [21, 22, 23, 80, 443, 445, 3389, 5000, 8080, 135]

        inicio = time.time()

        while time.time() - inicio < duracion:
            ip = random.choice(ips)
            puerto = random.choice(puertos)

            # Simular frecuencia de escaneo
            for _ in range(random.randint(1, 3)):
                self._procesar_evento(ip, puerto)

            time.sleep(0.5)

    # ==============================================================
    #                 LÓGICA DE DETECCIÓN REAL
    # ==============================================================
    def _procesar_evento(self, ip, puerto):
        self.conexiones_por_ip[ip] += 1
        self.puertos_por_ip[ip].add(puerto)

        # --- ALERTA 1: Acceso a puertos sensibles ---
        if puerto in PUERTOS_PELIGROSOS:
            self.alerter.nueva_alerta(
                "WARNING",
                "RED",
                f"Acceso sospechoso a puerto crítico {puerto} desde {ip}"
            )
            self.prevencion.bloquear_ip(ip, f"Acceso a puerto crítico {puerto}")

        # --- ALERTA 2: Escaneo de puertos (SYN Scan) ---
        if len(self.puertos_por_ip[ip]) >= 6:  # Muchas pruebas a distintos puertos
            self.alerter.nueva_alerta(
                "CRITICAL",
                "RED",
                f"Posible escaneo de puertos por {ip} (tocó {len(self.puertos_por_ip[ip])} puertos)"
            )
            self.prevencion.bloquear_ip(ip, "Escaneo de puertos (SYN scan)")

        # --- ALERTA 3: Conexiones anómalas repetidas ---
        if self.conexiones_por_ip[ip] >= 10:
            self.alerter.nueva_alerta(
                "CRITICAL",
                "RED",
                f"Frecuencia de conexión anómala detectada desde {ip}"
            )
            self.prevencion.bloquear_ip(ip, "Tráfico inusual / posible ataque")
