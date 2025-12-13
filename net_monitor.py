# net_monitor.py
import time
import random
import platform
from collections import defaultdict

from config import PUERTOS_PELIGROSOS, SCAPY_DISPONIBLE

WIN = platform.system() == "Windows"

# Intentar importar Scapy (si está disponible)
IFACES = []
if SCAPY_DISPONIBLE:
    try:
        from scapy.all import sniff, IP, TCP, get_if_list
        IFACES = get_if_list()
    except Exception:
        SCAPY_DISPONIBLE = False


class MonitorRed:
    def __init__(self, sistema_prevencion, alerter):
        self.prevencion = sistema_prevencion
        self.alerter = alerter

        # Detectar escaneos y comportamientos anómalos
        self.conexiones_por_ip = defaultdict(int)
        self.puertos_por_ip = defaultdict(set)

        self.eventos_analizados = 0
        self.alertas_generadas = 0

    # ==============================================================
    #                MÉTODO PRINCIPAL
    # ==============================================================
    def iniciar_monitoreo(self, duracion=10):
        print(f"\n[+] Iniciando Monitoreo de Red ({duracion}s)...")

        # ------------------------------
        # WINDOWS → Simulación obligada
        # ------------------------------
        if WIN:
            print("    Modo: SIMULACIÓN (Windows no permite sniffing estable con Scapy)")
            return self._simular_trafico(duracion)

        # ------------------------------
        # LINUX → Intentar captura real
        # ------------------------------
        if SCAPY_DISPONIBLE:
            iface = self._seleccionar_interfaz_linux()

            if iface:
                print(f"    Modo: SCAPY | Captura real en interfaz {iface}")
                try:
                    sniff(
                        iface=iface,
                        filter="tcp",
                        prn=self._analizar_paquete,
                        timeout=duracion,
                        store=False
                    )
                    self._resumen_monitoreo()
                    return
                except Exception as e:
                    print(f"    [!] Error al capturar: {e}")
                    print("    → Cambiando a modo simulación.")
            else:
                print("    [!] No se encontró interfaz válida para sniffing en Linux.")
        
        # Fallback
        print("    Modo: SIMULACIÓN (Scapy no disponible o fallo en sniffing)")
        self._simular_trafico(duracion)

    # ==============================================================
    #               SELECCIÓN DE INTERFAZ (Linux)
    # ==============================================================
    def _seleccionar_interfaz_linux(self):
        """Intenta elegir una interfaz realista para sniffing en Linux."""
        if not IFACES:
            return None

        # Priorizar eth0, wlan0, enp* etc.
        for iface in IFACES:
            if iface.startswith("eth") or iface.startswith("enp") or iface.startswith("wlan"):
                return iface

        # Último recurso: la primera interfaz disponible
        return IFACES[0]

    # ==============================================================
    #                  ANALIZADOR DE PAQUETES (SCAPY)
    # ==============================================================
    def _analizar_paquete(self, paquete):
        if paquete.haslayer(IP) and paquete.haslayer(TCP):
            ip = paquete[IP].src
            puerto = paquete[TCP].dport
            self._procesar_evento(ip, puerto)

    # ==============================================================
    #                     SIMULACIÓN DE TRÁFICO
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

            # Varias conexiones rápidas para simular escaneos
            for _ in range(random.randint(1, 3)):
                self._procesar_evento(ip, puerto)

            time.sleep(0.5)

    # ==============================================================
    #              MOTOR DE DETECCIÓN DE ATAQUES
    # ==============================================================
    def _procesar_evento(self, ip, puerto):
        self.eventos_analizados += 1
        self.conexiones_por_ip[ip] += 1
        self.puertos_por_ip[ip].add(puerto)

        # --- ALERTA 1: Puerto crítico ---
        if puerto in PUERTOS_PELIGROSOS:
            self.alertas_generadas += 1
            self.alerter.nueva_alerta(
                "WARNING",
                "RED",
                f"Acceso sospechoso a puerto crítico {puerto} desde {ip}"
            )
            self.prevencion.bloquear_ip(ip, f"Acceso a puerto crítico {puerto}")

        # --- ALERTA 2: SYN Scan (muchos puertos diferentes) ---
        if len(self.puertos_por_ip[ip]) >= 6:
            self.alertas_generadas += 1
            self.alerter.nueva_alerta(
                "CRITICAL",
                "RED",
                f"Posible escaneo de puertos por {ip} (tocó {len(self.puertos_por_ip[ip])} puertos)"
            )
            self.prevencion.bloquear_ip(ip, "Scan sospechoso (SYN scan)")

        # --- ALERTA 3: Frecuencia elevada ---
        if self.conexiones_por_ip[ip] >= 10:
            self.alertas_generadas += 1
            self.alerter.nueva_alerta(
                "CRITICAL",
                "RED",
                f"Frecuencia inusual de tráfico desde {ip}"
            )
            self.prevencion.bloquear_ip(ip, "Frecuencia elevada de paquetes")

    def _resumen_monitoreo(self):
        if self.eventos_analizados == 0:
            print("    [ℹ️] Monitoreo finalizado: no se capturó tráfico TCP.")
        elif self.alertas_generadas == 0:
            print("    [ℹ️] Monitoreo finalizado: tráfico observado sin actividad sospechosa.")
        else:
            print(f"    [!] Monitoreo finalizado: {self.alertas_generadas} alertas generadas.")
