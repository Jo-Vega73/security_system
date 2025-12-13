# log_analyzer.py
import re
import os
import platform

from config import PATRONES_LOGS

# Detectar si estamos en Windows
WIN = platform.system() == "Windows"
if WIN:
    try:
        import win32evtlog  # type: ignore
    except ImportError:
        win32evtlog = None


class AnalizadorLogs:
    def __init__(self, alerter, prevencion=None):
        self.alerter = alerter
        self.prevencion = prevencion   # Para bloquear IPs si aparecen en los logs

    # ==================================================================
    #         MÉTODO PRINCIPAL LLAMADO DESDE main.py
    # ==================================================================
    def analizar(self):
        if WIN and win32evtlog is not None:
            self._analizar_eventos_windows()
        else:
            self._analizar_archivo_linux("/var/log/auth.log")

    # ==================================================================
    #                       WINDOWS
    # ==================================================================
    def _analizar_eventos_windows(self):
        print("\n[+] Analizando logs de Windows (Security)...")

        server = "localhost"
        log_type = "Security"

        # Intento 1: leer Security
        try:
            handle = win32evtlog.OpenEventLog(server, log_type)
        except Exception as e:
            print("    [!] Sin privilegios para leer Security. Usando 'System'.")
            log_type = "System"

            # Intento 2: leer System
            try:
                handle = win32evtlog.OpenEventLog(server, log_type)
            except Exception as e2:
                print(f"    Error accediendo al visor de eventos: {e2}")
                return

        flags = win32evtlog.EVENTLOG_BACKWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ

        try:
            events = win32evtlog.ReadEventLog(handle, flags, 0)
        except Exception as e:
            print(f"    Error leyendo eventos: {e}")
            return

        hallazgos = 0

        for ev in events:
            if not ev.StringInserts:
                continue

            # Convertir contenido a texto plano
            linea = " ".join(str(s) for s in ev.StringInserts)

            # Buscar patrones sospechosos
            for patron in PATRONES_LOGS:
                if re.search(patron, linea, re.IGNORECASE):
                    hallazgos += 1
                    self._alertar("WINDOWS", patron, linea)
                    self._intentar_bloqueo_ip(linea)

        print(f"[+] Logs analizados en '{log_type}'. {hallazgos} eventos sospechosos detectados.")

    # ==================================================================
    #                       LINUX
    # ==================================================================
    def _analizar_archivo_linux(self, ruta_log):
        print(f"\n[+] Analizando logs Linux: {ruta_log}")

        if not os.path.exists(ruta_log):
            print("    [!] Archivo no encontrado. Creando log de prueba...")
            self._crear_log_prueba(ruta_log)

        hallazgos = 0

        with open(ruta_log, "r") as f:
            for linea in f:
                for patron in PATRONES_LOGS:
                    if re.search(patron, linea, re.IGNORECASE):
                        hallazgos += 1
                        self._alertar("LINUX", patron, linea.strip())
                        self._intentar_bloqueo_ip(linea)

        print(f"[+] Análisis de logs finalizado. {hallazgos} eventos sospechosos encontrados.")

    # ==================================================================
    #                       FUNCIONES DE SOPORTE
    # ==================================================================
    def _alertar(self, origen, patron, mensaje):
        self.alerter.nueva_alerta(
            "WARNING",
            f"LOGS_{origen}",
            f"Patrón detectado: '{patron}' → {mensaje}"
        )

    def _intentar_bloqueo_ip(self, texto):
        """Busca una IP en el log y la bloquea si existe sistema de prevención."""
        if not self.prevencion:
            return

        match = re.search(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", texto)
        if match:
            ip = match.group()
            self.prevencion.bloquear_ip(ip, "Actividad sospechosa detectada en logs")

    def _crear_log_prueba(self, ruta):
        with open(ruta, "w") as f:
            f.write("2023-11-01 08:00:00 - System started\n")
            f.write("2023-11-01 08:05:00 - Failed password for user root from 10.0.0.55\n")
            f.write("2023-11-01 08:10:00 - Auth success\n")
