import os
import logging
from config import LOG_FILE, LOG_DIR

# Configuración inicial de logging
if not os.path.exists(LOG_DIR):
    os.makedirs(LOG_DIR)
logging.basicConfig(filename=LOG_FILE, level=logging.WARNING, format='%(asctime)s - %(message)s')

# Importar nuestros módulos
from alerter import GestorAlertas
from prevention import SistemaPrevencion
from net_monitor import MonitorRed
from log_analyzer import AnalizadorLogs
from web_analyzer import AnalizadorWeb
from vuln_scanner import EscanerVuln
from reporter import GeneradorReportes

def main():
    print("==============================================")
    print("   SISTEMA INTEGRAL DE CIBERSEGURIDAD v2.0")
    print("==============================================")
    
    # 1. Instanciar el núcleo de prevención (compartido)
    alerter = GestorAlertas()
    sistema_prev = SistemaPrevencion(alerter)
    
    # 2. Instanciar los módulos
    monitor = MonitorRed(sistema_prev, alerter)
    analizador_logs = AnalizadorLogs(alerter)
    analizador_web = AnalizadorWeb(alerter)
    scanner = EscanerVuln(alerter)
    reporter = GeneradorReportes()
    
    # --- EJECUCIÓN DEL FLUJO DE TRABAJO ---
    
    # Paso A: Monitoreo de Red
    monitor.iniciar_monitoreo(duracion=5)
    
    # Paso B: Análisis de Logs
    analizador_logs.analizar()
    
    # Paso C: Escaneo de Vulnerabilidades
    vulns_encontradas = scanner.escanear_sistema("Servidor_Produccion_01")
    
    # Paso D: Análisis Web (Prueba interactiva)
    payload = input("\nIngrese una URL para analizar (prueba de inyección): ")
    analizador_web.analizar_peticion(payload, sistema_prev)
    
    # Paso E: Generar Reporte Final
    ips = sistema_prev.obtener_bloqueos()
    reporter.generar_html(ips, vulns_encontradas)

    # Paso F: Resumen final de alertas
    alerter.mostrar_resumen()

    
    print("\n[FIN] Ejecución completada.")

if __name__ == "__main__":
    main()