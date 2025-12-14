from alerter import GestorAlertas
from prevention import SistemaPrevencion
from net_monitor import MonitorRed
from log_analyzer import AnalizadorLogs
from vuln_scanner import EscanerVuln
from reporter import GeneradorReportes


def main():
    print("==============================================")
    print("   SISTEMA INTEGRAL DE CIBERSEGURIDAD v2.0")
    print("==============================================")

    # --------------------------------------------
    # Núcleo compartido
    # --------------------------------------------
    alerter = GestorAlertas()

    #  modo_real = False (seguro para evaluación)
    sistema_prevencion = SistemaPrevencion(
        alerter,
        modo_real=False
    )

    # --------------------------------------------
    # Módulos
    # --------------------------------------------
    monitor = MonitorRed(sistema_prevencion, alerter)
    analizador_logs = AnalizadorLogs(alerter)
    scanner = EscanerVuln(alerter)
    reporter = GeneradorReportes()
    
    # --- EJECUCIÓN DEL FLUJO DE TRABAJO ---
    
    # Paso A: Monitoreo de Red
    monitor.iniciar_monitoreo(duracion=15)
    
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
