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

    vulnerabilidades = scanner.escanear("Servidor_Produccion_01")

    # Obtener bloqueos hechos por prevention
    ips_bloqueadas = sistema_prevencion.ips_bloqueadas

    reporter.generar_html(ips_bloqueadas, vulnerabilidades)

    print("\n[FIN] Ejecución completada.")


if __name__ == "__main__":
    main()
