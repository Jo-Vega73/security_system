from alerter import GestorAlertas
from prevention import SistemaPrevencion
from net_monitor import MonitorRed
from log_analyzer import AnalizadorLogs
from vuln_scanner import EscanerVuln
from reporter import GeneradorReportes
from web_analyzer import AnalizadorWeb


def main():
    print("==============================================")
    print("   SISTEMA INTEGRAL DE CIBERSEGURIDAD v2.0")
    print("==============================================")

    # --------------------------------------------
    # Núcleo compartido
    # --------------------------------------------
    alerter = GestorAlertas()

    sistema_prevencion = SistemaPrevencion(
        alerter,
        modo_real=False   # Cambiar a True solo como admin/root
    )

    # --------------------------------------------
    # Módulos
    # --------------------------------------------
    monitor = MonitorRed(sistema_prevencion, alerter)
    analizador_logs = AnalizadorLogs(alerter, sistema_prevencion)
    scanner = EscanerVuln(alerter)
    analizador_web = AnalizadorWeb(alerter)
    reporter = GeneradorReportes()

    # --------------------------------------------
    # Flujo principal
    # --------------------------------------------
    monitor.iniciar_monitoreo(duracion=15)

    analizador_logs.analizar()

    vulns_encontradas = scanner.escanear("Servidor_Produccion_01")

    payload = input("\nIngrese una URL para analizar (prueba de inyección): ")
    analizador_web.analizar_peticion(payload, sistema_prevencion)

    ips = sistema_prevencion.obtener_bloqueos()
    reporter.generar_html(ips, vulns_encontradas)

    alerter.mostrar_resumen()

    print("\n[FIN] Ejecución completada.")


if __name__ == "__main__":
    main()
