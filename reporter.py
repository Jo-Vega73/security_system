# reporter.py
import os
import datetime
from config import REPORT_DIR


class GeneradorReportes:
    def generar_html(self, ips_bloqueadas, vulnerabilidades):
        if not os.path.exists(REPORT_DIR):
            os.makedirs(REPORT_DIR)

        timestamp = datetime.datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
        nombre_archivo = f"Reporte_Seguridad_{timestamp}.html"
        ruta_completa = os.path.join(REPORT_DIR, nombre_archivo)

        html = f"""
        <html>
        <head>
            <title>Reporte de Ciberseguridad</title>
            <style>
                body {{
                    font-family: Arial, sans-serif;
                    background-color: #f4f6f7;
                }}
                h1 {{ color: #2c3e50; }}
                h2 {{ color: #34495e; }}
                .bloqueo {{ color: #c0392b; }}
                .vuln {{ color: #e67e22; }}
                .ok {{ color: #27ae60; }}
                hr {{ border: 1px solid #ccc; }}
            </style>
        </head>
        <body>
            <h1>Reporte Final de Seguridad</h1>
            <p><strong>Generado el:</strong> {datetime.datetime.now()}</p>
            <hr>

            <h2>1. Acciones Preventivas (IPs Bloqueadas)</h2>
            <ul>
        """

        if ips_bloqueadas:
            for ip in ips_bloqueadas:
                html += f"<li class='bloqueo'>{ip}</li>"
        else:
            html += "<li class='ok'>No se realizaron bloqueos</li>"

        html += """
            </ul>
            <h2>2. Vulnerabilidades Detectadas</h2>
            <ul>
        """

        if vulnerabilidades:
            for v in vulnerabilidades:
                html += f"<li class='vuln'>{v}</li>"
        else:
            html += "<li class='ok'>No se detectaron vulnerabilidades</li>"

        html += """
            </ul>
            <hr>
            <p><em>Reporte generado automáticamente por el Sistema Integral de Ciberseguridad.</em></p>
        </body>
        </html>
        """

        with open(ruta_completa, "w", encoding="utf-8") as f:
            f.write(html)

        print(f"\n[+] Informe generado exitosamente en: {ruta_completa}")
