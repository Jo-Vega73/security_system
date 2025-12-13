# reporter.py
import os
import datetime
from config import REPORT_DIR

class GeneradorReportes:
    def generar_html(self, ips_bloqueadas, vulnerabilidades):
        if not os.path.exists(REPORT_DIR):
            os.makedirs(REPORT_DIR)
            
        nombre_archivo = f"Reporte_Seguridad_{datetime.date.today()}.html"
        ruta_completa = os.path.join(REPORT_DIR, nombre_archivo)
        
        html = f"""
        <html>
        <head>
            <title>Reporte de Ciberseguridad</title>
            <style>
                body {{ font-family: Arial, sans-serif; }}
                h1 {{ color: #2c3e50; }}
                .bloqueo {{ color: red; }}
                .vuln {{ color: orange; }}
            </style>
        </head>
        <body>
            <h1>Reporte Final de Seguridad</h1>
            <p>Generado el: {datetime.datetime.now()}</p>
            <hr>
            
            <h2>1. Acciones Preventivas (IPs Bloqueadas)</h2>
            <ul>
        """
        
        for ip in ips_bloqueadas:
            html += f"<li class='bloqueo'>{ip}</li>"
            
        html += """
            </ul>
            <h2>2. Vulnerabilidades Detectadas</h2>
            <ul>
        """
        
        for v in vulnerabilidades:
            html += f"<li class='vuln'>{v}</li>"
            
        html += """
            </ul>
            <p>Fin del reporte.</p>
        </body>
        </html>
        """
        
        with open(ruta_completa, "w") as f:
            f.write(html)
            
        print(f"\n[+] Informe generado exitosamente en: {ruta_completa}")