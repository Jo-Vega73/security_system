import logging

# prevention.py
class SistemaPrevencion:
    def __init__(self, alerter):  
        self.ips_bloqueadas = set()
        self.alerter = alerter   

    def bloquear_ip(self, ip, motivo):
        """Simula el bloqueo de una IP en el firewall."""
        if ip not in self.ips_bloqueadas:
            self.ips_bloqueadas.add(ip)
            
            mensaje = f"IP {ip} bloqueada. Motivo: {motivo}"
            self.alerter.nueva_alerta("INFO", "PREVENCION", mensaje)
            
            return True
        return False
        
    def obtener_bloqueos(self):
        return list(self.ips_bloqueadas)