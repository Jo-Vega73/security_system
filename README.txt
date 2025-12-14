# Sistema Integral de Ciberseguridad

## 📌 Descripción General

Este proyecto implementa un **Sistema  de Ciberseguridad** desarrollado en Python, cuyo objetivo es **detectar, alertar, prevenir y reportar incidentes de seguridad** de manera modular.

El sistema combina **detección reactiva** (monitoreo y análisis) con **prevención activa** (bloqueo de IPs), y genera un **reporte final en HTML** con los hallazgos más relevantes.

---

## 🧱 Arquitectura del Sistema

El sistema está compuesto por los siguientes módulos:

| Módulo            | Función                                                 |
| ----------------- | ------------------------------------------------------- |
| `net_monitor.py`  | Monitoreo de tráfico de red (Scapy / Simulación)        |
| `log_analyzer.py` | Análisis de logs del sistema (Windows / Linux)          |
| `vuln_scanner.py` | Escaneo de vulnerabilidades del sistema                 |
| `web_analyzer.py` | Detección de ataques web (SQLi, XSS, Command Injection) |
| `prevention.py`   | Prevención activa (bloqueo de IPs)                      |
| `alerter.py`      | Gestión centralizada de alertas                         |
| `reporter.py`     | Generación de reporte HTML final                        |
| `main.py`         | Orquestador principal del sistema                       |

---

## 🖥️ Diferencias según el Sistema Operativo

El comportamiento del sistema **varía según el sistema operativo**, debido a restricciones de permisos y herramientas disponibles.

### 🔹 Windows

* **Monitoreo de red:**

  * Se ejecuta en **modo simulado** por limitaciones de Scapy en Windows.
* **Análisis de logs:**

  * Intenta leer el log `Security`.
  * Si no hay privilegios suficientes, utiliza el log `System` como alternativa.
* **Escaneo de vulnerabilidades:**

  * Puede realizar **escaneo real** usando comandos como:

    * `systeminfo`
    * PowerShell (`Get-WindowsOptionalFeature`, `$PSVersionTable`)
  * Si falla por permisos, se activa automáticamente un **escenario simulado controlado**.
* **Prevención:**

  * Puede aplicar reglas reales usando `netsh` **solo si se ejecuta como Administrador**.

### 🔹 Kali Linux / Linux

* **Monitoreo de red:**

  * Captura real de tráfico TCP usando **Scapy**.
* **Análisis de logs:**

  * Analiza `/var/log/auth.log`.
* **Escaneo de vulnerabilidades:**

  * Revisión real de:

    * Kernel (`uname -r`)
    * Servicios expuestos (`ss -tuln`)
    * Configuración SSH
    * Estado del firewall (UFW)
* **Prevención:**

  * Bloqueo real mediante `iptables` **solo con privilegios root**.

---

## ⚠️ Importancia de Ejecutar como Administrador / Root

> 🔴 **Recomendado ejecutar el sistema con privilegios elevados**

| Sistema | Comando recomendado                              |
| ------- | ------------------------------------------------ |
| Windows | Ejecutar CMD / PowerShell como **Administrador** |
| Linux   | `sudo python3 main.py`                           |

Sin privilegios elevados:

* Algunos módulos cambian automáticamente a **modo simulado**.
* No se aplican bloqueos reales.
* El sistema sigue funcionando, pero de forma demostrativa.

---

## 🧠 Modo Real vs Modo Simulado

El sistema está diseñado para **no fallar nunca**:

* Si un escaneo real falla → se activa simulación
* Si no hay permisos → se usa escenario controlado
* Esto garantiza estabilidad y portabilidad

Este enfoque permite:

* Uso académico
* Pruebas sin riesgo
* Ejecución en diferentes entornos

---

## 🚨 Sistema de Alertas

El módulo `alerter.py` centraliza todas las alertas:

* Salida en consola en tiempo real
* Registro en archivo de logs
* Simulación de envío de correo para alertas críticas
* Resumen final de alertas al terminar la ejecución

---

## 📄 Reportes

Al finalizar la ejecución se genera un **reporte HTML** que incluye:

* IPs bloqueadas
* Vulnerabilidades detectadas
* Fecha y hora de ejecución

Los reportes se guardan en la carpeta `reports/` y **no se sobrescriben**, ya que incluyen timestamp.

---

## ▶️ Ejecución

```bash
python main.py
```

O en Linux:

```bash
sudo python3 main.py
```


---


**Autor:** Joseph Vega
**Lenguaje:** Python
**Entorno probado:** Windows 10 / Kali Linux
