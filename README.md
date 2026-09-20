# Blue Team & SOC Analyst Portfolio

Bienvenidos al repositorio central de mi portafolio técnico enfocado en **Operaciones de Seguridad (SOC Tier 1 / Tier 2)**, **Ciberinteligencia de Amenazas (CTI)** y **Respuesta a Incidentes (DFIR)**.

Este espacio recopila investigaciones prácticas, análisis dinámicos y estáticos de malware real, detección de amenazas basada en comportamiento, y desarrollo de reglas de mitigación proactivas orientadas a robustecer la postura defensiva y la ciberresiliencia de entornos corporativos.

---

## Perfil Profesional

* **Analista:** Nicolás Solís Collío
* **Especialidad:** Técnico Universitario en Ciberseguridad
* **Áreas de Enfoque:** 
  * Monitoreo y Triage de Alertas de Seguridad (SOC Tier 1 / 2)
  * Análisis de Malware & Ingeniería Inversa Básica (Estático y Dinámico interactivo)
  * Threat Hunting e Inteligencia de Amenazas (CTI aplicada)
  * Detección basada en Firmas y Reglas (YARA, Suricata IDS, Sigma)
  * Correlación y Mapeo táctico bajo el marco **MITRE ATT&CK** y la **Pirámide del Dolor**

---

## Directorio de Proyectos

### 1. Análisis Dinámico y CTI: Infostealer LummaC2 (MaaS)
* **Categoría:** Análisis de Malware / Threat Intelligence / Detección de Endpoint
* **Tecnologías:** ANY.RUN, VirusTotal, Suricata IDS, YARA, MITRE ATT&CK
* **Directorio:** [`SOC-Portfolio/2026-lumma_c2`](./SOC-Portfolio/2026-lumma_c2/)
* **Descripción:** 
  * Detonación interactiva y examen forense de una muestra real de LummaC2 empaquetada en Go (`setup.exe`).
  * Identificación de técnicas avanzadas de evasión: llamadas a WMI (`T1047`), chequeos anti-sandbox (`T1497`) y *process masquerading* sobre subprocesos del navegador legítimo `chrome.exe` (`T1071`).
  * Extracción de telemetría de red: 36 alertas críticas de Suricata IDS, identificación de servidor C2 (`grzpoint[.]cyou`), IP de comando y User-Agent.
  * Validación cruzada y pivotaje en VirusTotal (*Relations* y telemetría comunitaria).
  * Elaboración de matriz técnica de IOCs bajo la Pirámide del Dolor, diseño de regla YARA proactiva y medidas de mitigación para perímetros, EDR y gestión de identidades.


---

## Stack Técnico y Herramientas

| Dominio | Tecnologías / Herramientas |
| :--- | :--- |
| **Sandboxing & Triage Dinámico** | ANY.RUN, Joe Sandbox, Hybrid Analysis |
| **CTI & Repositorios de Amenazas** | VirusTotal, MalwareBazaar, AbuseIPDB, URLhaus |
| **IDS / Detección de Red** | Suricata IDS, Wireshark, Zeek/Bro, TCPdump |
| **Detección & Firmas** | Reglas YARA, Reglas Suricata, Reglas Sigma |
| **Marcos de Referencia Defensivos**| MITRE ATT&CK Framework, Cyber Kill Chain, Pyramid of Pain |
| **Sistemas & Scripting** | Windows Internals (Sysmon, WMI, Registry), Linux, PowerShell, Bash, Python |

---

## Metodología Operativa

Todas las investigaciones y proyectos alojados en este portafolio siguen un ciclo sistemático de ciberdefensa:

1. **Ingesta y Triage:** Obtención controlada del artefacto y análisis forense inicial sin ejecución.
2. **Análisis Dinámico Interactivo:** Detonación en sandbox para observar la jerarquía de procesos y telemetría de red.
3. **Validación Cruzada (Pivotaje):** Rastreo de infraestructura para relacionar dominios, IPs y certificados con campañas activas.
4. **Respuesta Accionable:** Generación de matrices de IOCs sanitizadas (*defanged*), reglas de detección y recomendaciones defensivas a nivel de arquitectura y directivas de seguridad.

---

## Contacto y Redes

* **LinkedIn:** [Nicolás Solís Collío](https://www.linkedin.com/in/nicolas-solis-collio/)
* **Correo de Contacto:** [nicolas.solisc@mayor.cl]
* **Ubicación:** Chile