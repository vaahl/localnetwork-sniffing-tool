<div align="center">

# Network Analysis & Security Tools

### Suite profesional de herramientas para análisis de tráfico de red, detección de intrusos y auditoría de seguridad

[![Python](https://img.shields.io/badge/Python-3.8%2B-blue.svg)](https://www.python.org/)
[![Scapy](https://img.shields.io/badge/Scapy-2.6.1-green.svg)](https://scapy.net/)
[![License](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Security](https://img.shields.io/badge/Purpose-Security%20Audit-red.svg)]()

[Características](#-características) • [Instalación](#-instalación) • [Herramientas](#-herramientas) • [Uso](#-uso) • [Legal](#%EF%B8%8F-aviso-legal)

</div>

---

## ⚠️ AVISO LEGAL

**IMPORTANTE:** Estas herramientas fueron creadas exclusivamente para propósitos **EDUCATIVOS** y de **AUDITORÍA DE SEGURIDAD** en redes propias o con autorización explícita por escrito.

El uso no autorizado en redes ajenas constituye un **DELITO INFORMÁTICO** según:
- 🇨🇱 Ley 19.223 (Chile) - Delitos Informáticos
- 🇺🇸 Computer Fraud and Abuse Act (USA)
- Convenio de Budapest sobre Ciberdelincuencia

**El autor NO se hace responsable del mal uso de estas herramientas.**

---

## Descripción

Suite de herramientas Python para **análisis de tráfico de red** y **detección de amenazas**, desarrollada como parte del portafolio de Administración de Sistemas y Ciberseguridad. Incluye un monitor de tráfico pasivo y un sistema IDS (Intrusion Detection System) con capacidades de Deep Packet Inspection.

### Objetivos

- ✅ Monitorear y analizar tráfico de red en tiempo real
- ✅ Detectar amenazas de seguridad (port scans, túneles ICMP)
- ✅ Auditar protocolos inseguros (credenciales en texto plano)
- ✅ Generar evidencia forense para análisis de incidentes
- ✅ Demostrar conocimientos prácticos en análisis de red

---

## Características Principales

### Monitor de Tráfico
- Captura pasiva de paquetes TCP/UDP/ICMP
- Análisis en tiempo real sin modificar tráfico
- Filtros BPF personalizables
- Estadísticas detalladas de protocolos
- Soporte para múltiples interfaces de red

### Sistema IDS
- **Detección de SYN Scans** - Identifica intentos de port scanning
- **Detección de Túneles ICMP** - Alerta sobre posible data exfiltration
- **Deep Packet Inspection** - Audita credenciales en texto plano
- **Geolocalización de IPs** - Enriquecimiento de datos con país/ISP
- **Logging Estructurado** - Exporta alertas en JSON para análisis
- **Protección de Datos** - Logs privados excluidos del repositorio

---

## Requisitos

### Sistema Operativo
- **Linux** (Kali, Ubuntu, AlmaLinux, RHEL, etc.)
- **Arquitectura:** x86_64, ARM64

### Software Requerido
```bash
# Python 3.8 o superior
python3 --version

# Permisos de root (para captura raw de paquetes)
sudo su
```

### Dependencias Python
```bash
# Instalar desde requirements.txt
pip install -r requirements.txt

# O manualmente:
pip install scapy==2.6.1
pip install colorama==0.4.6
pip install requests==2.32.5
```

---

## Instalación

### Método 1: Clone desde GitHub

```bash
# 1. Clonar el repositorio
git clone https://github.com/vaahl/localnetwork-sniffing-tool.git
cd localnetwork-sniffing-tool

# 2. Instalar dependencias
pip install -r requirements.txt

# 3. Dar permisos de ejecución
chmod +x *.py

# 4. Verificar instalación
python3 own_sniffer_tool.py --help
python3 ids_catcher.py --help
```

### Método 2: Instalación en Kali Linux

```bash
# Las herramientas están optimizadas para Kali
# Kali ya incluye Scapy por defecto

sudo apt update
sudo apt install python3-scapy python3-colorama python3-requests
git clone https://github.com/vaahl/localnetwork-sniffing-tool.git
cd localnetwork-sniffing-tool
```

---

## Herramientas Incluidas

### 1. Network Traffic Monitor (`own_sniffer_tool.py`)

**Descripción:**  
Monitor pasivo de tráfico de red que captura y analiza paquetes en tiempo real usando Scapy. No interfiere con el tráfico, solo observa.

**Características:**
- ✅ Captura TCP/UDP/ICMP en tiempo real
- ✅ Identificación de IPs origen/destino
- ✅ Análisis de puertos y flags TCP
- ✅ Estadísticas de protocolos
- ✅ Filtros BPF personalizables
- ✅ Soporte multi-interfaz
- ✅ Output colorido en terminal

**Casos de uso:**
- Troubleshooting de conectividad de red
- Análisis de comunicaciones entre hosts
- Verificación de servicios activos
- Educación en protocolos de red
- Debugging de aplicaciones cliente-servidor

**Sintaxis básica:**
```bash
# Captura básica (todas las interfaces)
sudo python3 own_sniffer_tool.py

# Interfaz específica
sudo python3 own_sniffer_tool.py -i eth0

# Capturar N paquetes
sudo python3 own_sniffer_tool.py -c 100

# Con filtro BPF
sudo python3 own_sniffer_tool.py --filter "tcp port 80"

# Modo verbose
sudo python3 own_sniffer_tool.py -v

# Listar interfaces disponibles
python3 own_sniffer_tool.py -l
```

**Screenshot de ejemplo:**
```
============================================================
  📡 NETWORK TRAFFIC MONITOR v2.0
============================================================
  Autor: Camilo Aros Pérez
  Inicio: 2025-12-15 16:30:15
============================================================

  Configuración:
    Interfaz: eth0
    Filtro BPF: tcp port 80
    Paquetes a capturar: 100
    Modo verbose: Sí

  Capturando tráfico... (Presiona Ctrl+C para detener)

──────────────────────────────────────────────────────────

[     1] TCP   | 192.168.1.101:52341 -> 93.184.216.34:80    | Flags: S
[     2] TCP   | 93.184.216.34:80    -> 192.168.1.101:52341 | Flags: SA
[     3] TCP   | 192.168.1.101:52341 -> 93.184.216.34:80    | Flags: A
```

---

### 2. IDS Catcher (`ids_catcher.py`)

**Descripción:**  
Sistema de Detección de Intrusos (IDS) que monitorea activamente el tráfico de red en busca de amenazas, anomalías y credenciales en texto plano. Incluye geolocalización de atacantes y logging estructurado.

**Características:**
- 🚨 **Detección de SYN Scans** - Identifica port scanning (Nmap, Masscan)
- 🔴 **Detección de Túneles ICMP** - Alerta sobre paquetes ICMP anormalmente grandes
- 🔐 **Auditoría DLP** - Captura credenciales en texto plano (HTTP, FTP, Telnet)
- 🌍 **Geolocalización** - Consulta APIs para identificar país/ISP del atacante
- 📊 **Logging JSON** - Exporta alertas estructuradas para SIEM
- 📝 **Logging Privado** - Guarda evidencia sensible separada
- ⚖️ **Disclaimer Legal** - Solicita aceptación explícita de términos

**Capacidades de detección:**

#### A) SYN Scan Detection
Detecta escaneos de puertos basados en flags SYN (característicos de Nmap):
```python
# Detecta flags TCP SYN sin ACK
if packet[TCP].flags == 'S':
    # Alerta de posible port scan
```

#### B) ICMP Tunnel Detection
Detecta túneles ICMP usados para data exfiltration:
```python
# Pings normales < 100 bytes
# Túneles pueden ser > 1000 bytes
if len(packet[ICMP].load) > 100:
    # Alerta de posible túnel
```

#### C) Credential Leak Detection (DLP)
Audita protocolos inseguros con Deep Packet Inspection:
```python
keywords = ["USER ", "PASS ", "password=", "login="]
# Busca en payloads TCP no cifrados
```

**Sintaxis:**
```bash
# Ejecución básica (acepta disclaimer)
sudo python3 ids_catcher.py

# Interfaz específica
sudo python3 ids_catcher.py -i eth0

# Modo verbose (más detalles)
sudo python3 ids_catcher.py -v

# Listar interfaces
python3 ids_catcher.py -l
```

**Output esperado:**
```
============================================================
  ⚠️  ADVERTENCIA DE USO LEGAL Y ÉTICO
============================================================
  Este software es una herramienta de AUDITORÍA DE SEGURIDAD.
  El uso en redes ajenas sin consentimiento escrito es ILEGAL.
  ...
  Para continuar, escribe 'ACEPTO' (sin comillas):
  > ACEPTO

[✓] Responsabilidad aceptada. Iniciando auditoría...

============================================================
  🛡️  IDS CATCHER - Sistema de Detección de Intrusos v5.1
============================================================
  Autor: @vaahl
  Inicio: 2025-12-15 16:45:30
============================================================

  Configuración:
    Interfaz: TODAS
    Log JSON: alertas.json
    Log credenciales: credenciales_capturadas.log

  Monitoreando tráfico... (Presiona Ctrl+C para detener)

──────────────────────────────────────────────────────────

[⚠] Escaneo SYN a puerto 22 desde 45.142.193.78 (Russia - Moscow - AS Example)
[⚠] Escaneo SYN a puerto 3389 desde 185.212.51.221 (Netherlands - Amsterdam - HostingCo)

[🚨] CREDENCIALES EN TEXTO PLANO DETECTADAS!
    Origen: 192.168.1.101 -> Destino: 44.228.249.3
    Protocolo: TCP/80
    Keyword: 'password='

[!!!] ICMP gigante (1024 bytes) - Posible túnel/exfiltración desde 10.0.0.50
```

**Archivos generados:**

1. **`alertas.json`** - Log estructurado de todas las alertas:
```json
{
  "timestamp": "2025-12-15 16:45:32",
  "type": "SYN_SCAN",
  "source": "45.142.193.78",
  "destination": "192.168.1.101",
  "message": "Escaneo SYN a puerto 22",
  "geo_info": "Russia - Moscow - AS Example"
}
```

2. **`credenciales_capturadas.log`** - Evidencia sensible (excluido de git):
```
[2025-12-15 16:46:10] PROTOCOLO: TCP/80
ORIGEN: 192.168.1.101 -> DESTINO: 44.228.249.3
PAYLOAD:
POST /login.php HTTP/1.1
Host: vulnerable-site.com
...
username=admin&password=secretpass123
────────────────────────────────────────────────
```

---

## Ejemplos de Uso Avanzado

### Escenario 1: Troubleshooting de Conectividad

```bash
# ¿Por qué mi aplicación no se conecta al servidor?
sudo python3 own_sniffer_tool.py --filter "host 10.0.0.50" -v

# Buscar específicamente tráfico HTTP
sudo python3 own_sniffer_tool.py --filter "tcp port 80" -c 50
```

### Escenario 2: Detectar Escaneos en Tiempo Real

```bash
# Monitorear intentos de conexión a tu servidor
sudo python3 ids_catcher.py -v

# Ver quién está escaneando tus puertos
# (Útil si expones servicios a Internet)
```

### Escenario 3: Auditoría de Protocolos Inseguros

```bash
# Detectar si alguien en tu red usa FTP/HTTP sin cifrar
sudo python3 ids_catcher.py

# Verificar que tus aplicaciones usen HTTPS
sudo python3 own_sniffer_tool.py --filter "tcp port 443"
```

### Escenario 4: Análisis Forense Post-Incidente

```bash
# Capturar tráfico durante X tiempo
sudo python3 own_sniffer_tool.py -c 10000 > captura.txt

# Revisar alertas generadas
cat alertas.json | jq '.[] | select(.type=="SYN_SCAN")'
```

---


## Filtros BPF (Berkeley Packet Filter)

Los filtros BPF permiten capturar tráfico específico:

```bash
# Solo tráfico TCP
--filter "tcp"

# Solo puerto específico
--filter "port 80"

# Host específico
--filter "host 192.168.1.1"

# Combinaciones
--filter "tcp and port 80"
--filter "src host 10.0.0.1 and dst port 443"
--filter "icmp or arp"

# Excluir SSH
--filter "not port 22"
```

**Ejemplos prácticos:**
```bash
# Monitorear solo DNS
sudo python3 own_sniffer_tool.py --filter "udp port 53"

# Ver tráfico web (HTTP/HTTPS)
sudo python3 own_sniffer_tool.py --filter "tcp port 80 or tcp port 443"

# Excluir tráfico SSH y DNS
sudo python3 own_sniffer_tool.py --filter "not (port 22 or port 53)"
```

---

## Troubleshooting

### Problema: "Permission denied"

**Causa:** Captura de paquetes requiere permisos de root

**Solución:**
```bash
# Ejecutar con sudo
sudo python3 own_sniffer_tool.py
```

### Problema: "Module 'scapy' not found"

**Solución:**
```bash
pip install -r requirements.txt
# O manualmente
pip install scapy colorama requests
```

### Problema: "No se capturan paquetes"

**Causas posibles:**
1. Interfaz incorrecta
2. Firewall bloqueando
3. Modo monitor no habilitado (WiFi)

**Solución:**
```bash
# Listar interfaces disponibles
python3 own_sniffer_tool.py -l

# Usar interfaz correcta
sudo python3 own_sniffer_tool.py -i eth0

# Verificar que la interfaz esté activa
ip link show
```

### Problema: Geolocalización no funciona

**Causa:** Sin conexión a Internet o API rate limited

**Solución:**
- El IDS seguirá funcionando pero mostrará "Geo Error"
- Las IPs locales (192.168.x.x) no se geoloc alizan (es normal)

---

## 🔐 Consideraciones de Seguridad

### Archivos Sensibles Excluidos

El `.gitignore` excluye automáticamente:
- `credenciales_capturadas.log` - Contiene datos sensibles
- `alertas.json` - Puede contener IPs internas

### Uso Responsable

✅ **Permitido:**
- Análisis de tu propia red doméstica
- Labs educativos aislados
- Auditorías autorizadas por escrito
- Certificaciones de seguridad (OSCP, CEH)

❌ **Prohibido:**
- Escanear redes ajenas sin permiso
- Capturar credenciales de terceros
- Uso malicioso o fraudulento
- Venta de información capturada

### Protección de Datos

Si usas estas herramientas profesionalmente:
1. Cifra logs con datos sensibles
2. Implementa políticas de retención
3. Cumple GDPR/LGPD si aplica
4. Documenta autorización por escrito

---

## 📊 Integración con SIEM

El archivo `alertas.json` puede integrarse con:

**Splunk:**
```bash
# Configurar input en Splunk
sourcetype = _json
source = /path/to/alertas.json
```

**ELK Stack (Elasticsearch):**
```bash
# Usar Filebeat para ingestar
filebeat.inputs:
- type: log
  paths:
    - /path/to/alertas.json
  json.keys_under_root: true
```

**Python Script:**
```python
import json

with open('alertas.json', 'r') as f:
    for line in f:
        alert = json.loads(line)
        if alert['type'] == 'SYN_SCAN':
            # Enviar a SIEM, webhook, etc.
            pass
```

---

## 🗺️ Roadmap

### ✅ Versión 1.0 (Actual - Diciembre 2025)
- [x] Monitor básico de tráfico
- [x] IDS con detección de SYN scans
- [x] Detección de túneles ICMP
- [x] Auditoría de credenciales
- [x] Geolocalización de IPs
- [x] Logging estructurado (JSON)

### 🔜 Versión 2.0 (Planeada - Q1 2026)
- [ ] Dashboard web en tiempo real (Flask/Dash)
- [ ] Base de datos SQLite para histórico
- [ ] Alertas por email/Telegram/Slack
- [ ] Detección de ARP spoofing
- [ ] Fingerprinting de OS (análisis TTL avanzado)
- [ ] Análisis de tráfico cifrado (metadata)
- [ ] Exportar a PCAP para Wireshark
- [ ] Tests automatizados (pytest)

### 🚀 Versión 3.0 (Futuro - 2026)
- [ ] Machine Learning para detección de anomalías
- [ ] Integración con VirusTotal API
- [ ] Detección de malware en payloads
- [ ] Cluster multi-sensor
- [ ] API REST para integración
- [ ] Soporte para IPv6 completo

---

## Licencia

Este proyecto está bajo la **Licencia MIT**. Ver [LICENSE](LICENSE) para detalles.

**En resumen:**
- ✅ Uso comercial permitido
- ✅ Modificación permitida
- ✅ Distribución permitida
- ℹ️ Sin garantía
- ℹ️ Incluir notice de copyright

---

## 📚 Recursos Adicionales


### Herramientas Complementarias
- **Wireshark** - Análisis gráfico de paquetes
- **Tcpdump** - Captura desde CLI
- **Nmap** - Network scanning
- **Zeek (Bro)** - IDS profesional
- **Suricata** - IDS/IPS open source

---


<div align="center">

## ⭐ Si estas herramientas te son útiles, considera darle una estrella al repositorio ⭐

**Desarrollado por un SysAdmin enfocado en Ciberseguridad**

### Recuerda: Con gran poder viene gran responsabilidad 

[⬆ Volver arriba](#-network-analysis--security-tools)

</div>