# Python Network Tools

Colección de scripts de Python para análisis de tráfico, monitoreo de red y detección básica de intrusos. Desarrollado como parte de mi portafolio de Administración de Sistemas y Ciberseguridad.

# IMPORTANTE

Estas herramientas fueron creadas para motivos educativos para el analisis de redes locales

## Contenido

1.  **own-sniffer-tool.py**: Capturador de tráfico en tiempo real usando Raw Sockets.
2.  **ids_catchet.py**: Sistema de Detección de Intrusos (IDS) básico capaz de identificar:
    * Anomalías de tamaño en paquetes ICMP (Posible Data Exfiltration).
    * Fingerprinting pasivo de Sistemas Operativos (TTL Analysis).
    * Monitoreo de conexiones TCP SYN.

## Tecnologías

* **Python 3**
* **Scapy**: Manipulación de paquetes.
* **Colorama**: Formato visual para alertas en terminal.
* **Linux/Kali**: Entorno de ejecución.

## Instalación y Uso

1. Clonar el repositorio:
   ```bash
   git clone [https://github.com/vaahl/python-network-tools.git](https://github.com/vaahl/python-network-tools.git)