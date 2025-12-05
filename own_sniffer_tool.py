#!/usr/bin/env python3
"""
Herramienta básica de monitoreo de paquetes de red.
Propósito: Demostrar el uso de Raw Sockets con Scapy para capturar tráfico TCP/IP.
Autor: [Tu Usuario de GitHub]
"""

from scapy.all import sniff, IP, TCP, UDP, ICMP
import sys

def procesar_paquete(paquete):
    """
    Callback que procesa cada paquete capturado.
    Filtra solo paquetes IP y determina el protocolo de transporte.
    """
    if IP in paquete:
        ip_src = paquete[IP].src
        ip_dst = paquete[IP].dst
        protocolo = "OTRO"
        
        # Identificación de protocolo
        if TCP in paquete:
            protocolo = "TCP"
        elif UDP in paquete:
            protocolo = "UDP"
        elif ICMP in paquete:
            protocolo = "ICMP"

        # Salida formateada
        print(f"[+] {protocolo:<4} | {ip_src:<15} -> {ip_dst:<15}")

def main():
    print("--- Monitor de Red Básico Iniciado ---")
    print("Capturando tráfico... (Presiona Ctrl+C para detener)")
    
    try:
        # store=0 evita llenar la memoria RAM con los paquetes
        sniff(prn=procesar_paquete, store=0)
    except PermissionError:
        print("\n[!] Error: Se requieren permisos de root (sudo) para capturar tráfico.")
        sys.exit(1)
    except KeyboardInterrupt:
        print("\n[!] Deteniendo captura.")
        sys.exit(0)

if __name__ == "__main__":
    main()