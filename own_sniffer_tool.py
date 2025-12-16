#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Network Traffic Monitor - Herramienta de Monitoreo de Tráfico de Red
Autor: Camilo Aros Pérez (@vaahl)
Descripción: Monitor pasivo de tráfico TCP/UDP/ICMP usando Scapy.
             Captura y analiza paquetes en tiempo real sin interferir en la red.
Propósito: Análisis de red, troubleshooting, auditoría de conectividad.
Versión: 2.0
Fecha: Diciembre 2025
"""

import sys
import argparse
from datetime import datetime
from scapy.all import sniff, IP, TCP, UDP, ICMP, get_if_list
from collections import defaultdict

# Estadísticas globales
stats = {
    'total_packets': 0,
    'tcp': 0,
    'udp': 0,
    'icmp': 0,
    'other': 0
}

protocol_counts = defaultdict(int)
ip_pairs = defaultdict(int)

class Colors:
    """Colores ANSI para terminal"""
    HEADER = '\033[95m'
    BLUE = '\033[94m'
    CYAN = '\033[96m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'

def print_header():
    """Imprime encabezado de la herramienta"""
    print(f"\n{Colors.HEADER}{Colors.BOLD}{'='*70}")
    print("  📡 NETWORK TRAFFIC MONITOR v2.0")
    print(f"{'='*70}{Colors.ENDC}")
    print(f"  Autor: Camilo Aros Pérez")
    print(f"  Inicio: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"{Colors.HEADER}{'='*70}{Colors.ENDC}\n")

def get_protocol_info(packet):
    """
    Determina el protocolo de transporte y retorna información detallada.
    
    Args:
        packet: Paquete capturado por Scapy
        
    Returns:
        tuple: (protocolo, puerto_origen, puerto_destino, flags)
    """
    if TCP in packet:
        flags = packet[TCP].flags
        return ("TCP", packet[TCP].sport, packet[TCP].dport, str(flags))
    elif UDP in packet:
        return ("UDP", packet[UDP].sport, packet[UDP].dport, "-")
    elif ICMP in packet:
        icmp_type = packet[ICMP].type
        return ("ICMP", icmp_type, "-", "-")
    else:
        return ("OTHER", "-", "-", "-")

def process_packet(packet, verbose=False, show_ports=True):
    """
    Callback que procesa cada paquete capturado.
    
    Args:
        packet: Paquete capturado
        verbose: Modo detallado (muestra más información)
        show_ports: Mostrar puertos (TCP/UDP)
    """
    global stats
    
    if IP in packet:
        stats['total_packets'] += 1
        
        ip_src = packet[IP].src
        ip_dst = packet[IP].dst
        
        # Obtener información del protocolo
        protocol, sport, dport, flags = get_protocol_info(packet)
        
        # Actualizar estadísticas
        if protocol == "TCP":
            stats['tcp'] += 1
        elif protocol == "UDP":
            stats['udp'] += 1
        elif protocol == "ICMP":
            stats['icmp'] += 1
        else:
            stats['other'] += 1
        
        protocol_counts[protocol] += 1
        ip_pairs[f"{ip_src} -> {ip_dst}"] += 1
        
        # Color según protocolo
        if protocol == "TCP":
            color = Colors.GREEN
        elif protocol == "UDP":
            color = Colors.BLUE
        elif protocol == "ICMP":
            color = Colors.YELLOW
        else:
            color = Colors.CYAN
        
        # Output formateado
        if verbose and show_ports:
            if protocol in ["TCP", "UDP"]:
                print(f"{color}[{stats['total_packets']:>6}] {protocol:<5}{Colors.ENDC} | "
                      f"{ip_src:<15}:{sport:<5} -> {ip_dst:<15}:{dport:<5} | "
                      f"Flags: {flags}")
            else:
                print(f"{color}[{stats['total_packets']:>6}] {protocol:<5}{Colors.ENDC} | "
                      f"{ip_src:<15} -> {ip_dst:<15}")
        else:
            print(f"{color}[{stats['total_packets']:>6}] {protocol:<5}{Colors.ENDC} | "
                  f"{ip_src:<15} -> {ip_dst:<15}")

def print_statistics():
    """Imprime estadísticas finales de captura"""
    print(f"\n{Colors.HEADER}{Colors.BOLD}{'='*70}")
    print("  📊 ESTADÍSTICAS DE CAPTURA")
    print(f"{'='*70}{Colors.ENDC}\n")
    
    print(f"  Total de paquetes capturados: {Colors.BOLD}{stats['total_packets']}{Colors.ENDC}")
    print(f"\n  Por protocolo:")
    print(f"    {Colors.GREEN}TCP:  {stats['tcp']:>6}{Colors.ENDC}")
    print(f"    {Colors.BLUE}UDP:  {stats['udp']:>6}{Colors.ENDC}")
    print(f"    {Colors.YELLOW}ICMP: {stats['icmp']:>6}{Colors.ENDC}")
    print(f"    {Colors.CYAN}Otro: {stats['other']:>6}{Colors.ENDC}")
    
    if ip_pairs:
        print(f"\n  Top 5 comunicaciones:")
        sorted_pairs = sorted(ip_pairs.items(), key=lambda x: x[1], reverse=True)[:5]
        for pair, count in sorted_pairs:
            print(f"    {pair}: {count} paquetes")
    
    print(f"\n{Colors.HEADER}{'='*70}{Colors.ENDC}\n")

def list_interfaces():
    """Lista interfaces de red disponibles"""
    print(f"\n{Colors.CYAN}Interfaces de red disponibles:{Colors.ENDC}")
    interfaces = get_if_list()
    for i, iface in enumerate(interfaces, 1):
        print(f"  {i}. {iface}")
    print()

def main():
    """Función principal con argumentos CLI"""
    parser = argparse.ArgumentParser(
        description='Monitor de tráfico de red en tiempo real',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Ejemplos de uso:
  sudo python3 own_sniffer_tool.py
  sudo python3 own_sniffer_tool.py -i eth0
  sudo python3 own_sniffer_tool.py -c 100 -v
  sudo python3 own_sniffer_tool.py --filter "tcp port 80"
  sudo python3 own_sniffer_tool.py -l  # Listar interfaces
        """
    )
    
    parser.add_argument(
        '-i', '--interface',
        help='Interfaz de red a monitorear (default: todas)',
        default=None
    )
    parser.add_argument(
        '-c', '--count',
        type=int,
        help='Número de paquetes a capturar (default: infinito)',
        default=0
    )
    parser.add_argument(
        '-f', '--filter',
        help='Filtro BPF (ej: "tcp port 80")',
        default=None
    )
    parser.add_argument(
        '-v', '--verbose',
        action='store_true',
        help='Modo verbose (más detalles)'
    )
    parser.add_argument(
        '--no-ports',
        action='store_true',
        help='No mostrar puertos'
    )
    parser.add_argument(
        '-l', '--list-interfaces',
        action='store_true',
        help='Listar interfaces disponibles'
    )
    
    args = parser.parse_args()
    
    # Listar interfaces si se solicita
    if args.list_interfaces:
        list_interfaces()
        sys.exit(0)
    
    try:
        print_header()
        
        # Información de configuración
        print(f"  Configuración:")
        print(f"    Interfaz: {args.interface if args.interface else 'TODAS'}")
        print(f"    Filtro BPF: {args.filter if args.filter else 'Ninguno'}")
        print(f"    Paquetes a capturar: {args.count if args.count > 0 else 'Infinito'}")
        print(f"    Modo verbose: {'Sí' if args.verbose else 'No'}")
        print()
        
        print(f"{Colors.YELLOW}  Capturando tráfico... (Presiona Ctrl+C para detener){Colors.ENDC}\n")
        print(f"{'─'*70}\n")
        
        # Configurar captura
        sniff_kwargs = {
            'prn': lambda pkt: process_packet(pkt, args.verbose, not args.no_ports),
            'store': 0
        }
        
        if args.interface:
            sniff_kwargs['iface'] = args.interface
        if args.count > 0:
            sniff_kwargs['count'] = args.count
        if args.filter:
            sniff_kwargs['filter'] = args.filter
        
        # Iniciar captura
        sniff(**sniff_kwargs)
        
    except PermissionError:
        print(f"\n{Colors.RED}[!] ERROR: Se requieren permisos de root{Colors.ENDC}")
        print(f"    Ejecuta con: {Colors.BOLD}sudo python3 {sys.argv[0]}{Colors.ENDC}\n")
        sys.exit(1)
        
    except KeyboardInterrupt:
        print(f"\n\n{Colors.YELLOW}[!] Captura detenida por el usuario{Colors.ENDC}")
        print_statistics()
        sys.exit(0)
        
    except Exception as e:
        print(f"\n{Colors.RED}[!] ERROR FATAL: {e}{Colors.ENDC}\n")
        sys.exit(1)

if __name__ == "__main__":
    main()