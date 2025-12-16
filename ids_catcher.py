#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
IDS Catcher - Sistema de Detección de Intrusos y Auditoría de Red
Autor: Camilo Aros Pérez (@vaahl)
Descripción: IDS básico que detecta escaneos de puertos, túneles ICMP,
             y auditoría de credenciales en texto plano (DLP).
Versión: 5.1
Fecha: Diciembre 2025

AVISO LEGAL:
Esta herramienta es exclusivamente para AUDITORÍA DE SEGURIDAD en redes propias
o con autorización explícita por escrito. El uso no autorizado en redes ajenas
es ILEGAL según leyes locales e internacionales.

El autor no se hace responsable del mal uso de esta herramienta.
"""

import sys
import time
import json
import argparse
from datetime import datetime
from pathlib import Path
import requests
from scapy.all import sniff, IP, TCP, ICMP, Raw, get_if_list
from colorama import Fore, Style, init
from collections import defaultdict

# Inicializar colorama
init(autoreset=True)

# Configuración global
CONFIG = {
    'ip_cache': {},
    'alert_counter': defaultdict(int),
    'log_credentials': 'credenciales_capturadas.log',
    'log_alerts_json': 'alertas.json',
    'ignored_ports': [22, 443, 53],  # SSH, HTTPS, DNS
    'geo_api_url': 'http://ip-api.com/json/{ip}?fields=country,isp,city',
    'geo_timeout': 2
}

class IDSMonitor:
    """Clase principal del sistema IDS"""
    
    def __init__(self, interface=None, verbose=False):
        """
        Inicializa el monitor IDS.
        
        Args:
            interface: Interfaz de red específica (None = todas)
            verbose: Modo detallado
        """
        self.interface = interface
        self.verbose = verbose
        self.stats = {
            'packets_analyzed': 0,
            'syn_scans_detected': 0,
            'icmp_tunnels_detected': 0,
            'credentials_leaked': 0
        }
        
        # Crear archivos de log si no existen
        Path(CONFIG['log_credentials']).touch(exist_ok=True)
        Path(CONFIG['log_alerts_json']).touch(exist_ok=True)
    
    def show_legal_disclaimer(self):
        """Muestra disclaimer legal y solicita aceptación"""
        print(f"\n{Fore.RED}{Style.BRIGHT}{'='*70}")
        print("  ⚠️  ADVERTENCIA DE USO LEGAL Y ÉTICO")
        print("="*70)
        print(f"{Fore.YELLOW}")
        print("  Este software es una herramienta de AUDITORÍA DE SEGURIDAD.")
        print("  El uso en redes ajenas sin autorización escrita es ILEGAL.")
        print()
        print("  Regulaciones aplicables:")
        print("    • Ley 19.223 (Chile) - Delitos Informáticos")
        print("    • Computer Fraud and Abuse Act (USA)")
        print("    • Convenio de Budapest sobre Ciberdelincuencia")
        print()
        print("  El desarrollador NO se hace responsable del mal uso.")
        print(f"{Fore.RED}{'─'*70}")
        print(f"{Fore.YELLOW}")
        print("  Para continuar, escribe 'ACEPTO' (sin comillas):")
        print(f"{Style.RESET_ALL}", end="")
        
        try:
            response = input(f"{Fore.CYAN}  > {Style.RESET_ALL}").strip().upper()
            if response != "ACEPTO":
                print(f"\n{Fore.RED}[!] Acceso denegado. Cerrando aplicación.{Style.RESET_ALL}\n")
                sys.exit(0)
            else:
                print(f"\n{Fore.GREEN}[✓] Responsabilidad aceptada. Iniciando auditoría...{Style.RESET_ALL}\n")
                time.sleep(1)
        except KeyboardInterrupt:
            print(f"\n\n{Fore.YELLOW}[!] Operación cancelada.{Style.RESET_ALL}\n")
            sys.exit(0)
    
    def get_geo_info(self, ip):
        """
        Enriquece la IP con datos de geolocalización.
        
        Args:
            ip: Dirección IP a consultar
            
        Returns:
            str: Información geográfica (País - Ciudad - ISP)
        """
        # IPs privadas/locales
        if ip.startswith(("192.168.", "10.", "127.", "172.16.")):
            return "Red Local"
        
        # Verificar cache
        if ip in CONFIG['ip_cache']:
            return CONFIG['ip_cache'][ip]
        
        try:
            url = CONFIG['geo_api_url'].format(ip=ip)
            response = requests.get(url, timeout=CONFIG['geo_timeout']).json()
            
            country = response.get('country', '?')
            city = response.get('city', '?')
            isp = response.get('isp', '?')
            
            info = f"{country} - {city} - {isp}"
            CONFIG['ip_cache'][ip] = info
            return info
            
        except Exception:
            return "Geo Error"
    
    def log_alert_json(self, alert_type, ip_src, ip_dst, message):
        """
        Guarda alerta en formato JSON para análisis posterior.
        
        Args:
            alert_type: Tipo de alerta (SYN_SCAN, ICMP_TUNNEL, etc.)
            ip_src: IP de origen
            ip_dst: IP de destino
            message: Descripción del evento
        """
        alert = {
            'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            'type': alert_type,
            'source': ip_src,
            'destination': ip_dst,
            'message': message,
            'geo_info': self.get_geo_info(ip_src)
        }
        
        try:
            with open(CONFIG['log_alerts_json'], 'a') as f:
                json.dump(alert, f, ensure_ascii=False)
                f.write('\n')
        except Exception as e:
            if self.verbose:
                print(f"{Fore.RED}[!] Error guardando alerta JSON: {e}{Style.RESET_ALL}")
    
    def log_credential(self, protocol, ip_src, ip_dst, payload):
        """
        Guarda credenciales capturadas en log privado.
        
        Args:
            protocol: Protocolo usado
            ip_src: IP origen
            ip_dst: IP destino
            payload: Payload con credenciales
        """
        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        report = (
            f"[{timestamp}] PROTOCOLO: {protocol}\n"
            f"ORIGEN: {ip_src} -> DESTINO: {ip_dst}\n"
            f"PAYLOAD:\n{payload}\n"
            f"{'-'*70}\n"
        )
        
        try:
            with open(CONFIG['log_credentials'], 'a') as f:
                f.write(report)
        except Exception as e:
            if self.verbose:
                print(f"{Fore.RED}[!] Error guardando credencial: {e}{Style.RESET_ALL}")
    
    def detect_syn_scan(self, packet):
        """
        Detecta escaneos SYN (port scanning).
        
        Args:
            packet: Paquete a analizar
        """
        if TCP in packet:
            src = packet[IP].src
            dst = packet[IP].dst
            dport = packet[TCP].dport
            sport = packet[TCP].sport
            
            # Ignorar puertos comunes seguros
            if dport in CONFIG['ignored_ports'] or sport in CONFIG['ignored_ports']:
                return
            
            # Detectar flag SYN puro (sin ACK)
            if packet[TCP].flags == 'S':
                geo = self.get_geo_info(src)
                
                # Solo alertar si es IP externa
                if "Red Local" not in geo:
                    message = f"Escaneo SYN a puerto {dport}"
                    
                    # Limitar alertas repetitivas
                    alert_key = f"{src}:{dport}"
                    CONFIG['alert_counter'][alert_key] += 1
                    
                    if CONFIG['alert_counter'][alert_key] <= 3:  # Solo primeras 3 veces
                        print(f"{Fore.YELLOW}[⚠] {message} desde {src} ({geo}){Style.RESET_ALL}")
                        self.log_alert_json("SYN_SCAN", src, dst, message)
                        self.stats['syn_scans_detected'] += 1
    
    def detect_icmp_tunnel(self, packet):
        """
        Detecta posibles túneles ICMP (data exfiltration).
        
        Args:
            packet: Paquete a analizar
        """
        if ICMP in packet and hasattr(packet[ICMP], "load"):
            payload_size = len(packet[ICMP].load)
            
            # Pings normales < 100 bytes, túneles suelen ser mayores
            if payload_size > 100:
                src = packet[IP].src
                dst = packet[IP].dst
                
                message = f"ICMP gigante ({payload_size} bytes) - Posible túnel/exfiltración"
                print(f"{Fore.RED}[!!!] {message} desde {src}{Style.RESET_ALL}")
                
                self.log_alert_json("ICMP_TUNNEL", src, dst, message)
                self.stats['icmp_tunnels_detected'] += 1
    
    def detect_credential_leak(self, packet):
        """
        Auditoría de credenciales en texto plano (DLP - Data Loss Prevention).
        
        Args:
            packet: Paquete a analizar
        """
        if TCP in packet and packet.haslayer(Raw):
            src = packet[IP].src
            dst = packet[IP].dst
            dport = packet[TCP].dport
            sport = packet[TCP].sport
            
            # Ignorar SSH (puerto 22)
            if dport == 22 or sport == 22:
                return
            
            try:
                payload = packet[Raw].load.decode('utf-8', errors='ignore')
                
                # Keywords sospechosas
                keywords = [
                    "USER ", "PASS ", "password=", "passwd=",
                    "uname=", "username=", "Login", "login=",
                    "pwd=", "auth="
                ]
                
                for keyword in keywords:
                    if keyword.lower() in payload.lower():
                        protocol = f"TCP/{dport}"
                        
                        print(f"\n{Fore.RED}{Style.BRIGHT}[🚨] CREDENCIALES EN TEXTO PLANO DETECTADAS!")
                        print(f"    Origen: {src} -> Destino: {dst}")
                        print(f"    Protocolo: {protocol}")
                        print(f"    Keyword: '{keyword}'{Style.RESET_ALL}\n")
                        
                        self.log_credential(protocol, src, dst, payload[:500])  # Primeros 500 chars
                        self.log_alert_json("CREDENTIAL_LEAK", src, dst, "Texto plano detectado")
                        self.stats['credentials_leaked'] += 1
                        break
                        
            except Exception:
                pass  # Ignorar errores de decodificación
    
    def analyze_packet(self, packet):
        """
        Función principal que analiza cada paquete capturado.
        
        Args:
            packet: Paquete capturado por Scapy
        """
        if IP in packet:
            self.stats['packets_analyzed'] += 1
            
            # Ejecutar detecciones
            self.detect_syn_scan(packet)
            self.detect_icmp_tunnel(packet)
            self.detect_credential_leak(packet)
            
            # Mostrar progreso cada 1000 paquetes en modo verbose
            if self.verbose and self.stats['packets_analyzed'] % 1000 == 0:
                print(f"{Fore.CYAN}[i] Paquetes analizados: {self.stats['packets_analyzed']}{Style.RESET_ALL}")
    
    def print_header(self):
        """Imprime encabezado del IDS"""
        print(f"\n{Fore.CYAN}{Style.BRIGHT}{'='*70}")
        print("  🛡️  IDS CATCHER - Sistema de Detección de Intrusos v5.1")
        print("="*70)
        print(f"{Fore.YELLOW}  Autor: @vaahl")
        print(f"  Inicio: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print(f"{Fore.CYAN}{'='*70}{Style.RESET_ALL}\n")
    
    def print_config(self):
        """Imprime configuración actual"""
        print(f"{Fore.GREEN}  Configuración:{Style.RESET_ALL}")
        print(f"    Interfaz: {self.interface if self.interface else 'TODAS'}")
        print(f"    Modo verbose: {'Sí' if self.verbose else 'No'}")
        print(f"    Log JSON: {CONFIG['log_alerts_json']}")
        print(f"    Log credenciales: {CONFIG['log_credentials']}")
        print(f"    Puertos ignorados: {CONFIG['ignored_ports']}")
        print()
    
    def print_statistics(self):
        """Imprime estadísticas finales"""
        print(f"\n{Fore.CYAN}{Style.BRIGHT}{'='*70}")
        print("  📊 ESTADÍSTICAS DE DETECCIÓN")
        print(f"{'='*70}{Style.RESET_ALL}\n")
        
        print(f"  Paquetes analizados: {Fore.BOLD}{self.stats['packets_analyzed']}{Style.RESET_ALL}")
        print(f"\n  Detecciones:")
        print(f"    {Fore.YELLOW}SYN Scans:         {self.stats['syn_scans_detected']}{Style.RESET_ALL}")
        print(f"    {Fore.RED}Túneles ICMP:      {self.stats['icmp_tunnels_detected']}{Style.RESET_ALL}")
        print(f"    {Fore.RED}Credenciales leak: {self.stats['credentials_leaked']}{Style.RESET_ALL}")
        
        print(f"\n{Fore.CYAN}{'='*70}{Style.RESET_ALL}\n")
    
    def start(self):
        """Inicia el monitoreo IDS"""
        self.show_legal_disclaimer()
        self.print_header()
        self.print_config()
        
        print(f"{Fore.YELLOW}  Monitoreando tráfico... (Presiona Ctrl+C para detener){Style.RESET_ALL}\n")
        print(f"{'─'*70}\n")
        
        try:
            sniff_kwargs = {
                'prn': self.analyze_packet,
                'store': 0
            }
            
            if self.interface:
                sniff_kwargs['iface'] = self.interface
            
            sniff(**sniff_kwargs)
            
        except PermissionError:
            print(f"\n{Fore.RED}[!] ERROR: Se requieren permisos de root{Style.RESET_ALL}")
            print(f"    Ejecuta con: {Fore.BOLD}sudo python3 {sys.argv[0]}{Style.RESET_ALL}\n")
            sys.exit(1)
            
        except KeyboardInterrupt:
            print(f"\n\n{Fore.YELLOW}[!] Monitoreo detenido por el usuario{Style.RESET_ALL}")
            self.print_statistics()
            sys.exit(0)

def list_interfaces():
    """Lista interfaces de red disponibles"""
    print(f"\n{Fore.CYAN}Interfaces de red disponibles:{Style.RESET_ALL}")
    interfaces = get_if_list()
    for i, iface in enumerate(interfaces, 1):
        print(f"  {i}. {iface}")
    print()

def main():
    """Función principal con CLI"""
    parser = argparse.ArgumentParser(
        description='IDS Catcher - Sistema de Detección de Intrusos',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Ejemplos de uso:
  sudo python3 ids_catcher.py
  sudo python3 ids_catcher.py -i eth0
  sudo python3 ids_catcher.py -v
  sudo python3 ids_catcher.py -l  # Listar interfaces
        """
    )
    
    parser.add_argument(
        '-i', '--interface',
        help='Interfaz de red a monitorear',
        default=None
    )
    parser.add_argument(
        '-v', '--verbose',
        action='store_true',
        help='Modo verbose'
    )
    parser.add_argument(
        '-l', '--list-interfaces',
        action='store_true',
        help='Listar interfaces disponibles'
    )
    
    args = parser.parse_args()
    
    if args.list_interfaces:
        list_interfaces()
        sys.exit(0)
    
    # Iniciar IDS
    ids = IDSMonitor(interface=args.interface, verbose=args.verbose)
    ids.start()

if __name__ == "__main__":
    main()