#!/usr/bin/env python3
"""
IDS Catcher - Herramienta de Auditoría de Red y Detección de Intrusos.
Autor: [Tu Usuario]
Descripción: Detecta escaneos, anomalías y tráfico inseguro (texto plano).
"""

import time
import json
import sys
import requests
from scapy.all import sniff, IP, TCP, ICMP, Raw
from colorama import Fore, Style, init

# Inicializar colores
init(autoreset=True)

# Configuración
IP_CACHE = {}
LOG_CREDENCIALES = "credenciales_capturadas.log"
LOG_ALERTAS_JSON = "alertas.json"

def advertencia_legal():
    """Muestra un disclaimer legal y obliga a aceptar responsabilidad."""
    print(f"\n{Fore.RED}{Style.BRIGHT}" + "="*65)
    print(" ⚠️  ADVERTENCIA DE USO LEGAL Y ÉTICO")
    print("="*65)
    print(" Este software es una herramienta de AUDITORÍA DE SEGURIDAD.")
    print(" El uso en redes ajenas sin consentimiento escrito es ILEGAL.")
    print(" El desarrollador no se hace responsable del mal uso.")
    print("-" * 65)
    print(f"{Fore.YELLOW} Para continuar, escribe 'ACEPTO' (sin comillas):{Style.RESET_ALL}")
    
    try:
        aceptar = input(" > ")
        if aceptar.strip().upper() != "ACEPTO":
            print(f"{Fore.RED}[!] Acceso denegado. Cerrando script.{Style.RESET_ALL}")
            sys.exit()
        else:
            print(f"{Fore.GREEN}[*] Responsabilidad aceptada. Iniciando auditoría...{Style.RESET_ALL}\n")
    except KeyboardInterrupt:
        sys.exit()

def obtener_geo_info(ip):
    """Enriquece la IP con datos de País e ISP."""
    if ip.startswith("192.168.") or ip.startswith("10.") or ip.startswith("127."):
        return "Red Local"
    
    if ip in IP_CACHE:
        return IP_CACHE[ip]
    
    try:
        url = f"http://ip-api.com/json/{ip}?fields=country,isp"
        respuesta = requests.get(url, timeout=2).json()
        info = f"{respuesta.get('country', '?')} - {respuesta.get('isp', '?')}"
        IP_CACHE[ip] = info
        return info
    except:
        return "Geo Error"

def loguear_json(tipo, ip_src, ip_dst, mensaje):
    """Guarda alertas en formato JSON."""
    alerta = {
        "timestamp": time.ctime(),
        "tipo": tipo,
        "origen": ip_src,
        "destino": ip_dst,
        "mensaje": mensaje
    }
    with open(LOG_ALERTAS_JSON, "a") as f:
        json.dump(alerta, f)
        f.write("\n")

def loguear_credencial(protocolo, ip_src, ip_dst, payload):
    """Guarda evidencia sensible en log privado."""
    reporte = f"[{time.ctime()}] PROTOCOLO: {protocolo} | {ip_src} -> {ip_dst}\nDATOS: {payload}\n{'-'*60}\n"
    with open(LOG_CREDENCIALES, "a") as f:
        f.write(reporte)

def analizar_paquete(packet):
    if IP in packet:
        src = packet[IP].src
        dst = packet[IP].dst
        
        # 1. DETECCIÓN DE ESCANEOS (Ignorando puertos ruidosos 22, 443, 53)
        if TCP in packet:
            puertos_seguros = [22, 443, 53]
            if packet[TCP].dport not in puertos_seguros and packet[TCP].sport not in puertos_seguros:
                if packet[TCP].flags == 'S': 
                    geo = obtener_geo_info(src)
                    if "Red Local" not in geo:
                        msg = f"Escaneo SYN a puerto {packet[TCP].dport}"
                        print(f"{Fore.YELLOW}[*] {msg} desde {src} ({geo})")
                        loguear_json("SYN_SCAN", src, dst, msg)

        # 2. DETECCIÓN DE TÚNELES ICMP
        if ICMP in packet and hasattr(packet[ICMP], "load"):
            if len(packet[ICMP].load) > 100:
                print(f"{Fore.RED}[!!!] ALERTA: Ping gigante ({len(packet[ICMP].load)}b) de {src}")
                loguear_json("ICMP_TUNNEL", src, dst, "Posible Exfiltración de Datos")

        # 3. AUDITORÍA DE CREDENCIALES (DLP)
        if TCP in packet and packet.haslayer(Raw):
            if packet[TCP].dport != 22 and packet[TCP].sport != 22:
                try:
                    payload = packet[Raw].load.decode('utf-8', errors='ignore')
                    keywords = ["USER ", "PASS ", "uname=", "password=", "Login"]
                    for key in keywords:
                        if key in payload:
                            print(f"\n{Fore.RED}{Style.BRIGHT}[🚨] CREDENCIALES DETECTADAS: {src} -> {dst}")
                            loguear_credencial(f"TCP/{packet[TCP].dport}", src, dst, payload)
                            loguear_json("CREDENTIAL_LEAK", src, dst, "Texto plano detectado")
                            break
                except:
                    pass

def main():
    advertencia_legal()
    print(f"{Fore.CYAN}--- 🛡️  IDS Monitor Activo v5.0 ---")
    print(f"{Fore.YELLOW}[i] JSON Logs: {LOG_ALERTAS_JSON}")
    print(f"{Fore.RED}[i] Private Logs: {LOG_CREDENCIALES}")
    
    sniff(prn=analizar_paquete, store=0)

if __name__ == "__main__":
    main()