#!/usr/bin/env python3
import time
import json
import requests
from scapy.all import sniff, IP, TCP, Raw
from colorama import Fore, Style, init

# Inicializar colores
init(autoreset=True)

# Cache de GeoIP para no saturar la API
ip_cache = {}
# Archivo privado para logs sensibles
LOG_FILE = "credenciales_capturadas.log"

def obtener_geo_info(ip):
    """Consulta API para enriquecer datos de IP."""
    if ip.startswith("192.168.") or ip.startswith("10.") or ip.startswith("127."):
        return "Red Local"
    if ip in ip_cache:
        return ip_cache[ip]
    try:
        url = f"http://ip-api.com/json/{ip}?fields=country,isp"
        respuesta = requests.get(url, timeout=2).json()
        info = f"{respuesta.get('country', '?')} - {respuesta.get('isp', '?')}"
        ip_cache[ip] = info
        return info
    except:
        return "Geo Error"

def loguear_credencial(protocolo, ip_src, ip_dst, payload_str):
    """Guarda la evidencia en un archivo privado."""
    timestamp = time.ctime()
    reporte = f"[{timestamp}] PROTOCOLO: {protocolo} | ORIGEN: {ip_src} -> DESTINO: {ip_dst}\nDATOS: {payload_str}\n{'-'*60}\n"
    
    with open(LOG_FILE, "a") as f:
        f.write(reporte)

def analizar_paquete(packet):
    if IP in packet and TCP in packet:
        src = packet[IP].src
        dst = packet[IP].dst
        dport = packet[TCP].dport
        sport = packet[TCP].sport
        
        # Ignorar tráfico SSH (Puerto 22) para evitar bucles de ruido
        if dport == 22 or sport == 22:
            return

        # --- AUDITORÍA DE PROTOCOLOS INSEGUROS ---
        # Verificamos si el paquete tiene carga útil (Datos/Payload)
        if packet.haslayer(Raw):
            try:
                # Intentamos leer el contenido del paquete
                payload = packet[Raw].load.decode('utf-8', errors='ignore')
                
                # Palabras clave típicas de login en texto plano
                keywords = ["USER ", "PASS ", "uname=", "pass=", "password=", "Login"]
                
                # Si encontramos alguna, es una alerta
                for key in keywords:
                    if key in payload:
                        geo = obtener_geo_info(dst) # Geolocalizamos el destino
                        print(f"\n{Fore.RED}{Style.BRIGHT}[🚨] ALERTA CRÍTICA: CREDENCIALES EN TEXTO PLANO DETECTADAS")
                        print(f"    Protocolo/Puerto: {dport}")
                        print(f"    Origen: {src} -> Destino: {dst} ({geo})")
                        print(f"    {Fore.YELLOW}>> Evidencia guardada en {LOG_FILE} <<{Style.RESET_ALL}")
                        
                        loguear_credencial(f"TCP/{dport}", src, dst, payload)
                        break
            except Exception:
                pass 

def main():
    print(f"{Fore.CYAN}--- Auditor de Credenciales (v3.0) Iniciado ---")
    print(f"{Fore.GREEN}[*] Monitorizando tráfico en busca de protocolos inseguros...")
    print(f"{Fore.YELLOW}[!] Logs privados en: {LOG_FILE}")
    
    # Filtramos para no escuchar nuestro propio SSH
    sniff(filter="tcp and not port 22", prn=analizar_paquete, store=0)

if __name__ == "__main__":
    main()