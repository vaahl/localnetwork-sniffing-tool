#!/usr/bin/env python3
import time
import json
import requests
from scapy.all import sniff, IP, ICMP, TCP
from colorama import Fore, Style, init

# Inicializar colores
init(autoreset=True)

# Cache para no preguntar mil veces la misma IP a la API
ip_cache = {}

def obtener_geo_info(ip):
    """
    ENRIQUECIMIENTO: Consulta una API para saber país e ISP.
    """
    # Si la IP es privada (local), no gastamos tiempo consultando
    if ip.startswith("192.168.") or ip.startswith("10.") or ip.startswith("127."):
        return "Red Local / Privada"

    # Si ya la consultamos antes, devolvemos lo guardado (ahorra tiempo)
    if ip in ip_cache:
        return ip_cache[ip]

    try:
        # Consultamos la API gratuita de ip-api.com
        url = f"http://ip-api.com/json/{ip}?fields=country,isp"
        respuesta = requests.get(url, timeout=3)
        datos = respuesta.json()
        
        if datos:
            info = f"{datos.get('country', 'Desconocido')} - {datos.get('isp', 'ISP Desconocido')}"
            ip_cache[ip] = info # Guardamos en cache
            return info
    except:
        return "Error al geolocalizar"
    
    return "Datos no disponibles"

def loguear_alerta(mensaje, ip_origen, ip_destino, tipo):
    """
    PERSISTENCIA: Guarda la alerta en un archivo para análisis futuro.
    """
    alerta = {
        "timestamp": time.ctime(),
        "tipo": tipo,
        "origen": ip_origen,
        "destino": ip_destino,
        "mensaje": mensaje
    }
    # Guardamos en un archivo JSON (append mode 'a')
    with open("alertas.json", "a") as f:
        json.dump(alerta, f)
        f.write("\n")

def analizar_trafico(paquete):
    if IP in paquete:
        src = paquete[IP].src
        dst = paquete[IP].dst
        ttl = paquete[IP].ttl
        
        # --- REGLA 1: Detección de Ping de la Muerte ---
        if ICMP in paquete and hasattr(paquete[ICMP], "load"):
            carga = len(paquete[ICMP].load)
            if carga > 100: 
                # Enriquecemos la data antes de imprimir
                geo = obtener_geo_info(src)
                
                print(f"{Fore.RED}[!!!] ALERTA CRÍTICA: Túnel ICMP detectado")
                print(f"      Origen: {src} ({geo})")
                print(f"      Payload: {carga} bytes{Style.RESET_ALL}")
                
                loguear_alerta(f"Payload ICMP grande ({carga}b)", src, dst, "ICMP_TUNNEL")

        # --- REGLA 2: Inspección TCP (SYN) ---
        if TCP in paquete:
            flags = paquete[TCP].flags
            if flags == 'S': # Solo SYN
                puerto = paquete[TCP].dport
                # Solo alertamos puertos sensibles para no llenar la pantalla
                # (SSH, HTTP, HTTPS, DBs, etc)
                puertos_sensibles = [21, 22, 23, 80, 443, 3306, 8080]
                
                if puerto in puertos_sensibles:
                    geo = obtener_geo_info(src)
                    print(f"{Fore.YELLOW}[*] Escaneo detectado en puerto {puerto}")
                    print(f"    IP: {src} -> Ubicación: {geo}{Style.RESET_ALL}")
                    
                    loguear_alerta(f"SYN Scan puerto {puerto}", src, dst, "SYN_SCAN")

def main():
    print(f"{Fore.CYAN}---  IDS v2.0 Iniciado ---")
    print("Guardando logs en 'alertas.json'...")
    try:
        sniff(prn=analizar_trafico, store=0)
    except PermissionError:
        print(f"{Fore.RED}[!] Error: Necesitas sudo.")
    except KeyboardInterrupt:
        print("\n[!] Monitor detenido.")

if __name__ == "__main__":
    main()