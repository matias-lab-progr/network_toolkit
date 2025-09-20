# network_toolkit/network_tools.py
"""
Módulo de herramientas de red para Network Toolkit - Comandos básicos de red
"""

import re
import platform
import subprocess
import json
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Tuple, Optional, Any
import colorama
from colorama import Fore, Style
from colorama import Fore, Style

from .utils import run_command, run_command_realtime

def ping_target(target: str, current_os: str, count: int = 4) -> str:
    """
    Ejecuta el comando ping según el sistema operativo
    
    Args:
        target: IP o dominio a hacer ping
        current_os: Sistema operativo (linux, macos, windows)
        count: Número de paquetes a enviar (default: 4)
    
    Returns:
        str: Salida cruda del comando ping
    """
    try:
        if current_os in ["linux", "macos"]:
            cmd = ["ping", "-c", str(count), target]
        else:  # windows
            cmd = ["ping", "-n", str(count), target]
        
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
        return result.stdout if result.returncode == 0 else result.stderr
    except subprocess.TimeoutExpired:
        return "Error: Timeout al ejecutar ping"
    except Exception as e:
        return f"Error ejecutando ping: {str(e)}"

def analyse_ping_output(output: str, target: str) -> Tuple[str, Dict[str, Any]]:
    """
    Analiza la salida del comando ping y extrae métricas
    
    Args:
        output: Salida cruda del comando ping
        target: IP o dominio que se hizo ping
    
    Returns:
        Tuple[str, Dict]: Análisis en texto y métricas estructuradas
    """
    metrics = {
        "target": target,
        "timestamp": datetime.now().isoformat(),
        "sent": 0,
        "received": 0,
        "lost": 0,
        "loss_percent": 0.0,
        "rtt_min": 0.0,
        "rtt_avg": 0.0,
        "rtt_max": 0.0,
        "rtt_stddev": 0.0,
        "ttl": 0,
        "reachable": False
    }
    
    analysis_lines = []
    
    # Verificar si el host es alcanzable
    if "Destination Host Unreachable" in output or "100% loss" in output:
        metrics["reachable"] = False
        analysis_lines.append(f"{Fore.RED}❌ Host {target} no alcanzable{Style.RESET_ALL}")
        return "\n".join(analysis_lines), metrics
    
    metrics["reachable"] = True
    analysis_lines.append(f"{Fore.GREEN}✅ Host {target} alcanzable{Style.RESET_ALL}")
    
    # Patrones regex para diferentes sistemas operativos
    # Linux/macOS
    packet_loss_pattern = r"(\d+) packets transmitted, (\d+) received, ([\d.]+)% packet loss"
    rtt_pattern = r"rtt min/avg/max/mdev = ([\d.]+)/([\d.]+)/([\d.]+)/([\d.]+) ms"
    ttl_pattern = r"ttl=(\d+)"
    
    # Windows
    win_packet_loss_pattern = r"Packets: Sent = (\d+), Received = (\d+), Lost = (\d+) .*\(([\d.]+)% loss\)"
    win_rtt_pattern = r"Minimum = ([\d.]+)ms, Maximum = ([\d.]+)ms, Average = ([\d.]+)ms"
    win_ttl_pattern = r"TTL=(\d+)"
    
    # Extraer métricas según el sistema operativo
    if platform.system().lower() != "windows":
        # Linux/macOS
        packet_loss_match = re.search(packet_loss_pattern, output)
        rtt_match = re.search(rtt_pattern, output)
        ttl_match = re.search(ttl_pattern, output)
        
        if packet_loss_match:
            metrics["sent"] = int(packet_loss_match.group(1))
            metrics["received"] = int(packet_loss_match.group(2))
            metrics["lost"] = metrics["sent"] - metrics["received"]
            metrics["loss_percent"] = float(packet_loss_match.group(3))
        
        if rtt_match:
            metrics["rtt_min"] = float(rtt_match.group(1))
            metrics["rtt_avg"] = float(rtt_match.group(2))
            metrics["rtt_max"] = float(rtt_match.group(3))
            metrics["rtt_stddev"] = float(rtt_match.group(4))
        
        if ttl_match:
            metrics["ttl"] = int(ttl_match.group(1))
    else:
        # Windows
        win_packet_loss_match = re.search(win_packet_loss_pattern, output)
        win_rtt_match = re.search(win_rtt_pattern, output)
        win_ttl_match = re.search(win_ttl_pattern, output)
        
        if win_packet_loss_match:
            metrics["sent"] = int(win_packet_loss_match.group(1))
            metrics["received"] = int(win_packet_loss_match.group(2))
            metrics["lost"] = int(win_packet_loss_match.group(3))
            metrics["loss_percent"] = float(win_packet_loss_match.group(4))
        
        if win_rtt_match:
            metrics["rtt_min"] = float(win_rtt_match.group(1))
            metrics["rtt_max"] = float(win_rtt_match.group(2))
            metrics["rtt_avg"] = float(win_rtt_match.group(3))
        
        if win_ttl_match:
            metrics["ttl"] = int(win_ttl_match.group(1))
    
    # Generar análisis en texto
    analysis_lines.append(f"\n{Fore.CYAN}📊 Métricas de Ping:{Style.RESET_ALL}")
    analysis_lines.append(f"  Paquetes enviados: {metrics['sent']}")
    analysis_lines.append(f"  Paquetes recibidos: {metrics['received']}")
    analysis_lines.append(f"  Paquetes perdidos: {metrics['lost']}")
    
    # Evaluar pérdida de paquetes
    loss_color = Fore.GREEN
    loss_comment = "Excelente"
    if metrics["loss_percent"] > 5:
        loss_color = Fore.YELLOW
        loss_comment = "Aceptable"
    if metrics["loss_percent"] > 15:
        loss_color = Fore.RED
        loss_comment = "Alta - Problemas de conectividad"
    
    analysis_lines.append(f"  Pérdida de paquetes: {loss_color}{metrics['loss_percent']}% {loss_comment}{Style.RESET_ALL}")
    
    # Evaluar latencia
    if metrics["rtt_avg"] > 0:
        analysis_lines.append(f"\n{Fore.CYAN}⏱️  Latencia (RTT):{Style.RESET_ALL}")
        analysis_lines.append(f"  Mínimo: {metrics['rtt_min']} ms")
        analysis_lines.append(f"  Promedio: {metrics['rtt_avg']} ms")
        analysis_lines.append(f"  Máximo: {metrics['rtt_max']} ms")
        
        if metrics.get("rtt_stddev", 0) > 0:
            analysis_lines.append(f"  Desviación estándar: {metrics['rtt_stddev']} ms")
            # Calcular jitter (usamos la desviación estándar como aproximación)
            jitter = metrics["rtt_stddev"]
            jitter_color = Fore.GREEN
            jitter_comment = "Estable"
            if jitter > 10:
                jitter_color = Fore.YELLOW
                jitter_comment = "Variable"
            if jitter > 30:
                jitter_color = Fore.RED
                jitter_comment = "Muy variable - Posibles problemas"
            analysis_lines.append(f"  Jitter (variación): {jitter_color}{jitter:.2f} ms {jitter_comment}{Style.RESET_ALL}")
        
        # Evaluar calidad de latencia
        latency_color = Fore.GREEN
        latency_comment = "Excelente"
        if metrics["rtt_avg"] > 100:
            latency_color = Fore.YELLOW
            latency_comment = "Aceptable"
        if metrics["rtt_avg"] > 300:
            latency_color = Fore.RED
            latency_comment = "Alta - Posibles problemas"
        
        analysis_lines.append(f"  Calidad de latencia: {latency_color}{latency_comment}{Style.RESET_ALL}")
    
    # Información TTL
    if metrics["ttl"] > 0:
        analysis_lines.append(f"\n{Fore.CYAN}🔍 TTL (Time to Live):{Style.RESET_ALL}")
        analysis_lines.append(f"  TTL: {metrics['ttl']}")
        # Estimación de saltos (aproximada)
        initial_ttl = 64 if metrics["ttl"] <= 64 else (128 if metrics["ttl"] <= 128 else 255)
        hops = initial_ttl - metrics["ttl"]
        analysis_lines.append(f"  Saltos estimados: {hops}")
    
    # Recomendaciones
    analysis_lines.append(f"\n{Fore.CYAN}💡 Recomendaciones:{Style.RESET_ALL}")
    if metrics["loss_percent"] > 15:
        analysis_lines.append(f"  {Fore.RED}• Investigar posibles problemas de red o congestión{Style.RESET_ALL}")
    if metrics["rtt_avg"] > 300:
        analysis_lines.append(f"  {Fore.YELLOW}• Considerar servidores más cercanos geográficamente{Style.RESET_ALL}")
    if metrics["reachable"] and metrics["loss_percent"] == 0 and metrics["rtt_avg"] < 50:
        analysis_lines.append(f"  {Fore.GREEN}• Conexión excelente, sin problemas detectados{Style.RESET_ALL}")
    
    return "\n".join(analysis_lines), metrics

def traceroute_target(target, current_os=None):
    """
    Ejecuta el comando traceroute/tracert hacia un objetivo específico.
    
    Args:
        target (str): IP o dominio a trazar
        current_os (str): Sistema operativo detectado ('windows', 'linux', 'darwin')
    
    Returns:
        str: Salida del comando traceroute
    """
    if current_os is None:
        current_os = platform.system()

    if current_os == "windows":
        command = f"tracert -h 15 {target}"
    else:
        command = f"traceroute -m 15 {target}"
    
    print(f"\n[*] Ejecutando Traceroute para {target}:\n")
    return run_command_realtime(command)

def geolocate_ip(ip_address: str) -> Tuple[Dict[str, Any], Dict[str, Any]]:
    """
    Obtiene información de geolocalización para una dirección IP y devuelve 
    tanto la información formateada como métricas estructuradas.
    
    Args:
        ip_address (str): Dirección IP a geolocalizar
    
    Returns:
        Tuple[Dict, Dict]: (location_info, metrics)
    """
    try:
        import requests
        import json
        
        # API gratuita de ipapi.co (1000 consultas/mes gratis)
        response = requests.get(f"http://ipapi.co/{ip_address}/json/", timeout=10)
        
        if response.status_code == 200:
            data = response.json()
            
            # Información formateada para mostrar
            location_info = {
                'ip': data.get('ip', 'N/A'),
                'city': data.get('city', 'N/A'),
                'region': data.get('region', 'N/A'),
                'country': data.get('country_name', 'N/A'),
                'postal': data.get('postal', 'N/A'),
                'latitude': data.get('latitude', 'N/A'),
                'longitude': data.get('longitude', 'N/A'),
                'timezone': data.get('timezone', 'N/A'),
                'org': data.get('org', 'N/A'),
                'asn': data.get('asn', 'N/A'),
                'country_code': data.get('country_code', 'N/A')
            }
            
            # Métricas estructuradas para el historial
            metrics = {
                'ip': ip_address,
                'city': location_info['city'],
                'region': location_info['region'],
                'country': location_info['country'],
                'country_code': location_info['country_code'],
                'latitude': location_info['latitude'],
                'longitude': location_info['longitude'],
                'organization': location_info['org'],
                'asn': location_info['asn'],
                'success': True,
                'api_used': 'ipapi.co',
                'timestamp': datetime.now().isoformat()
            }
            
            return location_info, metrics
            
        else:
            error_msg = {"error": f"Error en la API: {response.status_code}"}
            metrics = {
                'ip': ip_address,
                'success': False,
                'error': f"API error {response.status_code}",
                'timestamp': datetime.now().isoformat()
            }
            return error_msg, metrics
            
    except Exception as e:
        error_msg = {"error": f"Error al geolocalizar IP: {str(e)}"}
        metrics = {
            'ip': ip_address,
            'success': False,
            'error': str(e),
            'timestamp': datetime.now().isoformat()
        }
        return error_msg, metrics

def display_geolocation(location_info: Dict[str, Any]) -> str:
    """
    Muestra la información de geolocalización de forma formateada.
    
    Args:
        location_info (dict): Información de geolocalización
    
    Returns:
        str: Análisis formateado
    """
    if 'error' in location_info:
        return f"{Fore.RED}[!] {location_info['error']}{Style.RESET_ALL}"
    
    analysis_lines = []
    analysis_lines.append(f"{Fore.CYAN}--- INFORMACIÓN DE GEOLOCALIZACIÓN ---{Style.RESET_ALL}")
    analysis_lines.append(f"• IP: {location_info['ip']}")
    analysis_lines.append(f"• Ubicación: {location_info['city']}, {location_info['region']}, {location_info['country']}")
    analysis_lines.append(f"• Código Postal: {location_info['postal']}")
    analysis_lines.append(f"• Coordenadas: {location_info['latitude']}, {location_info['longitude']}")
    analysis_lines.append(f"• Zona Horaria: {location_info['timezone']}")
    analysis_lines.append(f"• Organización: {location_info['org']}")
    analysis_lines.append(f"• ASN: {location_info['asn']}")
    
    # Análisis adicional
    analysis_lines.append(f"\n{Fore.CYAN}--- ANÁLISIS GEOGRÁFICO ---{Style.RESET_ALL}")
    
    # Análisis por país
    country_code = location_info.get('country_code', '').upper()
    if country_code:
        analysis_lines.append(f"• País: {location_info['country']} ({country_code})")
        
        # Algunos análisis básicos por región
        if country_code in ['US', 'CA', 'AU', 'GB', 'DE', 'FR', 'JP']:
            analysis_lines.append(f"  {Fore.GREEN}✅ País desarrollado (buena conectividad){Style.RESET_ALL}")
        elif country_code in ['CN', 'RU', 'BR', 'IN']:
            analysis_lines.append(f"  {Fore.YELLOW}⚠️  País con regulaciones específicas de internet{Style.RESET_ALL}")
    
    # Análisis de organización
    org = location_info.get('org', '').lower()
    if any(keyword in org for keyword in ['google', 'amazon', 'azure', 'cloud']):
        analysis_lines.append(f"• Hosting: {Fore.BLUE}☁️  Servicio en la nube{Style.RESET_ALL}")
    elif 'isp' in org or 'internet' in org or 'telecom' in org:
        analysis_lines.append(f"• Proveedor: {Fore.GREEN}📡 ISP/Proveedor de internet{Style.RESET_ALL}")
    
    analysis_lines.append(f"{Fore.CYAN}----------------------------------------{Style.RESET_ALL}")
    
    return "\n".join(analysis_lines)

def get_detailed_asn_info(ip_address):
    """
    Obtiene información técnica del Sistema Autónomo (ASN) sin datos geográficos.
    """
    try:
        import requests
        
        response = requests.get(f"http://ip-api.com/json/{ip_address}", timeout=10)
        
        if response.status_code == 200:
            data = response.json()
            
            if data['status'] == 'success':
                # SOLO información técnica, sin datos geográficos
                asn_info = {
                    'ip': data.get('query', 'N/A'),
                    'asn': data.get('as', 'N/A'),
                    'isp': data.get('isp', 'N/A'),
                    'org': data.get('org', 'N/A'),
                    'asn_number': data.get('as', 'N/A').split(' ')[0] if data.get('as') else 'N/A'
                }
                
                return asn_info
            else:
                return {"error": f"No se pudo obtener información para {ip_address}"}
        else:
            return {"error": f"Error en la API: {response.status_code}"}
            
    except Exception as e:
        return {"error": f"Error obteniendo información ASN: {str(e)}"}

def display_detailed_asn_info(asn_info):
    """
    Muestra la información ASN/BGP puramente técnica con explicaciones educativas.
    """
    if 'error' in asn_info:
        print(f"{Fore.RED}[!] {asn_info['error']}{Style.RESET_ALL}")
        return
    
    print(f"\n{Fore.CYAN}=== INFORMACIÓN TÉCNICA ASN/BGP ==={Style.RESET_ALL}")
    print(f"{Fore.YELLOW}📡 Dirección IP: {Fore.WHITE}{asn_info['ip']}{Style.RESET_ALL}")
    
    # Información del Sistema Autónomo
    print(f"\n{Fore.GREEN}🏢 {Fore.WHITE}SISTEMA AUTÓNOMO (ASN){Style.RESET_ALL}")
    print(f"{Fore.YELLOW}• Número ASN: {Fore.WHITE}{asn_info['asn']}{Style.RESET_ALL}")
    
    if asn_info['asn_number'] != 'N/A':
        print(f"  {Fore.CYAN}  ↳ Identificador único del bloque de IPs")
        print(f"  {Fore.CYAN}  ↳ Administrado por: {asn_info['org']}{Style.RESET_ALL}")
    
    print(f"{Fore.YELLOW}• ISP: {Fore.WHITE}{asn_info['isp']}{Style.RESET_ALL}")
    print(f"  {Fore.CYAN}  ↳ Proveedor de servicios de Internet{Style.RESET_ALL}")
    
    print(f"{Fore.YELLOW}• Organización: {Fore.WHITE}{asn_info['org']}{Style.RESET_ALL}")
    print(f"  {Fore.CYAN}  ↳ Entidad responsable del ASN{Style.RESET_ALL}")
    
    # Explicaciones educativas (¡ESTA PARTE FALTABA!)
    print(f"\n{Fore.MAGENTA}📚 {Fore.WHITE}EXPLICACIÓN:{Style.RESET_ALL}")
    print(f"{Fore.CYAN}• {Fore.WHITE}ASN (Sistema Autónomo):{Style.RESET_ALL}")
    print(f"  {Fore.WHITE}  Un conjunto de redes IP administradas por una organización")
    print(f"  {Fore.WHITE}  bajo una política de enrutamiento única{Style.RESET_ALL}")
    
    print(f"{Fore.CYAN}• {Fore.WHITE}BGP (Border Gateway Protocol):{Style.RESET_ALL}")
    print(f"  {Fore.WHITE}  Protocolo que permite el intercambio de información de")
    print(f"  {Fore.WHITE}  enrutamiento entre sistemas autónomos{Style.RESET_ALL}")
    
    print(f"{Fore.CYAN}• {Fore.WHITE}ISP (Proveedor de Servicios de Internet):{Style.RESET_ALL}")
    print(f"  {Fore.WHITE}  Organización que proporciona acceso a Internet y gestiona")
    print(f"  {Fore.WHITE}  bloques de direcciones IP{Style.RESET_ALL}")
    
    # Recomendación para información geográfica
    print(f"\n{Fore.YELLOW}💡 {Fore.WHITE}Para información geográfica, usa la opción 10")
    print(f"{Fore.YELLOW}   (Geolocalización de IP){Style.RESET_ALL}")
    
    print(f"\n{Fore.CYAN}========================================={Style.RESET_ALL}")

def scan_common_ports(ip_address):
    """
    Escanea puertos comunes de una IP con información educativa.
    """
    try:
        import socket
        
        # Puertos comunes y sus servicios
        common_ports = {
            21: "FTP (File Transfer Protocol)",
            22: "SSH (Secure Shell)",
            23: "Telnet",
            25: "SMTP (Email)",
            53: "DNS (Domain Name System)",
            80: "HTTP (Web)",
            110: "POP3 (Email)",
            143: "IMAP (Email)",
            443: "HTTPS (Secure Web)",
            465: "SMTPS (Secure SMTP)",
            587: "SMTP Submission",
            993: "IMAPS (Secure IMAP)",
            995: "POP3S (Secure POP3)",
            3306: "MySQL Database",
            3389: "RDP (Remote Desktop)",
            5432: "PostgreSQL Database",
            27017: "MongoDB"
        }
        
        open_ports = {}
        
        print(f"{Fore.YELLOW}[*] Escaneando {len(common_ports)} puertos comunes...{Style.RESET_ALL}")
        
        for port, service in common_ports.items():
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                    s.settimeout(1)
                    result = s.connect_ex((ip_address, port))
                    if result == 0:
                        open_ports[port] = service
                        print(f"{Fore.GREEN}   ✅ Puerto {port} abierto - {service}{Style.RESET_ALL}")
                    else:
                        print(f"{Fore.RED}   ❌ Puerto {port} cerrado{Style.RESET_ALL}", end='\r')
            except:
                continue
        
        return {
            'open_ports': open_ports,
            'total_scanned': len(common_ports),
            'ports_info': common_ports
        }
        
    except Exception as e:
        return {"error": f"Error escaneando puertos: {str(e)}"}

def display_port_scan_results(scan_info, ip_address):
    """
    Muestra los resultados del escaneo de puertos con recomendaciones inteligentes.
    """
    if 'error' in scan_info:
        print(f"{Fore.RED}[!] {scan_info['error']}{Style.RESET_ALL}")
        return
    
    print(f"\n{Fore.CYAN}=== RESULTADOS DE ESCANEO DE PUERTOS ==={Style.RESET_ALL}")
    print(f"{Fore.YELLOW}• Puertos escaneados: {Fore.WHITE}{scan_info['total_scanned']}{Style.RESET_ALL}")
    print(f"{Fore.YELLOW}• Puertos abiertos: {Fore.WHITE}{len(scan_info['open_ports'])}{Style.RESET_ALL}")
    
    # Detectar proveedor
    provider = detect_provider(ip_address)
    print(f"{Fore.YELLOW}• Proveedor detectado: {Fore.WHITE}{provider}{Style.RESET_ALL}")
    
    if scan_info['open_ports']:
        print(f"\n{Fore.GREEN}🚪 {Fore.WHITE}PUERTOS ABIERTOS ENCONTRADOS:{Style.RESET_ALL}")
        for port, service in scan_info['open_ports'].items():
            print(f"{Fore.YELLOW}• Puerto {port}: {Fore.WHITE}{service}{Style.RESET_ALL}")
    else:
        print(f"\n{Fore.YELLOW}🔒 {Fore.WHITE}No se encontraron puertos abiertos comunes{Style.RESET_ALL}")
    
    # Explicación educativa
    print(f"\n{Fore.MAGENTA}📚 {Fore.WHITE}EXPLICACIÓN SOBRE PUERTOS:{Style.RESET_ALL}")
    print(f"{Fore.CYAN}• {Fore.WHITE}¿Qué es un puerto de red?{Style.RESET_ALL}")
    print(f"  {Fore.WHITE}  Punto de comunicación que permite a diferentes aplicaciones")
    print(f"  {Fore.WHITE}  intercambiar datos en una red{Style.RESET_ALL}")
    
    print(f"{Fore.CYAN}• {Fore.WHITE}Puertos bien conocidos (0-1023):{Style.RESET_ALL}")
    print(f"  {Fore.WHITE}  Servicios estándar de Internet (HTTP, FTP, SSH, etc.){Style.RESET_ALL}")
    
    print(f"{Fore.CYAN}• {Fore.WHITE}Importancia de la seguridad:{Style.RESET_ALL}")
    print(f"  {Fore.WHITE}  Puertos abiertos pueden representar vectores de ataque")
    print(f"  {Fore.WHITE}  Es importante mantener solo los puertos necesarios abiertos{Style.RESET_ALL}")
    
    # ✅ RECOMENDACIONES INTELIGENTES BASADAS EN PROVEEDOR
    if scan_info['open_ports']:
        print(f"\n{Fore.RED}🔒 {Fore.WHITE}RECOMENDACIONES DE SEGURIDAD:{Style.RESET_ALL}")
    
        for port in scan_info['open_ports']:
            # Puertos riesgosos (siempre alertar)
            if port in [21, 23, 3389, 5900, 135, 139, 445]:
                print(f"  {Fore.RED}• Puerto {port}: ⚠️  RIESGOSO - Cerrar inmediatamente{Style.RESET_ALL}")
        
            # Puerto DNS (especial para DNS públicos)
            elif port == 53:
                if provider in ['Google', 'Cloudflare']:
                    print(f"  {Fore.GREEN}• Puerto {port}: ✅ DNS público ({provider}){Style.RESET_ALL}")
                else:
                    print(f"  {Fore.YELLOW}• Puerto {port}: ⚠️  DNS expuesto - Considerar firewall{Style.RESET_ALL}")
        
            # Puertos web HTTP (siempre recomendar HTTPS)
            elif port == 80:
                if provider in ['Google', 'Cloudflare']:
                    print(f"  {Fore.YELLOW}• Puerto {port}: 🔄 Redirigir a HTTPS ({provider}){Style.RESET_ALL}")
                else:
                    print(f"  {Fore.YELLOW}• Puerto {port}: 🔒 Redirigir a HTTPS{Style.RESET_ALL}")
        
            # Puertos web HTTPS (ok para servidores web)
            elif port == 443:
                if provider in ['Google', 'Cloudflare', 'Amazon AWS', 'Microsoft Azure']:
                    print(f"  {Fore.GREEN}• Puerto {port}: ✅ HTTPS seguro ({provider}){Style.RESET_ALL}")
                else:
                    print(f"  {Fore.YELLOW}• Puerto {port}: 🔒 Verificar certificados SSL/TLS{Style.RESET_ALL}")
        
            # Puerto SSH (contextual)
            elif port == 22:
                if provider in ['Google', 'Amazon AWS', 'Microsoft Azure', 'Cloudflare']:
                    print(f"  {Fore.GREEN}• Puerto {port}: ✅ SSH seguro ({provider}){Style.RESET_ALL}")
                else:
                    print(f"  {Fore.YELLOW}• Puerto {port}: ⚠️  SSH expuesto - Usar claves SSH{Style.RESET_ALL}")
        
            # Otros puertos
            else:
                print(f"  {Fore.YELLOW}• Puerto {port}: 🔍 Revisar si es necesario{Style.RESET_ALL}")

def extended_reverse_dns(ip_address):
    """
    Información extendida de DNS inverso con análisis educativo.
    """
    try:
        import dns.reversename
        import dns.resolver
        import dns.rdatatype
        
        print(f"{Fore.YELLOW}[*] Realizando consultas DNS inversas...{Style.RESET_ALL}")
        
        # Reverse DNS tradicional
        reversed_ip = dns.reversename.from_address(ip_address)
        ptr_records = []
        
        try:
            answers = dns.resolver.resolve(reversed_ip, 'PTR')
            ptr_records = [str(r) for r in answers]
            print(f"{Fore.GREEN}   ✅ PTR records encontrados{Style.RESET_ALL}")
        except:
            ptr_records = ["No encontrado"]
            print(f"{Fore.RED}   ❌ No se encontraron registros PTR{Style.RESET_ALL}")
        
        # Intentar obtener información adicional
        dns_info = {
            'ptr_records': ptr_records,
            'has_ptr': len(ptr_records) > 0 and ptr_records[0] != "No encontrado"
        }
        
        return dns_info
        
    except Exception as e:
        return {"error": f"Error en DNS inverso extendido: {str(e)}"}

def display_extended_dns_info(dns_info, ip_address):
    """
    Muestra la información extendida de DNS con explicaciones.
    """
    if 'error' in dns_info:
        print(f"{Fore.RED}[!] {dns_info['error']}{Style.RESET_ALL}")
        return
    
    print(f"\n{Fore.CYAN}=== INFORMACIÓN EXTENDIDA DNS INVERSO ==={Style.RESET_ALL}")
    print(f"{Fore.YELLOW}📡 Dirección IP: {Fore.WHITE}{ip_address}{Style.RESET_ALL}")
    
    # Información de registros PTR
    print(f"\n{Fore.GREEN}🔁 {Fore.WHITE}REGISTROS PTR (DNS Inverso):{Style.RESET_ALL}")
    for ptr in dns_info['ptr_records']:
        print(f"{Fore.YELLOW}• {Fore.WHITE}{ptr}{Style.RESET_ALL}")
    
    # Análisis de los resultados
    if dns_info['has_ptr']:
        print(f"\n{Fore.GREEN}✅ {Fore.WHITE}La IP tiene registros DNS inversos configurados{Style.RESET_ALL}")
    else:
        print(f"\n{Fore.YELLOW}⚠️  {Fore.WHITE}La IP no tiene registros DNS inversos{Style.RESET_ALL}")
    
    # Explicación educativa
    print(f"\n{Fore.MAGENTA}📚 {Fore.WHITE}EXPLICACIÓN SOBRE DNS INVERSO:{Style.RESET_ALL}")
    print(f"{Fore.CYAN}• {Fore.WHITE}¿Qué es DNS inverso (PTR)?{Style.RESET_ALL}")
    print(f"  {Fore.WHITE}  Traduce una dirección IP a un nombre de dominio")
    print(f"  {Fore.WHITE}  (lo contrario del DNS normal){Style.RESET_ALL}")
    
    print(f"{Fore.CYAN}• {Fore.WHITE}Importancia del DNS inverso:{Style.RESET_ALL}")
    print(f"  {Fore.WHITE}  • Mejora la deliverabilidad de emails")
    print(f"  {Fore.WHITE}  • Ayuda en troubleshooting de red")
    print(f"  {Fore.WHITE}  • Proporciona legitimidad a servidores{Style.RESET_ALL}")
    
    print(f"{Fore.CYAN}• {Fore.WHITE}Configuración típica:{Style.RESET_ALL}")
    print(f"  {Fore.WHITE}  Los registros PTR son configurados por el proveedor")
    print(f"  {Fore.WHITE}  de Internet o administrador del bloque de IPs{Style.RESET_ALL}")
    
    # Recomendaciones
    if not dns_info['has_ptr']:
        print(f"\n{Fore.YELLOW}💡 {Fore.WHITE}RECOMENDACIÓN:{Style.RESET_ALL}")
        print(f"  {Fore.WHITE}  Considerar configurar registros PTR para:")
        print(f"  {Fore.WHITE}  • Servidores de correo")
        print(f"  {Fore.WHITE}  • Servidores públicos")
        print(f"  {Fore.WHITE}  • Infraestructura crítica{Style.RESET_ALL}")
    
    print(f"\n{Fore.CYAN}============================================={Style.RESET_ALL}")

def detect_provider(ip_address):
    """
    Detecta el proveedor/organización y normaliza el nombre.
    """
    try:
        import ipaddress
        from .utils import load_ip_ranges
        
        ip = ipaddress.ip_address(ip_address)
        ip_ranges = load_ip_ranges()
        
        # Primero buscar en los rangos definidos
        if ip_ranges:
            for provider, ranges in ip_ranges.items():
                for range_str in ranges:
                    try:
                        network = ipaddress.ip_network(range_str)
                        if ip in network:
                            return provider  # ← Retorna el nombre normalizado del JSON
                    except ValueError:
                        continue
        
        # Fallback: usar información ASN y normalizar
        asn_info = get_detailed_asn_info(ip_address)
        if 'error' not in asn_info and asn_info['org'] != 'N/A':
            return normalize_provider_name(asn_info['org'])
        
        return "Desconocido"
        
    except Exception as e:
        return f"Error en detección: {str(e)}"

def normalize_provider_name(org_name):
    """
    Normaliza nombres de proveedores para consistencia.
    """
    org_lower = org_name.lower()
    
    # Mapeo de nombres normalizados
    if 'cloudflare' in org_lower:
        return "Cloudflare"
    elif 'google' in org_lower:
        return "Google"
    elif 'amazon' in org_lower or 'aws' in org_lower:
        return "Amazon AWS"
    elif 'microsoft' in org_lower or 'azure' in org_lower:
        return "Microsoft Azure"
    elif 'oracle' in org_lower:
        return "Oracle Cloud"
    elif 'digitalocean' in org_lower:
        return "DigitalOcean"
    elif 'github' in org_lower:
        return "GitHub"
    elif 'facebook' in org_lower:
        return "Facebook"
    
    # Si no coincide, devolver el nombre original
    return org_name

def update_ip_ranges():
    """
    Intenta actualizar los rangos de IP desde una fuente externa.
    """
    try:
        import requests
        from .utils import load_ip_ranges
        
        print(f"{Fore.YELLOW}[*] Intentando actualizar rangos de IP...{Style.RESET_ALL}")
        
        # Aquí podrías agregar URLs de fuentes confiables
        # Por ejemplo: https://www.iana.org/assignments/ipv4-address-space/ipv4-address-space.xhtml
        # O APIs de proveedores de cloud
        
        print(f"{Fore.GREEN}[+] Los rangos se actualizan manualmente editando data/ip_ranges.json{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}[!] Descarga listas actualizadas de: {Style.RESET_ALL}")
        print(f"{Fore.WHITE}   • https://www.iana.org/assignments/ipv4-address-space/{Style.RESET_ALL}")
        print(f"{Fore.WHITE}   • https://bgp.he.net/{Style.RESET_ALL}")
        print(f"{Fore.WHITE}   • Documentación oficial de cada proveedor cloud{Style.RESET_ALL}")
        
        return True
        
    except Exception as e:
        print(f"{Fore.RED}[!] Error en actualización: {str(e)}{Style.RESET_ALL}")
        return False
