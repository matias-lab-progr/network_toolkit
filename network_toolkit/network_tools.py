# network_toolkit/network_tools.py
"""
Módulo de herramientas de red para Network Toolkit - Comandos básicos de red
"""
from colorama import Fore, Style

from .utils import run_command, run_command_realtime

def ping_target(target, current_os):
    """
    Ejecuta el comando ping hacia un objetivo específico.
    
    Args:
        target (str): IP o dominio a hacer ping
        current_os (str): Sistema operativo detectado ('windows', 'linux', 'darwin')
    
    Returns:
        str: Salida del comando ping
    """
    if current_os == "windows":
        command = f"ping -n 4 {target}"
    else:
        command = f"ping -c 4 {target}"
    
    return run_command(command)

def traceroute_target(target, current_os):
    """
    Ejecuta el comando traceroute/tracert hacia un objetivo específico.
    
    Args:
        target (str): IP o dominio a trazar
        current_os (str): Sistema operativo detectado ('windows', 'linux', 'darwin')
    
    Returns:
        str: Salida del comando traceroute
    """
    if current_os == "windows":
        command = f"tracert -h 15 {target}"
    else:
        command = f"traceroute -m 15 {target}"
    
    print(f"\n[*] Ejecutando Traceroute para {target}:\n")
    return run_command_realtime(command)

def geolocate_ip(ip_address):
    """
    Obtiene información de geolocalización para una dirección IP usando una API gratuita.
    
    Args:
        ip_address (str): Dirección IP a geolocalizar
    
    Returns:
        dict: Información de geolocalización o mensaje de error
    """
    try:
        import requests
        import json
        
        # API gratuita de ipapi.co (1000 consultas/mes gratis)
        response = requests.get(f"http://ipapi.co/{ip_address}/json/", timeout=10)
        
        if response.status_code == 200:
            data = response.json()
            
            # Filtrar información relevante
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
                'asn': data.get('asn', 'N/A')
            }
            
            return location_info
        else:
            return {"error": f"Error en la API: {response.status_code}"}
            
    except Exception as e:
        return {"error": f"Error al geolocalizar IP: {str(e)}"}

def display_geolocation(location_info):
    """
    Muestra la información de geolocalización de forma formateada.
    
    Args:
        location_info (dict): Información de geolocalización
    """
    if 'error' in location_info:
        print(f"{Fore.RED}[!] {location_info['error']}{Style.RESET_ALL}")
        return
    
    print(f"\n{Fore.CYAN}--- INFORMACIÓN DE GEOLOCALIZACIÓN ---{Style.RESET_ALL}")
    print(f"• IP: {location_info['ip']}")
    print(f"• Ubicación: {location_info['city']}, {location_info['region']}, {location_info['country']}")
    print(f"• Código Postal: {location_info['postal']}")
    print(f"• Coordenadas: {location_info['latitude']}, {location_info['longitude']}")
    print(f"• Zona Horaria: {location_info['timezone']}")
    print(f"• Organización: {location_info['org']}")
    print(f"• ASN: {location_info['asn']}")
    print(f"{Fore.CYAN}----------------------------------------{Style.RESET_ALL}")

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
    Muestra los resultados del escaneo de puertos con detección de proveedor.
    """
    if 'error' in scan_info:
        print(f"{Fore.RED}[!] {scan_info['error']}{Style.RESET_ALL}")
        return
    
    print(f"\n{Fore.CYAN}=== RESULTADOS DE ESCANEO DE PUERTOS ==={Style.RESET_ALL}")
    print(f"{Fore.YELLOW}• Puertos escaneados: {Fore.WHITE}{scan_info['total_scanned']}{Style.RESET_ALL}")
    print(f"{Fore.YELLOW}• Puertos abiertos: {Fore.WHITE}{len(scan_info['open_ports'])}{Style.RESET_ALL}")
    
    # ✅ DETECCIÓN DEL PROVEEDOR
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
    
    # Recomendaciones de seguridad
    if scan_info['open_ports']:
        print(f"\n{Fore.RED}🔒 {Fore.WHITE}RECOMENDACIONES DE SEGURIDAD:{Style.RESET_ALL}")
        for port in scan_info['open_ports']:
            if port in [21, 23, 3389]:  # Puertos considerados riesgosos
                print(f"  {Fore.RED}• Puerto {port}: Considerar cerrarlo si no es esencial{Style.RESET_ALL}")
            elif port in [80, 443]:  # Puertos web
                print(f"  {Fore.YELLOW}• Puerto {port}: Asegurar con certificados SSL/TLS{Style.RESET_ALL}")
    
    print(f"\n{Fore.CYAN}============================================={Style.RESET_ALL}")

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
    Detecta el proveedor/organización basado en rangos de IP conocidos.
    """
    try:
        import ipaddress
        from .utils import load_ip_ranges
        
        ip = ipaddress.ip_address(ip_address)
        ip_ranges = load_ip_ranges()
        
        if not ip_ranges:
            # Fallback a información ASN si no hay archivo de rangos
            asn_info = get_detailed_asn_info(ip_address)
            if 'error' not in asn_info and asn_info['org'] != 'N/A':
                return asn_info['org']
            return "Desconocido"
        
        for provider, ranges in ip_ranges.items():
            for range_str in ranges:
                try:
                    network = ipaddress.ip_network(range_str)
                    if ip in network:
                        return provider
                except ValueError:
                    # Ignorar rangos mal formados
                    continue
        
        # Fallback a información ASN
        asn_info = get_detailed_asn_info(ip_address)
        if 'error' not in asn_info and asn_info['org'] != 'N/A':
            return asn_info['org']
        
        return "Desconocido"
        
    except Exception as e:
        return f"Error en detección: {str(e)}"

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
