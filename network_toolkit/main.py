# network_toolkit/main.py
"""
Script principal de Network Toolkit - Punto de entrada de la aplicación
"""

import sys
import platform
from colorama import Fore, Style

from .ssl_tools import display_ssl_analysis, get_ssl_certificate, analyze_ssl_certificate, check_ssl_security

from .dns_tools import (
    dns_lookup,
    comprehensive_dns_scan,
    batch_dns_lookup,
    reverse_dns_lookup,
    handle_trace_dns_option
)

from .network_tools import (
    ping_target,
    traceroute_target
)

from .whois_tools import (
    get_whois_info
)

from .utils import (
    init_colorama,
    is_valid_domain,
    is_valid_target,
    check_optional_dependencies,
    run_command,
    is_valid_ip,
    get_raw_mode_input,
    is_dependency_available
)

from .analysis_tools import (
    analyze_dns_output,
    analyze_traceroute_output,
    analyse_ping_output,
    analyze_whois_output
)

def handle_ping_option(current_os):
    # Maneja la opción de ping
    target = input("Introduce el objetivo (ej. google.com): ").strip()

    # Validar que sea un objetivo válido (IP o dominio)
    if not is_valid_target(target):
        print(f"{Fore.RED}[!] Objetivo no válido. Debe ser una IP o dominio válido.{Style.RESET_ALL}")
        return

    output = ping_target(target, current_os)
    print(f"\n[*] Resultados de Ping para {target}:\n{output}")
    # Usar directamente la función importada
    analysis = analyse_ping_output(output, target)
    print(analysis)

def handle_traceroute_option(current_os):
    # Maneja la opción de traceroute
    target = input("Introduce el objetivo (ej. google.com): ").strip()
    
    output = traceroute_target(target, current_os)
    analysis = analyze_traceroute_output(output, target)
    print(analysis)

def handle_whois_option():
    # Maneja la opción de WHOIS
    target = input("Introduce el objetivo (ej. google.com): ").strip()
    
    # Validar que sea un dominio válido
    if not is_valid_domain(target):
        print(f"{Fore.RED}[!] Nombre de dominio no válido.{Style.RESET_ALL}")
        return
    
    print(f"\n[*] Obteniendo información WHOIS para {target}...")
    
    output = get_whois_info(target)
    print(f"\n[*] Resultado de WHOIS para {target}:\n{output}")
    # Usar directamente la función importada
    whois_analysis = analyze_whois_output(output, target)
    print(whois_analysis)

def handle_dns_lookup_option(current_os):
    # Maneja la opción de DNS lookup básico
    target = input("Introduce el objetivo (ej. google.com): ").strip()

    # Validar que sea un dominio válido
    if not is_valid_domain(target):
        print(f"{Fore.RED}[!] Nombre de dominio no válido.{Style.RESET_ALL}")
        return
    
    print(f"\n[*] Obteniendo información DNS para {target}...")

    if current_os == "windows":
        command = f"nslookup {target}"
    else:
        command = f"dig {target}"
    output = run_command(command)
    print(f"\n[*] Resultado de DNS Lookup para {target}:\n{output}")
    dns_analysis = analyze_dns_output(output, target)
    print(dns_analysis)

def handle_professional_dns_option():
    # Maneja la opción de consulta DNS profesional
    target = input("Introduce el objetivo (ej. google.com): ").strip()
    
    # Validar que sea un dominio válido
    if not is_valid_domain(target):
        print(f"{Fore.RED}[!] Nombre de dominio no válido.{Style.RESET_ALL}")
        return
    
    record_type= input("Tipo de registro (A, AAAA, NS, MX, TXT, CNAME, SOA) [A]: ").strip().upper()

    if not record_type:
        record_type = 'A'
    valid_records = ['A', 'AAAA', 'NS', 'MX', 'TXT', 'CNAME', 'SOA']
    if record_type not in valid_records:
        print(f"{Fore.RED}[!] Tipo de registro no válido. Usando A por defecto.{Style.RESET_ALL}")
        record_type = 'A'
    
    nameserver = input("Servidor DNS específico (opcional, Enter para usar por defecto): ").strip()
    if not nameserver:
        nameserver = None

    # Usar directamente la función importada (sin import interno)
    raw = get_raw_mode_input()
    dns_lookup(target, record_type, nameserver, raw)

def handle_comprehensive_dns_scan():
    # Maneja la opción de escaneo DNS completo
    target = input("Introduce el objetivo (ej. google.com): ").strip()
    
    # Validar que sea un dominio válido
    if not is_valid_domain(target):
        print(f"{Fore.RED}[!] Nombre de dominio no válido.{Style.RESET_ALL}")
        return
    
    nameserver = input("Servidor DNS específico (opcional, Enter para usar por defecto): ").strip()
    if not nameserver:
        nameserver = None
    
    # Usar directamente la función importada (sin import interno)
    raw = get_raw_mode_input()
    comprehensive_dns_scan(target, nameserver, raw)

def handle_batch_dns_lookup():
    # Maneja la opción de consulta DNS por lotes
    filename = input("Ruta al archivo con subdominios: ").strip()
    record_type = input("Tipo de registro (A, AAAA, NS, MX, TXT, CNAME, SOA) [A]: ").strip().upper()
    if not record_type:
        record_type = 'A'
    
    nameserver = input("Servidor DNS específico (opcional, Enter para usar por defecto): ").strip()
    if not nameserver:
        nameserver = None

    # Usar directamente la función importada (sin import interno)
    raw = get_raw_mode_input()
    batch_dns_lookup(filename, record_type, nameserver, raw)

def handle_reverse_dns_lookup():
    # Maneja la opción de consulta DNS inversa
    ip_address = input("Introduce la dirección IP para consulta inversa: ").strip()

    # validar que sea una IP valida
    if not is_valid_ip(ip_address):
        print(f"{Fore.RED}[!] Dirección IP no válida.{Style.RESET_ALL}")
        return
    
    nameserver = input("Servidor DNS específico (opcional, Enter para usar por defecto): ").strip()
    if not nameserver:
        nameserver = None
    
    # Usar directamente la función importada (sin import interno)
    raw = get_raw_mode_input()
    reverse_dns_lookup(ip_address, nameserver, raw)

def handle_geolocation_option():
    """Maneja la opción de geolocalización de IP"""
    ip_address = input("Introduce la dirección IP a geolocalizar: ").strip()

    # Validar que sea una IP válida
    if not is_valid_ip(ip_address):
        print(f"{Fore.RED}[!] Dirección IP no válida.{Style.RESET_ALL}")
        return
    
    from .network_tools import geolocate_ip, display_geolocation
    print(f"\n[*] Geolocalizando IP {ip_address}...")
    
    location_info = geolocate_ip(ip_address)
    display_geolocation(location_info)

def handle_asn_analysis_option():
    """Maneja la opción de análisis ASN/BGP"""
    ip_address = input("Introduce la dirección IP para análisis ASN/BGP: ").strip()

    if not is_valid_ip(ip_address):
        print(f"{Fore.RED}[!] Dirección IP no válida.{Style.RESET_ALL}")
        return
    
    from .network_tools import get_detailed_asn_info, display_detailed_asn_info
    print(f"\n[*] Obteniendo información ASN/BGP para {ip_address}...")
    
    asn_info = get_detailed_asn_info(ip_address)
    display_detailed_asn_info(asn_info)

def handle_port_scan_option():
    """Maneja la opción de escaneo de puertos"""
    ip_address = input("Introduce la dirección IP para escanear puertos: ").strip()

    if not is_valid_ip(ip_address):
        print(f"{Fore.RED}[!] Dirección IP no válida.{Style.RESET_ALL}")
        return
    
    from .network_tools import scan_common_ports, display_port_scan_results
    print(f"\n[*] Iniciando escaneo de puertos para {ip_address}...")
    
    print(f"{Fore.YELLOW}[!] Esto puede tomar algunos segundos...{Style.RESET_ALL}")
    
    scan_info = scan_common_ports(ip_address)
    display_port_scan_results(scan_info, ip_address)

def handle_extended_dns_option():
    """Maneja la opción de DNS inverso extendido"""
    ip_address = input("Introduce la dirección IP para análisis DNS inverso: ").strip()

    if not is_valid_ip(ip_address):
        print(f"{Fore.RED}[!] Dirección IP no válida.{Style.RESET_ALL}")
        return
    
    from .network_tools import extended_reverse_dns, display_extended_dns_info
    print(f"\n[*] Realizando análisis DNS inverso para {ip_address}...")
    
    dns_info = extended_reverse_dns(ip_address)
    display_extended_dns_info(dns_info, ip_address)

def handle_update_ip_ranges():
    """Maneja la actualización de rangos de IP"""
    from .network_tools import update_ip_ranges
    update_ip_ranges()

def handle_ssl_analysis_option():
    """Maneja la opción de análisis SSL"""
    domain = input("Introduce el dominio para análisis SSL: ").strip()

    if not is_valid_domain(domain):
        print(f"{Fore.RED}[!] Dominio no válido.{Style.RESET_ALL}")
        return
    
    print(f"\n[*] Analizando certificado SSL para {domain}...")
    
    # Obtener certificado
    cert_result = get_ssl_certificate(domain)
    if not cert_result['success']:
        print(f"{Fore.RED}[!] {cert_result['error']}{Style.RESET_ALL}")
        return
    
    # Analizar certificado
    ssl_info = analyze_ssl_certificate(cert_result['certificate'])
    if not ssl_info.get('success', True):
        print(f"{Fore.RED}[!] {ssl_info['error']}{Style.RESET_ALL}")
        return
    
    # Evaluar seguridad
    security = check_ssl_security(ssl_info, cert_result['cipher'])
    
    # Mostrar resultados
    results = {
        'success': True,
        'ssl_info': ssl_info,
        'security': security,
        'cipher': cert_result['cipher'],
        'version': cert_result['version']
    }
    
    display_ssl_analysis(results, domain)

def main():
    # Inicializar colorama de manera segura
    Fore, Style = init_colorama()
    
    print(f"{Fore.BLUE}[*] Sistema Operativo detectado: {platform.system()}{Style.RESET_ALL}")
    
    # Verificar dependencias opcionales
    print(f"{Fore.BLUE}[*] Verificando dependencias opcionales...{Style.RESET_ALL}")
    check_optional_dependencies()
    print()

    # Detección del SO
    current_os = platform.system().lower()
    print(f" [*] Sistema Operativo detectado: {current_os}")

    while True:
        print("\n--- Kit de Herramientas de Red ---")
        print("1. Ping")
        print("2. Traceroute")
        print("3. WHOIS")
        print("4. DNS Lookup (dig/nslookup)")
        print("5. Consulta DNS Profesional")
        print("6. Escaneo DNS Completo")
        print("7. Consulta DNS por Lotes")
        print("8. Consulta DNS Inversa (PTR)")
        print("9. Trace DNS (Resolución paso a paso)")
        print("10. Geolocalización de IP")
        print("11. Análisis ASN/BGP")
        print("12. Escaneo de Puertos")
        print("13. DNS Inverso ExtendidoP")
        print("14. Actualizar rangos de IP")
        print("15. Análisis SSL/TLS")
        print("16. Salir")
        
        choice = input("\nSelecciona una opción (1-16): ").strip()

        try:
            if choice == '1':
                handle_ping_option(current_os)
            elif choice == '2':
                handle_traceroute_option(current_os)
            elif choice == '3':
                handle_whois_option()
            elif choice == '4':
                handle_dns_lookup_option(current_os)
            elif choice == '5':
                handle_professional_dns_option()
            elif choice == '6':
                handle_comprehensive_dns_scan()
            elif choice == '7':
                handle_batch_dns_lookup()
            elif choice == '8':
                handle_reverse_dns_lookup()
            elif choice == '9':
                handle_trace_dns_option()
            elif choice == '10':
                handle_geolocation_option()
            elif choice == '11':
                handle_asn_analysis_option()
            elif choice == '12':
                handle_port_scan_option()
            elif choice == '13':
                handle_extended_dns_option()
            elif choice == '14':
                handle_update_ip_ranges()
            elif choice == '15':
                handle_ssl_analysis_option()
            elif choice == '16':
                print("¡Saliendo! Hasta luego")
                sys.exit(0)
            else:
                print("Opción no válida. Por favor, elige 1-16.")
        
        except KeyboardInterrupt:
            print("\n\nOperación cancelada por el usuario.")
        except Exception as e:
            print(f"{Fore.RED}[!] Error inesperado: {str(e)}{Style.RESET_ALL}")
            print("Por favor, intenta de nuevo.")

if __name__ == "__main__":
    main()
