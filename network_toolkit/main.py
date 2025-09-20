# network_toolkit/main.py
"""
Script principal de Network Toolkit - Punto de entrada de la aplicación
"""

import json
from datetime import datetime
from pathlib import Path
from typing import Any, Dict
from network_toolkit.history_tools import network_history
import sys
import platform
from colorama import Fore, Style
import re

from .ssl_tools import display_ssl_analysis, get_ssl_certificate, analyze_ssl_certificate, check_ssl_security
from .recon_tools import dns_subdomain_enumeration, display_subdomain_results
from network_toolkit.whois_tools import get_whois_info
from network_toolkit.analysis_tools import analyze_whois_output


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
    analyze_dns_output_simple,
    analyze_traceroute_output,
    analyse_ping_output,
    analyze_whois_output
)

def save_network_report(target: str, tool_type: str, raw_output: str, analysis: str, metrics: Dict[str, Any]) -> None:
    """
    Guarda un reporte de cualquier herramienta de red
    """
    try:
        # Obtener la ruta base del paquete
        base_dir = Path(__file__).parent
        reports_dir = base_dir / "data" / "network_reports"
        reports_dir.mkdir(parents=True, exist_ok=True)
        
        # Crear nombre de archivo seguro
        safe_target = re.sub(r'[<>:"/\\|?*]', '_', target)
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = reports_dir / f"{tool_type}_report_{safe_target}_{timestamp}.txt"
        
        with open(filename, "w", encoding="utf-8") as f:
            f.write(f"Reporte de {tool_type.upper()} - {target}\n")
            f.write(f"Generado: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write("=" * 50 + "\n\n")
            
            f.write("SALIDA CRUDA:\n")
            f.write("=" * 30 + "\n")
            f.write(raw_output + "\n\n")
            
            f.write("ANÁLISIS:\n")
            f.write("=" * 30 + "\n")
            # Remover códigos de color para el archivo de texto
            clean_analysis = re.sub(r'\x1b\[[0-9;]*m', '', analysis)
            f.write(clean_analysis + "\n\n")
            
            f.write("MÉTRICAS (JSON):\n")
            f.write("=" * 30 + "\n")
            f.write(json.dumps(metrics, indent=2) + "\n")
        
        print(f"{Fore.GREEN}✅ Reporte guardado en: {filename}{Style.RESET_ALL}")
        
    except Exception as e:
        print(f"{Fore.RED}❌ Error guardando reporte: {e}{Style.RESET_ALL}")

def handle_ping_option(current_os):
    target = input(f"{Fore.YELLOW}Introduce el objetivo (ej. google.com): {Style.RESET_ALL}").strip()

    # Validar que sea un objetivo válido (IP o dominio)
    if not is_valid_target(target):
        print(f"{Fore.RED}[!] Objetivo no válido. Debe ser una IP o dominio válido.{Style.RESET_ALL}")
        return
    
    # Preguntar por número de paquetes
    try:
        count = int(input(f"{Fore.YELLOW}Número de paquetes (default 4): {Style.RESET_ALL}") or "4")
    except ValueError:
        count = 4
        print(f"{Fore.YELLOW}Usando valor por defecto: 4 paquetes{Style.RESET_ALL}")

    print(f"\n{Fore.CYAN}Realizando ping a {target}...{Style.RESET_ALL}")
    
    output = ping_target(target, current_os, count)
    print(f"\n{Fore.CYAN}Salida cruda:{Style.RESET_ALL}")
    print(output)
    
    # Usar la nueva función que devuelve análisis y métricas
    analysis, metrics = analyse_ping_output(output, target)
    print(f"\n{analysis}")
    
    # Guardar en historial (nuevo sistema)
    if network_history.save_result(target, "ping", metrics):
        print(f"{Fore.GREEN}✅ Resultados guardados en historial{Style.RESET_ALL}")
    else:
        print(f"{Fore.YELLOW}⚠️  No se pudo guardar en historial{Style.RESET_ALL}")
    
    # Preguntar si guardar reporte
    save_report = input(f"\n{Fore.YELLOW}¿Desea guardar un reporte completo? (s/N): {Style.RESET_ALL}").lower()
    if save_report == "s":
        save_network_report(target, "ping", output, analysis, metrics)

def handle_traceroute_option(current_os):
    # Maneja la opción de traceroute
    target = input(f"{Fore.YELLOW}Introduce el objetivo (ej. google.com): {Style.RESET_ALL}").strip()
    
    output = traceroute_target(target, current_os)
    analysis, metrics = analyze_traceroute_output(output, target)  # Cambiada para devolver métricas también
    print(analysis)
    
    # Guardar en historial
    if network_history.save_result(target, "traceroute", metrics):
        print(f"{Fore.GREEN}✅ Resultados de traceroute guardados en historial{Style.RESET_ALL}")
    else:
        print(f"{Fore.YELLOW}⚠️  No se pudo guardar en historial{Style.RESET_ALL}")
    
    # Preguntar si guardar reporte
    save_report = input(f"\n{Fore.YELLOW}¿Desea guardar un reporte completo? (s/N): {Style.RESET_ALL}").lower()
    if save_report == "s":
        save_network_report(target, "traceroute", output, analysis, metrics)

def handle_whois_option():
    # Maneja la opción de WHOIS
    target = input(f"{Fore.YELLOW}Introduce el objetivo (ej. google.com): {Style.RESET_ALL}").strip()
    
    # Validar que sea un dominio válido
    if not is_valid_domain(target):
        print(f"{Fore.RED}[!] Nombre de dominio no válido.{Style.RESET_ALL}")
        return
    
    print(f"\n{Fore.CYAN}Obteniendo información WHOIS para {target}...{Style.RESET_ALL}")
    
    # Obtener información WHOIS
    output, metrics = get_whois_info(target)
    print(f"\n{Fore.CYAN}Resultado de WHOIS para {target}:{Style.RESET_ALL}")
    print(output)
    
    # Analizar la salida
    analysis, enhanced_metrics = analyze_whois_output(output, target)
    print(f"\n{analysis}")
    
    # Combinar métricas
    combined_metrics = {**metrics, **enhanced_metrics}
    
    # Guardar en historial
    if network_history.save_result(target, "whois", combined_metrics):
        print(f"{Fore.GREEN}✅ Resultados de WHOIS guardados en historial{Style.RESET_ALL}")
    else:
        print(f"{Fore.YELLOW}⚠️  No se pudo guardar en historial{Style.RESET_ALL}")
    
    # Preguntar si guardar reporte
    save_report = input(f"\n{Fore.YELLOW}¿Desea guardar un reporte completo? (s/N): {Style.RESET_ALL}").lower()
    if save_report == "s":
        save_network_report(target, "whois", output, analysis, combined_metrics)

def handle_dns_lookup_option(current_os):
    # Maneja la opción de DNS lookup básico
    target = input(f"{Fore.YELLOW}Introduce el objetivo (ej. google.com): {Style.RESET_ALL}").strip()

    # Validar que sea un dominio válido
    if not is_valid_domain(target):
        print(f"{Fore.RED}[!] Nombre de dominio no válido.{Style.RESET_ALL}")
        return
    
    # Preguntar por tipo de registro
    record_type = input(f"{Fore.YELLOW}Tipo de registro (A, AAAA, MX, NS, TXT - default A): {Style.RESET_ALL}").strip().upper()
    if not record_type:
        record_type = "A"
    
    print(f"\n{Fore.CYAN}Obteniendo información DNS para {target} ({record_type})...{Style.RESET_ALL}")

    if current_os == "windows":
        command = f"nslookup -type={record_type} {target}"
    else:
        command = f"dig {target} {record_type} +short"
    
    output = run_command(command)
    print(f"\n{Fore.CYAN}Resultado de DNS Lookup para {target}:{Style.RESET_ALL}")
    print(output)
    
    # Análisis básico (sin métricas complejas)
    analysis = analyze_dns_output_simple(output, target, record_type)
    print(f"\n{analysis}")

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
    ip_address = input(f"{Fore.YELLOW}Introduce la dirección IP a geolocalizar: {Style.RESET_ALL}").strip()

    # Validar que sea una IP válida
    if not is_valid_ip(ip_address):
        print(f"{Fore.RED}[!] Dirección IP no válida.{Style.RESET_ALL}")
        return
    
    from .network_tools import geolocate_ip, display_geolocation
    print(f"\n{Fore.CYAN}Geolocalizando IP {ip_address}...{Style.RESET_ALL}")
    
    # Obtener información de geolocalización
    location_info, metrics = geolocate_ip(ip_address)
    
    # Mostrar información
    analysis = display_geolocation(location_info)
    print(f"\n{analysis}")
    
    # Guardar en historial
    if network_history.save_result(ip_address, "geoip", metrics):
        print(f"{Fore.GREEN}✅ Resultados de geolocalización guardados en historial{Style.RESET_ALL}")
    else:
        print(f"{Fore.YELLOW}⚠️  No se pudo guardar en historial{Style.RESET_ALL}")
    
    # Preguntar si guardar reporte
    save_report = input(f"\n{Fore.YELLOW}¿Desea guardar un reporte completo? (s/N): {Style.RESET_ALL}").lower()
    if save_report == "s":
        # Crear output para el reporte
        output = f"Geolocalización para {ip_address}\n"
        for key, value in location_info.items():
            if key != 'error':
                output += f"{key}: {value}\n"
        
        save_network_report(ip_address, "geoip", output, analysis, metrics)

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

def handle_subdomain_enumeration_option():
    """Maneja la opción de enumeración de subdominios"""
    domain = input("Introduce el dominio para enumerar subdominios: ").strip()

    if not is_valid_domain(domain):
        print(f"{Fore.RED}[!] Dominio no válido.{Style.RESET_ALL}")
        return
    
    # Opciones de enumeración
    print(f"\n{Fore.YELLOW}[*] Selecciona método de enumeración:{Style.RESET_ALL}")
    print("1. Fuerza bruta DNS (rápido)")
    print("2. Enumeración pasiva (más resultados, requiere internet)")
    
    choice = input("Opción (1-2): ").strip()
    
    if choice == '1':
        print(f"\n[*] Iniciando enumeración por fuerza bruta...")
        results = dns_subdomain_enumeration(domain)
        display_subdomain_results(results)
        
    elif choice == '2':
        print(f"\n[*] Iniciando enumeración pasiva...")
        from .recon_tools import passive_subdomain_enumeration, display_passive_subdomain_results
        results = passive_subdomain_enumeration(domain)
        display_passive_subdomain_results(results)
        
    else:
        print(f"{Fore.RED}[!] Opción no válida{Style.RESET_ALL}")

def handle_threat_intel_option():
    """Maneja la opción de threat intelligence con métodos públicos"""
    ip_address = input("Introduce la IP para análisis de threat intelligence: ").strip()

    if not is_valid_ip(ip_address):
        print(f"{Fore.RED}[!] IP no válida.{Style.RESET_ALL}")
        return
    
    from .threat_intel import get_public_ip_report, display_threat_intel_results
    results = get_public_ip_report(ip_address)
    display_threat_intel_results(results)

def handle_ct_search_option():
    """Maneja la opción de búsqueda en Certificate Transparency"""
    domain = input("Introduce el dominio para buscar en CT logs: ").strip()

    if not is_valid_domain(domain):
        print(f"{Fore.RED}[!] Dominio no válido.{Style.RESET_ALL}")
        return
    
    from .recon_tools import certificate_transparency_search, display_ct_results
    print(f"\n[*] Buscando en Certificate Transparency logs para {domain}...")
    
    results = certificate_transparency_search(domain)
    display_ct_results(results)

def handle_comprehensive_subdomain_enum_option():
    """Maneja la enumeración completa de subdominios"""
    domain = input("Introduce el dominio para enumeración completa: ").strip()

    if not is_valid_domain(domain):
        print(f"{Fore.RED}[!] Dominio no válido.{Style.RESET_ALL}")
        return
    
    from .recon_tools import comprehensive_subdomain_enumeration
    print(f"\n[*] Iniciando enumeración completa para {domain}...")
    print(f"{Fore.YELLOW}[!] Esto puede tomar varios minutos...{Style.RESET_ALL}")
    
    results = comprehensive_subdomain_enumeration(domain)
    
    # Usar display mejorado para resultados comprehensivos
    from .recon_tools import display_comprehensive_results
    display_comprehensive_results(results)


# Nueva función para el menú de historial
def handle_network_history_menu():
    while True:
        print(f"\n{Fore.CYAN}=== Historial de Network Toolkit ==={Style.RESET_ALL}")
        print("1. Mostrar historial resumido (todos los tipos)")
        print("2. Mostrar historial detallado de un host")
        print("3. Mostrar historial por tipo de herramienta")
        print("4. Borrar historial")
        print("5. Volver al menú principal")
        
        opcion = input(f"{Fore.YELLOW}Seleccione una opción: {Style.RESET_ALL}")
        
        if opcion == "1":
            show_network_summary()
        elif opcion == "2":
            show_detailed_network_history()
        elif opcion == "3":
            show_history_by_tool_type()
        elif opcion == "4":
            clear_network_history()
        elif opcion == "5":
            break
        else:
            print(f"{Fore.RED}Opción no válida{Style.RESET_ALL}")

# Función para mostrar resumen de todos los tipos
def show_network_summary():
    """Muestra un resumen de todo el historial"""
    summary = network_history.get_history_summary()
    
    if not summary:
        print(f"{Fore.YELLOW}No hay historial guardado{Style.RESET_ALL}")
        return
    
    print(f"\n{Fore.CYAN}📋 Resumen del Historial Completo:{Style.RESET_ALL}")
    print("-" * 100)
    print(f"{'Herramienta':<12} {'Host':<20} {'Última comprobación':<20} {'Estado':<10} {'Métricas':<30}")
    print("-" * 100)
    
    for entry in summary:
        tool_type = entry["tool_type"]
        target = entry["target"]
        last_check = datetime.fromisoformat(entry["last_check"]).strftime("%Y-%m-%d %H:%M") if entry["last_check"] else "N/A"
        
        # Estado según el tipo de herramienta
        status = "N/A"
        metrics_text = ""
        
        if tool_type == "ping":
            status = f"{Fore.GREEN}Alcanzable{Style.RESET_ALL}" if entry.get("reachable") else f"{Fore.RED}Inalcanzable{Style.RESET_ALL}"
            metrics = entry.get("metrics", {})
            loss = metrics.get("loss_percent", "N/A")
            latency = metrics.get("rtt_avg", "N/A")
            metrics_text = f"Pérdida: {loss}%, Latencia: {latency}ms"
        
        elif tool_type == "traceroute":
            status = f"{Fore.GREEN}Completado{Style.RESET_ALL}" if entry.get("reachable") else f"{Fore.YELLOW}Parcial{Style.RESET_ALL}"
            metrics = entry.get("metrics", {})
            hops = metrics.get("total_hops", "N/A")
            max_latency = metrics.get("max_latency", "N/A")
            metrics_text = f"Saltos: {hops}, Máx: {max_latency}ms"
        
        elif tool_type == "whois":
            metrics = entry.get("metrics", {})
            registrar = metrics.get("registrar", "N/A")
            expiration = metrics.get("expiration_date", "N/A")
            
            if metrics.get("success", False):
                status = f"{Fore.GREEN}Consulta exitosa{Style.RESET_ALL}"
            else:
                status = f"{Fore.YELLOW}Consulta parcial{Style.RESET_ALL}"
            
            # Acortar el registrador si es muy largo
            if registrar and len(registrar) > 15:
                registrar = registrar.split(',')[0]
                if len(registrar) > 12:
                    registrar = registrar[:12] + "..."
            
            metrics_text = f"Registrador: {registrar}"
        
        elif tool_type == "geoip":
            metrics = entry.get("metrics", {})
            country = metrics.get("country", "N/A")
            city = metrics.get("city", "N/A")
            org = metrics.get("organization", "N/A")
            
            if metrics.get("success", False):
                status = f"{Fore.GREEN}Localizado{Style.RESET_ALL}"
            else:
                status = f"{Fore.RED}Error{Style.RESET_ALL}"
            
            # Mejorar la visualización del target para GeoIP
            # Intentar mostrar el nombre del servicio en lugar de la IP
            ip = target
            service_name = get_service_name_from_ip(ip)  # Nueva función helper
            display_target = service_name if service_name else ip
            
            # Acortar organización si es muy larga
            if org and len(org) > 20:
                org = org[:17] + "..."
            
            metrics_text = f"Ubicación: {city}, {country}"
            
            # Usar el target mejorado
            target = display_target

        print(f"{tool_type:<12} {target:<20} {last_check:<20} {status:<25} {metrics_text:<30}")

def show_detailed_network_history():
    """Muestra el historial detallado de un host específico"""
    target = input(f"{Fore.YELLOW}Ingrese el host a consultar: {Style.RESET_ALL}").strip()
    
    if not target:
        print(f"{Fore.RED}Debe ingresar un host{Style.RESET_ALL}")
        return
    
    # Obtener todos los resultados para este host
    entries = network_history.load_results(target=target)
    
    if not entries:
        print(f"{Fore.YELLOW}No hay historial para {target}{Style.RESET_ALL}")
        return
    
    print(f"\n{Fore.CYAN}📊 Historial detallado de {target}:{Style.RESET_ALL}")
    print("=" * 80)
    
    for key, history_entries in entries.items():
        # Extraer el tipo de herramienta de la clave
        tool_type = key.split('_')[-1] if '_' in key else "unknown"
        
        print(f"\n{Fore.MAGENTA}🔧 Herramienta: {tool_type.upper()}{Style.RESET_ALL}")
        print("-" * 60)
        
        for i, entry in enumerate(reversed(history_entries), 1):
            timestamp = datetime.fromisoformat(entry["timestamp"]).strftime("%Y-%m-%d %H:%M:%S")
            
            print(f"{Fore.CYAN}Ejecución {i} - {timestamp}{Style.RESET_ALL}")
            
            # Mostrar información según el tipo de herramienta
            if tool_type == "ping":
                if entry.get("reachable", False):
                    print(f"  Estado: {Fore.GREEN}Alcanzable{Style.RESET_ALL}")
                    print(f"  Paquetes: {entry.get('sent', 0)} enviados, {entry.get('received', 0)} recibidos")
                    print(f"  Pérdida: {entry.get('loss_percent', 0)}%")
                    print(f"  Latencia: min={entry.get('rtt_min', 0)}ms, avg={entry.get('rtt_avg', 0)}ms, max={entry.get('rtt_max', 0)}ms")
                    print(f"  TTL: {entry.get('ttl', 'N/A')}")
                else:
                    print(f"  Estado: {Fore.RED}No alcanzable{Style.RESET_ALL}")
            
            elif tool_type == "traceroute":
                reachable = entry.get("reachable", False)
                status = f"{Fore.GREEN}Completado{Style.RESET_ALL}" if reachable else f"{Fore.YELLOW}Parcial{Style.RESET_ALL}"
                print(f"  Estado: {status}")
                print(f"  Saltos totales: {entry.get('total_hops', 0)}")
                print(f"  Saltos con timeout: {entry.get('timeout_hops', 0)}")
                print(f"  Latencia máxima: {entry.get('max_latency', 0)}ms")
            
            elif tool_type == "whois":
                print(f"  Estado: {Fore.BLUE}Consulta exitosa{Style.RESET_ALL}")
                if entry.get("creation_date"):
                    print(f"  - Fecha creación: {entry.get('creation_date')}")
                if entry.get("expiration_date"):
                    print(f"  - Fecha expiración: {entry.get('expiration_date')}")
                    if entry.get("days_until_expiration") is not None:
                        days_left = entry.get("days_until_expiration")
                        status_color = Fore.GREEN if days_left > 365 else Fore.YELLOW if days_left > 30 else Fore.RED
                        print(f"  - Días hasta expiración: {status_color}{days_left}{Style.RESET_ALL}")
                if entry.get("registrar"):
                    print(f"  - Registrador: {entry.get('registrar')}")
                if entry.get("name_servers"):
                    print(f"  - Servidores DNS: {len(entry.get('name_servers', []))} encontrados")
                    for ns in entry.get("name_servers", [])[:3]:  # Mostrar solo los primeros 3
                        print(f"    - {ns}")
                    if len(entry.get("name_servers", [])) > 3:
                        print(f"    - ... y {len(entry.get('name_servers', [])) - 3} más")
                if entry.get("domain_age_years"):
                    print(f"  - Edad del dominio: {entry.get('domain_age_years')} años")
            
            elif tool_type == "geoip":
                if entry.get("success", False):
                    print(f"  Estado: {Fore.GREEN}Localización exitosa{Style.RESET_ALL}")
                    print(f"  - IP: {entry.get('ip', 'N/A')}")
                    print(f"  - Ubicación: {entry.get('city', 'N/A')}, {entry.get('country', 'N/A')}")
                    print(f"  - Coordenadas: {entry.get('latitude', 'N/A')}, {entry.get('longitude', 'N/A')}")
                    print(f"  - Organización: {entry.get('organization', 'N/A')}")
                    print(f"  - ASN: {entry.get('asn', 'N/A')}")
                    print(f"  - País: {entry.get('country_code', 'N/A')}")
                else:
                    print(f"  Estado: {Fore.RED}Error de localización{Style.RESET_ALL}")
                    print(f"  - Error: {entry.get('error', 'Desconocido')}")

            print("-" * 40)

def show_history_by_tool_type():
    """Muestra historial filtrado por tipo de herramienta"""
    print(f"\n{Fore.CYAN}📋 Tipos de herramientas disponibles:{Style.RESET_ALL}")
    print("1. Ping")
    print("2. Traceroute")
    print("3. Whois")
    print("4. GeoIP")
    print("5. Todos los tipos")
    
    tool_choice = input(f"{Fore.YELLOW}Seleccione el tipo: {Style.RESET_ALL}").strip()
    
    tool_type = None
    if tool_choice == "1":
        tool_type = "ping"
    elif tool_choice == "2":
        tool_type = "traceroute"
    elif tool_choice == "3":
        tool_type = "whois"
    elif tool_choice == "4":
        tool_type = "geoip"
    elif tool_choice == "5":
        tool_type = None
    else:
        print(f"{Fore.RED}Opción no válida{Style.RESET_ALL}")
        return
    
    # Obtener resultados filtrados
    entries = network_history.load_results(tool_type=tool_type)
    
    if not entries:
        print(f"{Fore.YELLOW}No hay historial para el tipo seleccionado{Style.RESET_ALL}")
        return
    
    print(f"\n{Fore.CYAN}📊 Historial por tipo {'(' + tool_type + ')' if tool_type else '(todos)'}:{Style.RESET_ALL}")
    print("=" * 80)
    
    for key, history_entries in entries.items():
        # Extraer target y tipo de la clave
        key_parts = key.split('_')
        target = '_'.join(key_parts[:-1])  # Todo excepto el último elemento
        tool = key_parts[-1] if len(key_parts) > 1 else "unknown"
        
        # Mejorar visualización del target para GeoIP
        if tool == "geoip":
            service_name = get_service_name_from_ip(target)
            if service_name:
                display_target = f"{service_name} ({target})"  # ← AMBOS
            else:
                display_target = target
        else:
            display_target = target
        
        if history_entries:
            latest = history_entries[-1]
            timestamp = datetime.fromisoformat(latest["timestamp"]).strftime("%Y-%m-%d %H:%M")
            
            print(f"\n{Fore.MAGENTA}🔧 {tool.upper()} - {display_target}{Style.RESET_ALL}")
            print(f"  Última ejecución: {timestamp}")
            
            # Mostrar métricas resumidas según el tipo
            if tool == "ping":
                reachable = latest.get("reachable", False)
                status = f"{Fore.GREEN}Alcanzable{Style.RESET_ALL}" if reachable else f"{Fore.RED}No alcanzable{Style.RESET_ALL}"
                print(f"  Estado: {status}")
                if reachable:
                    print(f"  Pérdida: {latest.get('loss_percent', 0)}%")
                    print(f"  Latencia avg: {latest.get('rtt_avg', 0)}ms")
            
            elif tool == "traceroute":
                reachable = latest.get("reachable", False)
                status = f"{Fore.GREEN}Completado{Style.RESET_ALL}" if reachable else f"{Fore.YELLOW}Parcial{Style.RESET_ALL}"
                print(f"  Estado: {status}")
                print(f"  Saltos: {latest.get('total_hops', 0)}")
                print(f"  Latencia máx: {latest.get('max_latency', 0)}ms")
            
            elif tool == "whois":
                if latest.get("success", False):
                    print(f"  Estado: {Fore.GREEN}Consulta exitosa{Style.RESET_ALL}")
                    if latest.get("registrar"):
                        print(f"  - Registrador: {latest.get('registrar')}")
                    if latest.get("expiration_date"):
                        print(f"  - Expira: {latest.get('expiration_date')}")
                else:
                    print(f"  Estado: {Fore.YELLOW}Consulta parcial{Style.RESET_ALL}")
            
            elif tool == "geoip":
                if latest.get("success", False):
                    print(f"  Estado: {Fore.GREEN}Localizado{Style.RESET_ALL}")
                    print(f"  - IP: {latest.get('ip', 'N/A')}")  # ← IP EXPLÍCITA
                    print(f"  - Ubicación: {latest.get('city', 'N/A')}, {latest.get('country', 'N/A')}")
                    print(f"  - Organización: {latest.get('organization', 'N/A')}")
                    if latest.get('latitude') and latest.get('longitude'):
                        print(f"  - Coordenadas: {latest.get('latitude')}, {latest.get('longitude')}")
                else:
                    print(f"  Estado: {Fore.RED}Error{Style.RESET_ALL}")
                    print(f"  - Error: {latest.get('error', 'Desconocido')}")

def get_service_name_from_ip(ip_address):
    """
    Intenta obtener el nombre del servicio basado en la IP
    usando una tabla de servicios conocidos.
    """
    known_services = {
        # Google
        '172.217.': 'google.com',
        '142.250.': 'google.com',
        '74.125.': 'google.com',
        # Cloudflare
        '1.1.1.1': 'cloudflare-dns.com',
        '1.0.0.1': 'cloudflare-dns.com',
        # OpenDNS
        '208.67.222.222': 'opendns.com',
        '208.67.220.220': 'opendns.com',
        # Amazon AWS
        '3.': 'aws.amazon.com',
        '52.': 'aws.amazon.com',
        # Microsoft
        '40.': 'microsoft.com',
        '13.': 'microsoft.com',
        # Facebook
        '31.13.': 'facebook.com',
        '157.240.': 'facebook.com',
    }
    
    for ip_prefix, service_name in known_services.items():
        if ip_address.startswith(ip_prefix):
            return service_name
    
    # Si no se encuentra en la lista, hacer reverse DNS (opcional)
    try:
        import socket
        hostname = socket.gethostbyaddr(ip_address)[0]
        if hostname and not hostname.startswith(('ec2-', 'ip-')):  # Excluir nombres genéricos de cloud
            return hostname
    except:
        pass
    
    return None

def clear_network_history():
    """Borra el historial completo o filtrado"""
    print(f"\n{Fore.RED}⚠️  ADVERTENCIA: Esta acción no se puede deshacer{Style.RESET_ALL}")
    print("1. Borrar todo el historial")
    print("2. Borrar historial de un host específico")
    print("3. Borrar historial de un tipo de herramienta")
    print("4. Cancelar")
    
    choice = input(f"{Fore.YELLOW}Seleccione una opción: {Style.RESET_ALL}").strip()
    
    if choice == "4":
        print(f"{Fore.YELLOW}Operación cancelada{Style.RESET_ALL}")
        return
    
    if choice == "1":
        confirm = input(f"{Fore.RED}¿Está seguro de que quiere borrar TODO el historial? (s/N): {Style.RESET_ALL}").lower()
        if confirm == "s":
            if network_history.clear_history():
                print(f"{Fore.GREEN}✅ Historial completo borrado{Style.RESET_ALL}")
            else:
                print(f"{Fore.RED}❌ Error borrando historial{Style.RESET_ALL}")
    
    elif choice == "2":
        target = input(f"{Fore.YELLOW}Ingrese el host a borrar: {Style.RESET_ALL}").strip()
        if target:
            confirm = input(f"{Fore.RED}¿Borrar todo el historial de {target}? (s/N): {Style.RESET_ALL}").lower()
            if confirm == "s":
                if network_history.clear_history(target=target):
                    print(f"{Fore.GREEN}✅ Historial de {target} borrado{Style.RESET_ALL}")
                else:
                    print(f"{Fore.RED}❌ Error borrando historial{Style.RESET_ALL}")
    
    elif choice == "3":
        print("1. Borrar solo ping")
        print("2. Borrar solo traceroute")
        tool_choice = input(f"{Fore.YELLOW}Seleccione el tipo: {Style.RESET_ALL}").strip()
        
        tool_type = None
        if tool_choice == "1":
            tool_type = "ping"
        elif tool_choice == "2":
            tool_type = "traceroute"
        else:
            print(f"{Fore.RED}Opción no válida{Style.RESET_ALL}")
            return
        
        confirm = input(f"{Fore.RED}¿Borrar todo el historial de {tool_type}? (s/N): {Style.RESET_ALL}").lower()
        if confirm == "s":
            if network_history.clear_history(tool_type=tool_type):
                print(f"{Fore.GREEN}✅ Historial de {tool_type} borrado{Style.RESET_ALL}")
            else:
                print(f"{Fore.RED}❌ Error borrando historial{Style.RESET_ALL}")
    
    else:
        print(f"{Fore.RED}Opción no válida{Style.RESET_ALL}")

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
        print(f"\n{Fore.CYAN}=== Network Toolkit ==={Style.RESET_ALL}")
        print("1. Ping a un objetivo")
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
        print("13. DNS Inverso Extendido")
        print("14. Actualizar rangos de IP")
        print("15. Análisis SSL/TLS")
        print("16. Enumeración de Subdominios")
        print("17. Certificate Transparency Search")
        print("18. Enumeración Completa Subdominios")
        print("19. Threat Intelligence (Público)")
        print("20. Historial de Network Toolkit")
        print("0. Salir")
        
        choice = input("\nSelecciona una opción (1-20): ").strip()

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
                handle_subdomain_enumeration_option()
            elif choice == '17':
                handle_ct_search_option()
            elif choice == '18':
                handle_comprehensive_subdomain_enum_option()
            elif choice == '19':
                handle_threat_intel_option()
            elif choice == '20':
                handle_network_history_menu()
            elif choice == '0':
                print("¡Saliendo! Hasta luego")
                sys.exit(0)
            else:
                print("Opción no válida. Por favor, elige 1-20.")
        
        except KeyboardInterrupt:
            print("\n\nOperación cancelada por el usuario.")
        except Exception as e:
            print(f"{Fore.RED}[!] Error inesperado: {str(e)}{Style.RESET_ALL}")
            print("Por favor, intenta de nuevo.")

if __name__ == "__main__":
    main()
