# network_toolkit/threat_intel.py
"""
Módulo de Threat Intelligence usando métodos públicos - Sin API keys requeridas
"""

import requests
import re
from colorama import Fore, Style
import time

def get_public_ip_report(ip_address):
    """
    Obtiene información pública de IP usando diversos métodos.
    """
    results = {
        'ip': ip_address,
        'services': {},
        'threat_level': 'unknown',
        'recommendations': []
    }
    
    print(f"{Fore.YELLOW}[*] Analizando IP {ip_address} con métodos públicos...{Style.RESET_ALL}")
    
    # 1. AbuseIPDB (web scraping)
    print(f"{Fore.YELLOW}[*] Consultando AbuseIPDB (público)...{Style.RESET_ALL}")
    abuse_result = check_abuseipdb_public(ip_address)
    results['services']['abuseipdb'] = abuse_result
    
    # 2. VirusTotal (web scraping)
    print(f"{Fore.YELLOW}[*] Consultando VirusTotal (público)...{Style.RESET_ALL}")
    vt_result = check_virustotal_public(ip_address)
    results['services']['virustotal'] = vt_result
    
    # 3. IPinfo (datos básicos)
    print(f"{Fore.YELLOW}[*] Obteniendo información básica de IP...{Style.RESET_ALL}")
    ipinfo_result = get_ipinfo_public(ip_address)
    results['services']['ipinfo'] = ipinfo_result
    
    # 4. Determinar nivel de threat basado en resultados
    threat_score = 0
    
    # Basado en AbuseIPDB
    if abuse_result.get('success') and abuse_result.get('abuse_confidence', 0) > 0:
        threat_score += abuse_result['abuse_confidence']
    
    # Basado en VirusTotal
    if vt_result.get('success') and vt_result.get('detected_malicious', 0) > 0:
        threat_score += vt_result['detected_malicious'] * 10
    
    # Determinar nivel de threat
    if threat_score > 50:
        results['threat_level'] = 'high'
    elif threat_score > 20:
        results['threat_level'] = 'medium'
    elif threat_score > 0:
        results['threat_level'] = 'low'
    else:
        results['threat_level'] = 'clean'
    
    # Generar recomendaciones
    generate_recommendations(results)
    
    return results

def check_abuseipdb_public(ip_address):
    """
    Consulta AbuseIPDB usando web scraping (método público).
    """
    try:
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        }
        
        url = f"https://www.abuseipdb.com/check/{ip_address}"
        response = requests.get(url, headers=headers, timeout=15)
        
        if response.status_code == 200:
            html_content = response.text
            
            # Extraer información con regex
            abuse_confidence = 0
            total_reports = 0
            country = "N/A"
            isp = "N/A"
            
            # Buscar confidence score
            confidence_match = re.search(r'Abuse Confidence Score:.*?(\d+)%', html_content)
            if confidence_match:
                abuse_confidence = int(confidence_match.group(1))
            
            # Buscar total reports
            reports_match = re.search(r'Total reports.*?(\d+)', html_content)
            if reports_match:
                total_reports = int(reports_match.group(1))
            
            # Buscar país
            country_match = re.search(r'Country.*?<td>(.*?)</td>', html_content, re.IGNORECASE)
            if country_match:
                country = country_match.group(1).strip()
            
            # Buscar ISP
            isp_match = re.search(r'ISP.*?<td>(.*?)</td>', html_content, re.IGNORECASE)
            if isp_match:
                isp = isp_match.group(1).strip()
            
            return {
                'success': True,
                'abuse_confidence': abuse_confidence,
                'total_reports': total_reports,
                'country': country,
                'isp': isp,
                'url': url
            }
        else:
            return {'error': f"Error HTTP: {response.status_code}"}
            
    except Exception as e:
        return {'error': f"Error en AbuseIPDB: {str(e)}"}

def check_virustotal_public(ip_address):
    """
    Consulta VirusTotal usando web scraping (método público).
    """
    try:
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        }
        
        url = f"https://www.virustotal.com/gui/ip-address/{ip_address}"
        response = requests.get(url, headers=headers, timeout=15)
        
        if response.status_code == 200:
            html_content = response.text
            
            # Extraer información básica
            detected_malicious = 0
            undetected = 0
            
            # Buscar detecciones (patrón simplificado)
            detection_match = re.search(r'(\d+)\s*security vendors.*?malicious', html_content, re.IGNORECASE)
            if detection_match:
                detected_malicious = int(detection_match.group(1))
            
            return {
                'success': True,
                'detected_malicious': detected_malicious,
                'undetected': undetected,
                'url': url,
                'message': 'Datos limitados disponibles (ver página web completa)'
            }
        else:
            return {'error': f"Error HTTP: {response.status_code}"}
            
    except Exception as e:
        return {'error': f"Error en VirusTotal: {str(e)}"}

def get_ipinfo_public(ip_address):
    """
    Obtiene información básica de IP usando API pública de ipinfo.io.
    """
    try:
        url = f"http://ipinfo.io/{ip_address}/json"
        response = requests.get(url, timeout=10)
        
        if response.status_code == 200:
            data = response.json()
            return {
                'success': True,
                'country': data.get('country', 'N/A'),
                'region': data.get('region', 'N/A'),
                'city': data.get('city', 'N/A'),
                'org': data.get('org', 'N/A'),
                'hostname': data.get('hostname', 'N/A')
            }
        else:
            return {'error': f"Error HTTP: {response.status_code}"}
            
    except Exception as e:
        return {'error': f"Error en ipinfo.io: {str(e)}"}

def generate_recommendations(results):
    """
    Genera recomendaciones basadas en el análisis de threat.
    """
    recommendations = []
    threat_level = results['threat_level']
    
    if threat_level == 'high':
        recommendations.append("🚨 ALTA PROBABILIDAD DE IP MALICIOSA")
        recommendations.append("🔒 Bloquear inmediatamente en firewall")
        recommendations.append("📋 Reportar a autoridades si es necesario")
        
    elif threat_level == 'medium':
        recommendations.append("⚠️  IP CON REPORTES MODERADOS")
        recommendations.append("👀 Monitorear actividad cuidadosamente")
        recommendations.append("🔍 Investigar tráfico desde esta IP")
        
    elif threat_level == 'low':
        recommendations.append("✅ IP CON BAJA REPUTACIÓN")
        recommendations.append("📊 Mantener monitoreo básico")
        
    elif threat_level == 'clean':
        recommendations.append("👍 IP LIMPIA - Sin reportes conocidos")
        recommendations.append("💚 No se requiere acción inmediata")
    
    else:
        recommendations.append("❓ REPUTACIÓN DESCONOCIDA")
        recommendations.append("🔍 No hay suficiente información disponible")
    
    results['recommendations'] = recommendations

def display_threat_intel_results(results):
    """
    Muestra los resultados de threat intelligence.
    """
    print(f"\n{Fore.CYAN}=== THREAT INTELLIGENCE REPORT (PÚBLICO) ==={Style.RESET_ALL}")
    print(f"{Fore.YELLOW}• IP analizada: {Fore.WHITE}{results['ip']}{Style.RESET_ALL}")
    
    # Nivel de threat
    threat_level = results['threat_level']
    threat_display = {
        'high': f"{Fore.RED}ALTO 🚨",
        'medium': f"{Fore.YELLOW}MEDIO ⚠️", 
        'low': f"{Fore.BLUE}BAJO 📊",
        'clean': f"{Fore.GREEN}LIMPIO ✅",
        'unknown': f"{Fore.WHITE}DESCONOCIDO ❓"
    }
    
    print(f"{Fore.YELLOW}• Nivel de amenaza: {threat_display.get(threat_level, 'UNKNOWN')}{Style.RESET_ALL}")
    
    # Resultados de AbuseIPDB
    abuse_data = results['services'].get('abuseipdb', {})
    if abuse_data.get('success'):
        print(f"\n{Fore.GREEN}🛡️  {Fore.WHITE}ABUSEIPDB:{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}• Confidence Score: {Fore.WHITE}{abuse_data.get('abuse_confidence', 0)}%{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}• Reportes totales: {Fore.WHITE}{abuse_data.get('total_reports', 0)}{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}• País: {Fore.WHITE}{abuse_data.get('country', 'N/A')}{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}• ISP: {Fore.WHITE}{abuse_data.get('isp', 'N/A')}{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}• URL: {Fore.BLUE}{abuse_data.get('url', '')}{Style.RESET_ALL}")
    
    # Resultados de VirusTotal
    vt_data = results['services'].get('virustotal', {})
    if vt_data.get('success'):
        print(f"\n{Fore.GREEN}🔍 {Fore.WHITE}VIRUSTOTAL:{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}• Detecciones maliciosas: {Fore.WHITE}{vt_data.get('detected_malicious', 0)}{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}• URL: {Fore.BLUE}{vt_data.get('url', '')}{Style.RESET_ALL}")
        if vt_data.get('message'):
            print(f"{Fore.YELLOW}• Info: {Fore.WHITE}{vt_data.get('message')}{Style.RESET_ALL}")
    
    # Información de IP básica
    ipinfo_data = results['services'].get('ipinfo', {})
    if ipinfo_data.get('success'):
        print(f"\n{Fore.GREEN}🌐 {Fore.WHITE}INFORMACIÓN GEOGRÁFICA:{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}• País: {Fore.WHITE}{ipinfo_data.get('country', 'N/A')}{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}• Región: {Fore.WHITE}{ipinfo_data.get('region', 'N/A')}{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}• Ciudad: {Fore.WHITE}{ipinfo_data.get('city', 'N/A')}{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}• Organización: {Fore.WHITE}{ipinfo_data.get('org', 'N/A')}{Style.RESET_ALL}")
    
    # Recomendaciones
    if results['recommendations']:
        print(f"\n{Fore.MAGENTA}💡 {Fore.WHITE}RECOMENDACIONES:{Style.RESET_ALL}")
        for recommendation in results['recommendations']:
            print(f"  {Fore.CYAN}• {recommendation}{Style.RESET_ALL}")
    
    # Disclaimer
    print(f"\n{Fore.YELLOW}📝 {Fore.WHITE}INFORMACIÓN:{Style.RESET_ALL}")
    print(f"{Fore.CYAN}• Datos obtenidos de fuentes públicas{Style.RESET_ALL}")
    print(f"{Fore.CYAN}• Pueden estar limitados o incompletos{Style.RESET_ALL}")
    print(f"{Fore.CYAN}• Para análisis completo, usar APIs oficiales{Style.RESET_ALL}")
    
    print(f"\n{Fore.CYAN}==================================================={Style.RESET_ALL}")


