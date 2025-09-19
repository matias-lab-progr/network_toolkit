# network_toolkit/ssl_tools.py
"""
Módulo de análisis SSL/TLS para Network Toolkit - Análisis de certificados y seguridad SSL
"""

import ssl
import socket
import OpenSSL
from datetime import datetime
from colorama import Fore, Style

def get_ssl_certificate(domain, port=443, timeout=10):
    """
    Obtiene el certificado SSL de un dominio.
    
    Args:
        domain (str): Dominio a analizar
        port (int): Puerto SSL (por defecto 443)
        timeout (int): Timeout para la conexión
    
    Returns:
        dict: Información del certificado o error
    """
    try:
        # Crear contexto SSL
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        
        # Conectar y obtener certificado
        with socket.create_connection((domain, port), timeout=timeout) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as ssock:
                cert_der = ssock.getpeercert(binary_form=True)
                cert = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_ASN1, cert_der)
                
                return {
                    'success': True,
                    'certificate': cert,
                    'cipher': ssock.cipher(),
                    'version': ssock.version()
                }
                
    except Exception as e:
        return {
            'success': False,
            'error': f"Error obteniendo certificado: {str(e)}"
        }

def analyze_ssl_certificate(cert):
    """
    Analiza un certificado SSL y extrae información importante.
    
    Args:
        cert: Certificado OpenSSL
    
    Returns:
        dict: Información analizada del certificado
    """
    try:
        # Información del sujeto
        subject = cert.get_subject()
        subject_dict = {}
        for key, value in subject.get_components():
            subject_dict[key.decode()] = value.decode()
        
        # Información del emisor
        issuer = cert.get_issuer()
        issuer_dict = {}
        for key, value in issuer.get_components():
            issuer_dict[key.decode()] = value.decode()
        
        # Fechas de validez
        not_before = cert.get_notBefore().decode('utf-8')
        not_after = cert.get_notAfter().decode('utf-8')
        
        # Convertir fechas a formato legible
        not_before_dt = datetime.strptime(not_before, '%Y%m%d%H%M%SZ')
        not_after_dt = datetime.strptime(not_after, '%Y%m%d%H%M%SZ')
        
        # Días hasta expiración
        days_until_expiry = (not_after_dt - datetime.now()).days
        
        # Información de extensión
        extensions = {}
        for i in range(cert.get_extension_count()):
            ext = cert.get_extension(i)
            extensions[ext.get_short_name().decode()] = str(ext)
        
        return {
            'subject': subject_dict,
            'issuer': issuer_dict,
            'not_before': not_before_dt,
            'not_after': not_after_dt,
            'days_until_expiry': days_until_expiry,
            'serial_number': cert.get_serial_number(),
            'signature_algorithm': cert.get_signature_algorithm().decode(),
            'version': cert.get_version(),
            'extensions': extensions,
            'has_expired': days_until_expiry < 0
        }
        
    except Exception as e:
        return {
            'success': False,
            'error': f"Error analizando certificado: {str(e)}"
        }

def check_ssl_security(ssl_info, cipher_info):
    """
    Evalúa la seguridad SSL basado en best practices.
    
    Args:
        ssl_info: Información del certificado
        cipher_info: Información del cipher suite
    
    Returns:
        dict: Evaluación de seguridad
    """
    security_issues = []
    recommendations = []
    score = 100  # Score inicial
    
    # 1. Verificar expiración
    if ssl_info['days_until_expiry'] < 30:
        security_issues.append(f"Certificado expira en {ssl_info['days_until_expiry']} días")
        score -= 20
    
    if ssl_info['has_expired']:
        security_issues.append("Certificado EXPIRADO")
        score -= 50
    
    # 2. Verificar cipher suite
    cipher, version, bits = cipher_info
    if 'RC4' in cipher or 'DES' in cipher or 'MD5' in cipher:
        security_issues.append(f"Cipher suite débil: {cipher}")
        score -= 30
        recommendations.append("Actualizar a cipher suites modernos (TLS 1.2+)")
    
    # 3. Verificar key length (inferido del cipher)
    if bits and int(bits) < 128:
        security_issues.append(f"Longitud de clave insuficiente: {bits} bits")
        score -= 20
        recommendations.append("Usar claves de al menos 128 bits")
    
    # 4. Verificar SAN (Subject Alternative Names)
    if 'subjectAltName' in ssl_info['extensions']:
        san = ssl_info['extensions']['subjectAltName']
        if 'DNS:' in san:
            recommendations.append("Certificate SAN configurado correctamente")
        else:
            security_issues.append("Faltan nombres alternativos en certificado")
            score -= 10
    else:
        security_issues.append("No hay Subject Alternative Names configurados")
        score -= 15
    
    # 5. Verificar OCSP Stapling
    if 'OCSP' in ssl_info['extensions']:
        recommendations.append("OCSP Stapling configurado")
    else:
        recommendations.append("Considerar implementar OCSP Stapling")
        score -= 5
    
    return {
        'score': max(score, 0),
        'security_issues': security_issues,
        'recommendations': recommendations,
        'grade': get_ssl_grade(score)
    }

def get_ssl_grade(score):
    """Convierte score numérico a grado de seguridad."""
    if score >= 90: return "A+"
    elif score >= 80: return "A"
    elif score >= 70: return "B"
    elif score >= 60: return "C"
    elif score >= 50: return "D"
    else: return "F"

def display_ssl_analysis(results, domain):
    """
    Muestra el análisis SSL de forma formateada.
    """
    if not results.get('success', False):
        print(f"{Fore.RED}[!] {results.get('error', 'Error desconocido')}{Style.RESET_ALL}")
        return
    
    ssl_info = results['ssl_info']
    security = results['security']
    cipher = results['cipher']
    
    print(f"\n{Fore.CYAN}=== ANÁLISIS SSL/TLS PARA {domain.upper()} ==={Style.RESET_ALL}")
    
    # Información básica
    print(f"\n{Fore.GREEN}📄 {Fore.WHITE}INFORMACIÓN DEL CERTIFICADO:{Style.RESET_ALL}")
    print(f"{Fore.YELLOW}• Emisor: {Fore.WHITE}{ssl_info['issuer'].get('CN', 'N/A')}{Style.RESET_ALL}")
    print(f"{Fore.YELLOW}• Válido desde: {Fore.WHITE}{ssl_info['not_before'].strftime('%Y-%m-%d')}{Style.RESET_ALL}")
    print(f"{Fore.YELLOW}• Válido hasta: {Fore.WHITE}{ssl_info['not_after'].strftime('%Y-%m-%d')}{Style.RESET_ALL}")
    print(f"{Fore.YELLOW}• Días hasta expiración: {Fore.WHITE}{ssl_info['days_until_expiry']}{Style.RESET_ALL}")
    
    # Cipher suite
    print(f"\n{Fore.GREEN}🔐 {Fore.WHITE}CONFIGURACIÓN SSL:{Style.RESET_ALL}")
    print(f"{Fore.YELLOW}• Cipher Suite: {Fore.WHITE}{cipher[0]}{Style.RESET_ALL}")
    print(f"{Fore.YELLOW}• Protocolo: {Fore.WHITE}{results['version']}{Style.RESET_ALL}")
    if cipher[2]:  # Bits de encriptación
        print(f"{Fore.YELLOW}• Bits de encriptación: {Fore.WHITE}{cipher[2]}{Style.RESET_ALL}")
    
    # Calificación de seguridad
    print(f"\n{Fore.GREEN}🛡️  {Fore.WHITE}EVALUACIÓN DE SEGURIDAD:{Style.RESET_ALL}")
    grade_display = f"{security['grade']} ({security['score']}/100)"
    if security['grade'] in ['A+', 'A']:
        print(f"{Fore.YELLOW}• Calificación: {Fore.GREEN}{grade_display}{Style.RESET_ALL}")
    elif security['grade'] in ['B', 'C']:
        print(f"{Fore.YELLOW}• Calificación: {Fore.YELLOW}{grade_display}{Style.RESET_ALL}")
    else:
        print(f"{Fore.YELLOW}• Calificación: {Fore.RED}{grade_display}{Style.RESET_ALL}")
    
    # Problemas de seguridad
    if security['security_issues']:
        print(f"\n{Fore.RED}⚠️  {Fore.WHITE}PROBLEMAS DE SEGURIDAD:{Style.RESET_ALL}")
        for issue in security['security_issues']:
            print(f"  {Fore.RED}• {issue}{Style.RESET_ALL}")
    
    # Recomendaciones
    if security['recommendations']:
        print(f"\n{Fore.BLUE}💡 {Fore.WHITE}RECOMENDACIONES:{Style.RESET_ALL}")
        for rec in security['recommendations']:
            print(f"  {Fore.CYAN}• {rec}{Style.RESET_ALL}")
    
    # Información extendida
    print(f"\n{Fore.MAGENTA}🔍 {Fore.WHITE}INFORMACIÓN TÉCNICA DETALLADA:{Style.RESET_ALL}")
    
    # 1. Información del Subject (mejor formateada)
    print(f"\n{Fore.YELLOW}📝 {Fore.WHITE}SUBJECT (Dueño):{Style.RESET_ALL}")
    for key, value in ssl_info['subject'].items():
        print(f"  {Fore.CYAN}{key}: {Fore.WHITE}{value}{Style.RESET_ALL}")
    
    # 2. Información del Issuer (mejor formateada)  
    print(f"\n{Fore.YELLOW}🏢 {Fore.WHITE}ISSUER (Emisor):{Style.RESET_ALL}")
    for key, value in ssl_info['issuer'].items():
        print(f"  {Fore.CYAN}{key}: {Fore.WHITE}{value}{Style.RESET_ALL}")
    
    # 3. Información criptográfica detallada
    print(f"\n{Fore.YELLOW}🔐 {Fore.WHITE}INFORMACIÓN CRIPTOGRÁFICA:{Style.RESET_ALL}")
    print(f"  {Fore.CYAN}Número de serie: {Fore.WHITE}{ssl_info['serial_number']}{Style.RESET_ALL}")
    print(f"  {Fore.CYAN}Algoritmo de firma: {Fore.WHITE}{ssl_info['signature_algorithm']}{Style.RESET_ALL}")
    print(f"  {Fore.CYAN}Versión certificado: {Fore.WHITE}{ssl_info['version'] + 1}{Style.RESET_ALL}")  # OpenSSL usa 0-based
    
    # 4. Extensiones importantes (SAN, Key Usage, etc.)
    print(f"\n{Fore.YELLOW}📋 {Fore.WHITE}EXTENSIONES IMPORTANTES:{Style.RESET_ALL}")
    important_extensions = ['subjectAltName', 'keyUsage', 'extendedKeyUsage', 'basicConstraints']
    for ext in important_extensions:
        if ext in ssl_info['extensions']:
            value = ssl_info['extensions'][ext]
            # Acortar valores muy largos
            if len(value) > 100:
                value = value[:100] + "..."
            print(f"  {Fore.CYAN}{ext}: {Fore.WHITE}{value}{Style.RESET_ALL}")
    
    print(f"\n{Fore.CYAN}============================================={Style.RESET_ALL}")




