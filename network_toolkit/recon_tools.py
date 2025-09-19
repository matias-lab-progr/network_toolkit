# network_toolkit/recon_tools.py
"""
Módulo de reconnaissance para Network Toolkit - Enumeración de subdominios y OSINT
"""
import os
import requests
import dns.resolver
import concurrent.futures
from colorama import Fore, Style
import time
from datetime import datetime

def load_subdomain_wordlist():
    """
    Carga una lista de subdominios comunes para fuerza bruta.
    
    Returns:
        list: Lista de subdominios comunes
    """
    # Lista de subdominios comunes (podemos expandir esto)
    common_subdomains = [
        'www', 'mail', 'ftp', 'localhost', 'webmail', 'smtp', 'pop', 'ns1', 'ns2',
        'webdisk', 'admin', 'forum', 'blog', 'news', 'dev', 'test', 'api', 'cdn',
        'static', 'img', 'images', 'media', 'support', 'help', 'wiki', 'status',
        'shop', 'store', 'payment', 'secure', 'login', 'signin', 'account',
        'download', 'upload', 'files', 'cloud', 'email', 'portal', 'dashboard',
        'cpanel', 'whm', 'webmin', 'server', 'ns', 'dns', 'mx', 'vpn', 'ssh',
        'git', 'svn', 'm', 'mobile', 'app', 'apps', 'demo', 'stage', 'staging',
        'db', 'database', 'internal', 'external', 'backup', 'archive', 'old',
        'new', 'beta', 'alpha', 'live', 'prod', 'production', 'test1', 'test2'
    ]
    
    return common_subdomains

def dns_subdomain_enumeration(domain, wordlist=None, threads=50, timeout=5):
    """
    Enumeración de subdominios mediante fuerza bruta DNS.
    
    Args:
        domain (str): Dominio base a enumerar
        wordlist (list): Lista de subdominios a probar
        threads (int): Número de hilos concurrentes
        timeout (int): Timeout para consultas DNS
    
    Returns:
        dict: Resultados de la enumeración
    """
    if wordlist is None:
        wordlist = load_subdomain_wordlist()
    
    found_subdomains = []
    resolver = dns.resolver.Resolver()
    resolver.timeout = timeout
    resolver.lifetime = timeout
    
    print(f"{Fore.YELLOW}[*] Enumerando {len(wordlist)} subdominios para {domain}{Style.RESET_ALL}")
    print(f"{Fore.YELLOW}[*] Usando {threads} hilos concurrentes...{Style.RESET_ALL}")
    
    def check_subdomain(subdomain):
        try:
            full_domain = f"{subdomain}.{domain}"
            answers = resolver.resolve(full_domain, 'A')
            if answers:
                ips = [str(r) for r in answers]
                return (full_domain, ips)
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.Timeout):
            pass
        except Exception as e:
            # Silenciar otros errores para no saturar output
            pass
        return None
    
    start_time = time.time()
    
    with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as executor:
        future_to_subdomain = {
            executor.submit(check_subdomain, subdomain): subdomain 
            for subdomain in wordlist
        }
        
        for future in concurrent.futures.as_completed(future_to_subdomain):
            result = future.result()
            if result:
                subdomain, ips = result
                found_subdomains.append((subdomain, ips))
                print(f"{Fore.GREEN}[+] {subdomain} → {', '.join(ips)}{Style.RESET_ALL}")
    
    elapsed_time = time.time() - start_time
    
    return {
        'domain': domain,
        'found_subdomains': found_subdomains,
        'total_tested': len(wordlist),
        'elapsed_time': elapsed_time
    }

def passive_subdomain_enumeration(domain):
    """
    Enumeración pasiva de subdominios usando APIs públicas.
    
    Args:
        domain (str): Dominio a enumerar
    
    Returns:
        dict: Subdominios encontrados pasivamente
    """
    # Esta función la implementaremos después con APIs reales
    print(f"{Fore.YELLOW}[!] Enumeración pasiva no implementada aún{Style.RESET_ALL}")
    return {'domain': domain, 'found_subdomains': [], 'method': 'passive'}

def display_subdomain_results(results):
    """
    Muestra los resultados de la enumeración de subdominios.
    
    Args:
        results (dict): Resultados de la enumeración
    """
    print(f"\n{Fore.CYAN}=== RESULTADOS ENUMERACIÓN SUBDOMINIOS ==={Style.RESET_ALL}")
    print(f"{Fore.YELLOW}• Dominio: {Fore.WHITE}{results['domain']}{Style.RESET_ALL}")
    print(f"{Fore.YELLOW}• Subdominios probados: {Fore.WHITE}{results['total_tested']}{Style.RESET_ALL}")
    print(f"{Fore.YELLOW}• Subdominios encontrados: {Fore.WHITE}{len(results['found_subdomains'])}{Style.RESET_ALL}")
    print(f"{Fore.YELLOW}• Tiempo de ejecución: {Fore.WHITE}{results['elapsed_time']:.2f} segundos{Style.RESET_ALL}")
    
    if results['found_subdomains']:
        print(f"\n{Fore.GREEN}🎯 {Fore.WHITE}SUBDOMINIOS ENCONTRADOS:{Style.RESET_ALL}")
        for subdomain, ips in results['found_subdomains']:
            print(f"{Fore.YELLOW}• {Fore.WHITE}{subdomain}{Style.RESET_ALL}")
            for ip in ips:
                print(f"  {Fore.CYAN}  → {ip}{Style.RESET_ALL}")
    else:
        print(f"\n{Fore.YELLOW}🔍 {Fore.WHITE}No se encontraron subdominios{Style.RESET_ALL}")
    
    # Estadísticas y recomendaciones
    success_rate = (len(results['found_subdomains']) / results['total_tested']) * 100
    print(f"\n{Fore.MAGENTA}📊 {Fore.WHITE}ESTADÍSTICAS:{Style.RESET_ALL}")
    print(f"{Fore.YELLOW}• Tasa de éxito: {Fore.WHITE}{success_rate:.2f}%{Style.RESET_ALL}")
    
    if len(results['found_subdomains']) > 0:
        print(f"\n{Fore.BLUE}💡 {Fore.WHITE}RECOMENDACIONES:{Style.RESET_ALL}")
        print(f"{Fore.CYAN}• Verificar configuraciones de cada subdominio{Style.RESET_ALL}")
        print(f"{Fore.CYAN}• Revisar seguridad de aplicaciones expuestas{Style.RESET_ALL}")
        print(f"{Fore.CYAN}• Considerar implementar WAF/CDN{Style.RESET_ALL}")
    
    print(f"\n{Fore.CYAN}============================================={Style.RESET_ALL}")

def passive_subdomain_enumeration(domain):
    """
    Enumeración pasiva de subdominios usando APIs públicas y fuentes OSINT.
    
    Args:
        domain (str): Dominio a enumerar
    
    Returns:
        dict: Subdominios encontrados pasivamente
    """
    print(f"{Fore.YELLOW}[*] Iniciando enumeración pasiva para {domain}{Style.RESET_ALL}")
    print(f"{Fore.YELLOW}[*] Esto puede tomar algunos minutos...{Style.RESET_ALL}")
    
    found_subdomains = []
    methods_used = []
    
    # 1. Certificate Transparency Logs
    try:
        ct_subdomains = _check_certificate_transparency(domain)
        if ct_subdomains:
            found_subdomains.extend(ct_subdomains)
            methods_used.append("Certificate Transparency")
            print(f"{Fore.GREEN}[+] Certificate Transparency: {len(ct_subdomains)} subdominios{Style.RESET_ALL}")
    except Exception as e:
        print(f"{Fore.RED}[-] Error en Certificate Transparency: {str(e)}{Style.RESET_ALL}")
    
    # 2. SecurityTrails API (gratuita con límite)
    try:
        st_subdomains = _check_securitytrails(domain)
        if st_subdomains:
            found_subdomains.extend(st_subdomains)
            methods_used.append("SecurityTrails API")
            print(f"{Fore.GREEN}[+] SecurityTrails: {len(st_subdomains)} subdominios{Style.RESET_ALL}")
    except Exception as e:
        print(f"{Fore.RED}[-] Error en SecurityTrails: {str(e)}{Style.RESET_ALL}")
    
    # 3. HackerTarget API
    try:
        ht_subdomains = _check_hackertarget(domain)
        if ht_subdomains:
            found_subdomains.extend(ht_subdomains)
            methods_used.append("HackerTarget API")
            print(f"{Fore.GREEN}[+] HackerTarget: {len(ht_subdomains)} subdominios{Style.RESET_ALL}")
    except Exception as e:
        print(f"{Fore.RED}[-] Error en HackerTarget: {str(e)}{Style.RESET_ALL}")
    
    # Eliminar duplicados
    unique_subdomains = list(set(found_subdomains))
    
    return {
        'domain': domain,
        'found_subdomains': unique_subdomains,
        'methods_used': methods_used,
        'total_found': len(unique_subdomains)
    }

def _check_certificate_transparency(domain):
    """Consulta Certificate Transparency logs."""
    try:
        import requests
        
        # API de crt.sh (Certificate Transparency)
        url = f"https://crt.sh/?q=%.{domain}&output=json"
        response = requests.get(url, timeout=15)
        
        if response.status_code == 200:
            data = response.json()
            subdomains = set()
            
            for entry in data:
                name = entry.get('name_value', '')
                if name and domain in name:
                    # Limpiar y normalizar subdominios
                    clean_name = name.strip().lower()
                    if '\n' in clean_name:
                        # Algunas entradas tienen múltiples subdominios
                        for sub in clean_name.split('\n'):
                            if domain in sub:
                                subdomains.add(sub)
                    else:
                        subdomains.add(clean_name)
            
            return list(subdomains)
        
    except Exception as e:
        print(f"{Fore.RED}[-] Error en crt.sh: {str(e)}{Style.RESET_ALL}")
    
    return []

def _check_securitytrails(domain):
    """Consulta SecurityTrails API (requiere API key)."""
    try:
        import requests
        
        # Necesitarías una API key gratuita de SecurityTrails
        api_key = "tu_api_key_aqui"  # Se puede hacer configurable
        if api_key == "tu_api_key_aqui":
            print(f"{Fore.YELLOW}[!] Configura tu API key de SecurityTrails{Style.RESET_ALL}")
            return []
        
        url = f"https://api.securitytrails.com/v1/domain/{domain}/subdomains"
        headers = {"APIKEY": api_key}
        response = requests.get(url, headers=headers, timeout=15)
        
        if response.status_code == 200:
            data = response.json()
            subdomains = [f"{sub}.{domain}" for sub in data.get('subdomains', [])]
            return subdomains
            
    except Exception as e:
        print(f"{Fore.RED}[-] Error en SecurityTrails API: {str(e)}{Style.RESET_ALL}")
    
    return []

def _check_hackertarget(domain):
    """Consulta HackerTarget API (gratuita con límites)."""
    try:
        import requests
        
        url = f"https://api.hackertarget.com/hostsearch/?q={domain}"
        response = requests.get(url, timeout=15)
        
        if response.status_code == 200:
            subdomains = []
            for line in response.text.split('\n'):
                if line and ',' in line:
                    subdomain = line.split(',')[0].strip()
                    if subdomain and domain in subdomain:
                        subdomains.append(subdomain)
            return subdomains
            
    except Exception as e:
        print(f"{Fore.RED}[-] Error en HackerTarget API: {str(e)}{Style.RESET_ALL}")
    
    return []

def display_passive_subdomain_results(results):
    """
    Muestra los resultados de la enumeración pasiva.
    """
    print(f"\n{Fore.CYAN}=== RESULTADOS ENUMERACIÓN PASIVA ==={Style.RESET_ALL}")
    print(f"{Fore.YELLOW}• Dominio: {Fore.WHITE}{results['domain']}{Style.RESET_ALL}")
    print(f"{Fore.YELLOW}• Métodos usados: {Fore.WHITE}{', '.join(results['methods_used'])}{Style.RESET_ALL}")
    print(f"{Fore.YELLOW}• Subdominios encontrados: {Fore.WHITE}{results['total_found']}{Style.RESET_ALL}")
    
    if results['found_subdomains']:
        print(f"\n{Fore.GREEN}🎯 {Fore.WHITE}SUBDOMINIOS ENCONTRADOS:{Style.RESET_ALL}")
        for subdomain in sorted(results['found_subdomains']):
            print(f"{Fore.YELLOW}• {Fore.WHITE}{subdomain}{Style.RESET_ALL}")
    else:
        print(f"\n{Fore.YELLOW}🔍 {Fore.WHITE}No se encontraron subdominios{Style.RESET_ALL}")
    
    # Información adicional
    print(f"\n{Fore.MAGENTA}📊 {Fore.WHITE}INFORMACIÓN:{Style.RESET_ALL}")
    print(f"{Fore.CYAN}• La enumeración pasiva usa fuentes públicas{Style.RESET_ALL}")
    print(f"{Fore.CYAN}• Los resultados pueden incluir subdominios históricos{Style.RESET_ALL}")
    print(f"{Fore.CYAN}• Algunas APIs tienen límites de uso{Style.RESET_ALL}")
    
    print(f"\n{Fore.CYAN}============================================={Style.RESET_ALL}")

def certificate_transparency_search(domain):
    """
    Busca subdominios en Certificate Transparency logs usando crt.sh.
    
    Args:
        domain (str): Dominio a buscar en CT logs
    
    Returns:
        dict: Resultados de la búsqueda en CT logs
    """
    print(f"{Fore.YELLOW}[*] Buscando en Certificate Transparency logs...{Style.RESET_ALL}")
    
    try:
        import requests
        import json
        
        # API pública de crt.sh (no requiere API key)
        url = f"https://crt.sh/?q=%.{domain}&output=json"
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
            'Accept': 'application/json'
        }
        
        response = requests.get(url, headers=headers, timeout=30)
        
        if response.status_code == 200:
            data = response.json()
            subdomains = set()
            
            for entry in data:
                # Extraer nombres de los certificados
                names = set()
                
                # Nombre común
                if entry.get('name_value'):
                    names.add(entry['name_value'].strip().lower())
                
                # Nombres alternativos
                if entry.get('subject_alt_name'):
                    alt_names = entry['subject_alt_name'].split('\n')
                    for name in alt_names:
                        if name.strip():
                            names.add(name.strip().lower())
                
                # Filtrar y normalizar subdominios
                for name in names:
                    if domain in name:
                        # Limpiar caracteres extraños y wildcards
                        clean_name = name.replace('*.', '').replace('\\n', '')
                        if clean_name.endswith(domain) and not clean_name.startswith('*'):
                            subdomains.add(clean_name)
            
            # Ordenar y convertir a lista
            sorted_subdomains = sorted(list(subdomains))
            
            return {
                'success': True,
                'domain': domain,
                'subdomains': sorted_subdomains,
                'total_found': len(sorted_subdomains),
                'source': 'crt.sh (Certificate Transparency)',
                'url': f"https://crt.sh/?q=%.{domain}"
            }
            
        else:
            return {
                'success': False,
                'error': f"Error HTTP {response.status_code}",
                'domain': domain
            }
            
    except requests.exceptions.Timeout:
        return {
            'success': False,
            'error': "Timeout en la consulta a crt.sh",
            'domain': domain
        }
    except Exception as e:
        return {
            'success': False,
            'error': f"Error en Certificate Transparency: {str(e)}",
            'domain': domain
        }

def display_ct_results(results):
    """
    Muestra los resultados de Certificate Transparency.
    """
    if not results.get('success'):
        print(f"{Fore.RED}[!] Error: {results.get('error', 'Error desconocido')}{Style.RESET_ALL}")
        return
    
    print(f"\n{Fore.CYAN}=== CERTIFICATE TRANSPARENCY RESULTS ==={Style.RESET_ALL}")
    print(f"{Fore.YELLOW}• Dominio: {Fore.WHITE}{results['domain']}{Style.RESET_ALL}")
    print(f"{Fore.YELLOW}• Fuente: {Fore.WHITE}{results['source']}{Style.RESET_ALL}")
    print(f"{Fore.YELLOW}• Subdominios encontrados: {Fore.WHITE}{results['total_found']}{Style.RESET_ALL}")
    print(f"{Fore.YELLOW}• URL de consulta: {Fore.BLUE}{results['url']}{Style.RESET_ALL}")
    
    if results['subdomains']:
        print(f"\n{Fore.GREEN}🎯 {Fore.WHITE}SUBDOMINIOS ENCONTRADOS:{Style.RESET_ALL}")
        
        # Agrupar por tipo de subdominio para mejor visualización
        common_prefixes = {}
        for subdomain in results['subdomains']:
            # Extraer el primer subnivel
            parts = subdomain.split('.')
            if len(parts) > 2:  # Tiene subdominios
                prefix = parts[0]
                if prefix not in common_prefixes:
                    common_prefixes[prefix] = []
                common_prefixes[prefix].append(subdomain)
            else:
                # Dominio principal o sin subdominios
                print(f"{Fore.YELLOW}• {Fore.WHITE}{subdomain}{Style.RESET_ALL}")
        
        # Mostrar subdominios agrupados
        for prefix, subdomains in common_prefixes.items():
            if len(subdomains) > 1:
                print(f"\n{Fore.MAGENTA}📁 {Fore.WHITE}{prefix}.* ({len(subdomains)}):{Style.RESET_ALL}")
                for subdomain in sorted(subdomains)[:10]:  # Mostrar primeros 10
                    print(f"  {Fore.CYAN}• {Fore.WHITE}{subdomain}{Style.RESET_ALL}")
                if len(subdomains) > 10:
                    print(f"  {Fore.YELLOW}  ... y {len(subdomains) - 10} más{Style.RESET_ALL}")
            else:
                for subdomain in subdomains:
                    print(f"{Fore.YELLOW}• {Fore.WHITE}{subdomain}{Style.RESET_ALL}")
    else:
        print(f"\n{Fore.YELLOW}🔍 {Fore.WHITE}No se encontraron subdominios en CT logs{Style.RESET_ALL}")
    
    # Información educativa
    print(f"\n{Fore.MAGENTA}📚 {Fore.WHITE}INFORMACIÓN SOBRE CERTIFICATE TRANSPARENCY:{Style.RESET_ALL}")
    print(f"{Fore.CYAN}• Los CT logs registran todos los certificados SSL emitidos{Style.RESET_ALL}")
    print(f"{Fore.CYAN}• Revelan subdominios aunque no estén activos DNS{Style.RESET_ALL}")
    print(f"{Fore.CYAN}• Útil para descubrir infrastructure oculta{Style.RESET_ALL}")
    
    # Recomendaciones
    if results['total_found'] > 0:
        print(f"\n{Fore.BLUE}💡 {Fore.WHITE}RECOMENDACIONES:{Style.RESET_ALL}")
        print(f"{Fore.CYAN}• Verificar cada subdominio encontrado{Style.RESET_ALL}")
        print(f"{Fore.CYAN}• Revisar certificados expirados/revocados{Style.RESET_ALL}")
        print(f"{Fore.CYAN}• Considerar attack surface expandido{Style.RESET_ALL}")
    
    print(f"\n{Fore.CYAN}==================================================={Style.RESET_ALL}")

def comprehensive_subdomain_enumeration(domain):
    """
    Enumeración completa de subdominios combinando múltiples métodos.
    """
    print(f"{Fore.YELLOW}[*] Iniciando enumeración completa para {domain}{Style.RESET_ALL}")
    
    all_subdomains = set()
    methods_results = {}
    
    # 1. Certificate Transparency (nuevo)
    print(f"{Fore.YELLOW}[*] Método 1/3: Certificate Transparency...{Style.RESET_ALL}")
    ct_results = certificate_transparency_search(domain)
    methods_results['ct'] = ct_results
    if ct_results.get('success'):
        all_subdomains.update(ct_results['subdomains'])
    
    # 2. Fuerza bruta DNS (existente)
    print(f"{Fore.YELLOW}[*] Método 2/3: Fuerza bruta DNS...{Style.RESET_ALL}")
    dns_results = dns_subdomain_enumeration(domain)
    methods_results['dns'] = dns_results
    if dns_results.get('found_subdomains'):
        for subdomain, ips in dns_results['found_subdomains']:
            all_subdomains.add(subdomain)
    
    # 3. Enumeración pasiva (existente)
    print(f"{Fore.YELLOW}[*] Método 3/3: Enumeración pasiva...{Style.RESET_ALL}")
    passive_results = passive_subdomain_enumeration(domain)
    methods_results['passive'] = passive_results
    if passive_results.get('found_subdomains'):
        all_subdomains.update(passive_results['found_subdomains'])
    
    # Resultados consolidados
    sorted_subdomains = sorted(list(all_subdomains))
    
    # Calcular total_tested para compatibilidad
    total_tested = 0
    if 'dns' in methods_results and methods_results['dns']:
        total_tested = methods_results['dns'].get('total_tested', 
                         methods_results['dns'].get('total_scanned', 73))
    
    return {
        'success': True,
        'domain': domain,
        'found_subdomains': [(sub, []) for sub in sorted_subdomains],  # Formato compatible
        'subdomains': sorted_subdomains,  # Lista plana adicional
        'total_found': len(sorted_subdomains),
        'total_tested': total_tested,  # ← Campo requerido para display_subdomain_results
        'total_scanned': total_tested,  # ← Campo alternativo
        'elapsed_time': 0,  # ← Campo requerido
        'methods': methods_results,
        'summary': {
            'ct_count': len(ct_results.get('subdomains', [])),
            'dns_count': len(dns_results.get('found_subdomains', [])),
            'passive_count': len(passive_results.get('found_subdomains', []))
        }
    }

def display_comprehensive_results(results):
    """
    Muestra resultados de enumeración completa para muchos subdominios.
    """
    print(f"\n{Fore.CYAN}=== ENUMERACIÓN COMPLETA RESULTADOS ==={Style.RESET_ALL}")
    print(f"{Fore.YELLOW}• Dominio: {Fore.WHITE}{results['domain']}{Style.RESET_ALL}")
    print(f"{Fore.YELLOW}• Total subdominios: {Fore.WHITE}{results['total_found']}{Style.RESET_ALL}")
    print(f"{Fore.YELLOW}• Tiempo ejecución: {Fore.WHITE}{results.get('elapsed_time', 0):.2f} segundos{Style.RESET_ALL}")
    
    # Estadísticas por método
    if 'summary' in results:
        print(f"\n{Fore.GREEN}📊 {Fore.WHITE}ESTADÍSTICAS POR MÉTODO:{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}• Certificate Transparency: {Fore.WHITE}{results['summary']['ct_count']}{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}• Fuerza bruta DNS: {Fore.WHITE}{results['summary']['dns_count']}{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}• Fuentes pasivas: {Fore.WHITE}{results['summary']['passive_count']}{Style.RESET_ALL}")
    
    # Para muchos resultados, mostrar resumen en lugar de lista completa
    if results['total_found'] > 30:
        print(f"\n{Fore.GREEN}🎯 {Fore.WHITE}MUESTRA ALEATORIA (30 de {results['total_found']}):{Style.RESET_ALL}")
        import random
        sample_subdomains = random.sample(results['subdomains'], min(30, len(results['subdomains'])))
        for subdomain in sorted(sample_subdomains):
            print(f"{Fore.YELLOW}• {Fore.WHITE}{subdomain}{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}  ... y {results['total_found'] - 30} más{Style.RESET_ALL}")
        
        # Mostrar los más interesantes (subdominios internos/testing)
        interesting_subs = [sub for sub in results['subdomains'] 
                          if any(x in sub for x in ['corp', 'test', 'dev', 'staging', 'sandbox', 'qa'])]
        if interesting_subs:
            print(f"\n{Fore.MAGENTA}🔍 {Fore.WHITE}SUBDOMINIOS INTERESANTES ({len(interesting_subs)}):{Style.RESET_ALL}")
            for subdomain in sorted(interesting_subs)[:10]:
                print(f"{Fore.YELLOW}• {Fore.WHITE}{subdomain}{Style.RESET_ALL}")
            if len(interesting_subs) > 10:
                print(f"{Fore.YELLOW}  ... y {len(interesting_subs) - 10} más{Style.RESET_ALL}")
    else:
        print(f"\n{Fore.GREEN}🎯 {Fore.WHITE}SUBDOMINIOS ENCONTRADOS:{Style.RESET_ALL}")
        for subdomain in results['subdomains']:
            print(f"{Fore.YELLOW}• {Fore.WHITE}{subdomain}{Style.RESET_ALL}")
    
    # Información y recomendaciones
    print(f"\n{Fore.MAGENTA}💡 {Fore.WHITE}RECOMENDACIONES:{Style.RESET_ALL}")
    if results['total_found'] > 100:
        print(f"{Fore.CYAN}• Se encontraron MUCHOS subdominios - revisar cuidadosamente{Style.RESET_ALL}")
    if any('corp' in sub for sub in results['subdomains']):
        print(f"{Fore.CYAN}• Subdominios corporativos encontrados - posible información interna{Style.RESET_ALL}")
    if any(x in sub for sub in results['subdomains'] for x in ['test', 'dev', 'staging']):
        print(f"{Fore.CYAN}• Entornos de testing encontrados - pueden ser menos seguros{Style.RESET_ALL}")
    
    print(f"{Fore.CYAN}• Exportar resultados para análisis detallado{Style.RESET_ALL}")
    
    print(f"\n{Fore.CYAN}==================================================={Style.RESET_ALL}")

    # Comparar con exportaciones previas
    comparison = compare_with_previous_export(results)
    if comparison:
        print(f"\n{Fore.MAGENTA}📈 {Fore.WHITE}COMPARACIÓN CON ANTERIOR ({comparison['previous_file']}):{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}• Anterior: {Fore.WHITE}{comparison['previous_total']} subdominios{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}• Actual: {Fore.WHITE}{comparison['current_total']} subdominios{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}• Nuevos: {Fore.WHITE}{len(comparison['new_subdomains'])}{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}• Eliminados: {Fore.WHITE}{len(comparison['removed_subdomains'])}{Style.RESET_ALL}")
        
        if comparison['new_subdomains']:
            print(f"{Fore.GREEN}🎯 Nuevos subdominios encontrados:{Style.RESET_ALL}")
            for subdomain in comparison['new_subdomains'][:5]:
                print(f"  {Fore.CYAN}• {subdomain}{Style.RESET_ALL}")
            if len(comparison['new_subdomains']) > 5:
                print(f"  {Fore.YELLOW}  ... y {len(comparison['new_subdomains']) - 5} más{Style.RESET_ALL}")
    
    # Opciones de exportación
    print(f"\n{Fore.BLUE}💾 {Fore.WHITE}OPCIONES DE EXPORTACIÓN:{Style.RESET_ALL}")
    print(f"{Fore.CYAN}1. Exportar resultados completos{Style.RESET_ALL}")
    print(f"{Fore.CYAN}2. Exportar solo subdominios nuevos{Style.RESET_ALL}")
    print(f"{Fore.CYAN}3. No exportar{Style.RESET_ALL}")
    
    export_choice = input(f"{Fore.YELLOW}Selecciona opción (1-3): {Style.RESET_ALL}").strip()
    
    if export_choice == '1':
        export_subdomains_to_file(results)
    elif export_choice == '2' and comparison and comparison['new_subdomains']:
        # Exportar solo subdominios nuevos
        new_results = results.copy()
        new_results['subdomains'] = comparison['new_subdomains']
        new_results['total_found'] = len(comparison['new_subdomains'])
        export_subdomains_to_file(new_results, "data/new_subdomains")
    elif export_choice == '2' and not comparison:
        print(f"{Fore.YELLOW}[!] No hay exportación previa para comparar{Style.RESET_ALL}")
    
    # Mostrar exportaciones previas
    previous_exports = list_previous_exports(results.get('domain'))
    if previous_exports:
        print(f"\n{Fore.MAGENTA}📂 {Fore.WHITE}EXPORTACIONES PREVIAS:{Style.RESET_ALL}")
        for export in previous_exports[:3]:  # Mostrar solo las 3 más recientes
            time_str = export['time'].strftime("%Y-%m-%d %H:%M")
            print(f"{Fore.YELLOW}• {export['filename']} ({time_str}) - {export['size']} bytes{Style.RESET_ALL}")
        if len(previous_exports) > 3:
            print(f"{Fore.YELLOW}  ... y {len(previous_exports) - 3} más{Style.RESET_ALL}")

def display_subdomain_results(results):
    """
    Muestra los resultados del escaneo de subdominios (versión mejorada).
    """
    # Si es un resultado comprehensivo, usar display especial
    if 'methods' in results and 'summary' in results:
        display_comprehensive_results(results)
        return
        
    # Versión original para resultados simples
    if 'error' in results:
        print(f"{Fore.RED}[!] {results['error']}{Style.RESET_ALL}")
        return
    
    print(f"\n{Fore.CYAN}=== RESULTADOS ENUMERACIÓN SUBDOMINIOS ==={Style.RESET_ALL}")
    print(f"{Fore.YELLOW}• Dominio: {Fore.WHITE}{results.get('domain', 'N/A')}{Style.RESET_ALL}")
    print(f"{Fore.YELLOW}• Subdominios probados: {Fore.WHITE}{results.get('total_tested', results.get('total_scanned', 'N/A'))}{Style.RESET_ALL}")
    print(f"{Fore.YELLOW}• Subdominios encontrados: {Fore.WHITE}{results.get('total_found', len(results.get('found_subdomains', [])))}{Style.RESET_ALL}")
    print(f"{Fore.YELLOW}• Tiempo de ejecución: {Fore.WHITE}{results.get('elapsed_time', 'N/A')} segundos{Style.RESET_ALL}")
    
    found_subdomains = results.get('found_subdomains', [])
    if found_subdomains:
        print(f"\n{Fore.GREEN}🎯 {Fore.WHITE}SUBDOMINIOS ENCONTRADOS:{Style.RESET_ALL}")
        for subdomain, ips in found_subdomains:
            print(f"{Fore.YELLOW}• {Fore.WHITE}{subdomain}{Style.RESET_ALL}")
            if ips:
                for ip in ips[:3]:  # Mostrar máximo 3 IPs
                    print(f"  {Fore.CYAN}  → {ip}{Style.RESET_ALL}")
                if len(ips) > 3:
                    print(f"  {Fore.YELLOW}  ... y {len(ips) - 3} más{Style.RESET_ALL}")
    else:
        print(f"\n{Fore.YELLOW}🔍 {Fore.WHITE}No se encontraron subdominios{Style.RESET_ALL}")
    
    print(f"\n{Fore.CYAN}============================================={Style.RESET_ALL}")

def get_data_directory():
    """
    Devuelve la ruta correcta a la carpeta data existente.
    """
    # Obtener el directorio actual del módulo
    current_dir = os.path.dirname(os.path.abspath(__file__))
    data_dir = os.path.join(current_dir, 'data')
    return data_dir

def export_subdomains_to_file(results, output_dir=None):
    """
    Exporta los subdominios encontrados a la carpeta data existente.
    """
    try:
        # Usar la carpeta data existente
        if output_dir is None:
            output_dir = get_data_directory()
        
        # Crear directorio si no existe (por si acaso)
        if not os.path.exists(output_dir):
            os.makedirs(output_dir)
            print(f"{Fore.GREEN}[+] Directorio creado: {output_dir}{Style.RESET_ALL}")
        
        domain = results.get('domain', 'subdomains')
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        
        # Nombre de archivo único con timestamp
        filename = f"{domain}_subdomains_{timestamp}.txt"
        filepath = os.path.join(output_dir, filename)
        
        # Verificar si ya existe (aunque es improbable con timestamp)
        counter = 1
        while os.path.exists(filepath):
            filename = f"{domain}_subdomains_{timestamp}_{counter}.txt"
            filepath = os.path.join(output_dir, filename)
            counter += 1
        
        with open(filepath, 'w', encoding='utf-8') as f:
            # Encabezado con metadatos
            f.write(f"# Network Toolkit - Subdomain Enumeration Report\n")
            f.write(f"# Domain: {domain}\n")
            f.write(f"# Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write(f"# Total subdomains: {results.get('total_found', 0)}\n")
            f.write(f"# Methods: CT={results.get('summary', {}).get('ct_count', 0)}, "
                   f"DNS={results.get('summary', {}).get('dns_count', 0)}, "
                   f"Passive={results.get('summary', {}).get('passive_count', 0)}\n")
            f.write("#" + "="*60 + "\n\n")
            
            # Subdominios organizados por categorías
            subdomains = results.get('subdomains', [])
            
            # Separar subdominios interesantes
            corp_subs = [sub for sub in subdomains if 'corp' in sub]
            test_subs = [sub for sub in subdomains if any(x in sub for x in ['test', 'dev', 'staging', 'qa', 'sandbox'])]
            prod_subs = [sub for sub in subdomains if sub not in corp_subs + test_subs]
            
            # Escribir secciones organizadas
            if corp_subs:
                f.write("# CORPORATE/INTERNAL SUBDOMAINS\n")
                f.write("#" + "-"*40 + "\n")
                for subdomain in sorted(corp_subs):
                    f.write(f"{subdomain}\n")
                f.write("\n")
            
            if test_subs:
                f.write("# TESTING/DEVELOPMENT SUBDOMAINS\n")
                f.write("#" + "-"*40 + "\n")
                for subdomain in sorted(test_subs):
                    f.write(f"{subdomain}\n")
                f.write("\n")
            
            f.write("# PRODUCTION SUBDOMAINS\n")
            f.write("#" + "-"*40 + "\n")
            for subdomain in sorted(prod_subs):
                f.write(f"{subdomain}\n")
            
            # Footer con estadísticas
            f.write("\n" + "#" + "="*60 + "\n")
            f.write(f"# STATISTICS:\n")
            f.write(f"# Total: {len(subdomains)}\n")
            f.write(f"# Corporate: {len(corp_subs)}\n")
            f.write(f"# Testing: {len(test_subs)}\n")
            f.write(f"# Production: {len(prod_subs)}\n")
        
        print(f"{Fore.GREEN}[+] Resultados exportados a: {Fore.WHITE}{filepath}{Style.RESET_ALL}")
        return filepath
        
    except Exception as e:
        print(f"{Fore.RED}[!] Error exportando resultados: {str(e)}{Style.RESET_ALL}")
        return None
    
    except Exception as e:
        print(f"{Fore.RED}[!] Error exportando resultados: {str(e)}{Style.RESET_ALL}")
        return None

def list_previous_exports(domain=None, output_dir=None):
    """
    Lista exportaciones previas desde la carpeta data existente.
    """
    if output_dir is None:
        output_dir = get_data_directory()
    
    if not os.path.exists(output_dir):
        return []
    
    try:
        exports = []
        for filename in os.listdir(output_dir):
            if filename.endswith('.txt') and (domain is None or domain in filename):
                filepath = os.path.join(output_dir, filename)
                file_time = os.path.getmtime(filepath)
                exports.append({
                    'filename': filename,
                    'path': filepath,
                    'time': datetime.fromtimestamp(file_time),
                    'size': os.path.getsize(filepath)
                })
        
        # Ordenar por fecha (más reciente primero)
        exports.sort(key=lambda x: x['time'], reverse=True)
        return exports
        
    except Exception as e:
        print(f"{Fore.RED}[!] Error listando exportaciones: {str(e)}{Style.RESET_ALL}")
        return []

def compare_with_previous_export(current_results, output_dir=None):
    """
    Compara resultados actuales con exportaciones previas en data/.
    """
    if output_dir is None:
        output_dir = get_data_directory()
    
    domain = current_results.get('domain')

    if not domain:
        return None
    
    previous_exports = list_previous_exports(domain, output_dir)
    if not previous_exports:
        return None
    
    # Tomar la exportación más reciente
    latest_export = previous_exports[0]
    
    try:
        # Leer subdominios previos
        with open(latest_export['path'], 'r', encoding='utf-8') as f:
            previous_subs = set()
            for line in f:
                line = line.strip()
                if line and not line.startswith('#'):
                    previous_subs.add(line)
        
        current_subs = set(current_results.get('subdomains', []))
        
        # Encontrar diferencias
        new_subs = current_subs - previous_subs
        removed_subs = previous_subs - current_subs
        
        return {
            'previous_total': len(previous_subs),
            'current_total': len(current_subs),
            'new_subdomains': sorted(new_subs),
            'removed_subdomains': sorted(removed_subs),
            'previous_file': latest_export['filename'],
            'previous_time': latest_export['time']
        }
        
    except Exception as e:
        print(f"{Fore.RED}[!] Error comparando con exportación previa: {str(e)}{Style.RESET_ALL}")
        return None



