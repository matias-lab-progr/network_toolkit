# network_toolkit/dns_tools.py
"""
Módulo de herramientas DNS para Network Toolkit - Consultas DNS profesionales
"""

import time
import dns.resolver
import dns.exception
import dns.reversename
import dns.ipv6
import dns.message
import dns.query
import dns.rdatatype
from colorama import Fore, Style

from .utils import check_network_connectivity, is_valid_domain

def dns_lookup(domain, record_type='A', nameserver=None, raw=False):
    # Realiza consultas DNS profesionales con salida formateada para pentesting
    # Args:
    #   domain (str): dominio a consultar (e.g. "google.com")
    #   record_type (str): tipo de registro DNS (A, AAAA, NS, MX, TXT, CNAME, SOA)
    #   nameserver (str): servidor DNS específico (e.g. "1.1.1.1")
    #   raw (bool): Si True, muestra salida técnica; si False, muestra resumen para pentesting
    # Returns:
    #   list: lista de diccionarios con los resultados de la consulta
    results = []

    try:
        # Configurar el resolver con timeout
        resolver = dns.resolver.Resolver()
        resolver.lifetime = 10  # 10 segundos de timeout
        resolver.timeout = 5    # 5 segundo por consulta

        # Usar el nameserver específico si se proporciona
        if nameserver:
            resolver.nameservers = [nameserver]

        # Realizar la consulta
        answer = resolver.resolve(domain, record_type)

        # Procesar los resultados
        for rdata in answer:
            record_info = {
                'type': record_type,
                'ttl': answer.rrset.ttl if answer.rrset else 'N/A',
                'data': str(rdata),
                'raw': rdata
            }
            results.append(record_info)
        
        # Mostrar salida según el modo
        if raw:
            _display_raw_output(results, domain, record_type)
        else:
            _display_pentesting_output(results, domain, record_type)
        
        print(f"{Fore.GREEN}[-] Consulta finalizada. {len(results)} registros encontrados.{Style.RESET_ALL}")

    except dns.resolver.Timeout:
        print(f"{Fore.RED}[!] Timeout en la consulta DNS después de 10 segundos{Style.RESET_ALL}")
    except dns.resolver.NoAnswer:
        print(f"{Fore.YELLOW}[!] El dominio existe pero no tiene registros {record_type}{Style.RESET_ALL}")
    except dns.resolver.NXDOMAIN:
        print(f"{Fore.RED}[!] El dominio {domain} no existe{Style.RESET_ALL}")
    except dns.exception.DNSException as e:
        print(f"{Fore.RED}[!] Error DNS: {str(e)}{Style.RESET_ALL}")
    except Exception as e:
        print(f"{Fore.RED}[!] Error inesperado: {str(e)}{Style.RESET_ALL}")

    return results

def comprehensive_dns_scan(domain, nameserver=None, raw=False):
    # Realiza un escaneo completo de todos los tipos de registros DNS comunes.
    # Arg:
    #   domain (str): dominio a escanear
    #   nameserver (str): servidor DNS específico
    #   raw (bool): modo de salida (True=técnico, False=pentesting)
    record_types = ['A', 'AAAA', 'NS', 'MX', 'TXT', 'CNAME', 'SOA']
    all_results = {}

    print(f"{Fore.BLUE}\n[+] Iniciando escaneo DNS completo para {domain}{Style.RESET_ALL}")

    for rtype in record_types:
        print(f"\n{Fore.MAGENTA}[*] Consultando {rtype}...{Style.RESET_ALL}")
        result = dns_lookup(domain, rtype, nameserver, raw)
        all_results[rtype] = result

        # Pequeña pausa entre consultas para no saturar
        time.sleep(0.3)
    
    return all_results

def batch_dns_lookup(filename, record_type='A', nameserver=None, raw=False):
    # Realiza consultas DNS por lotes desde un archivo de subdominios.
    # Args:
    #   filename (str): ruta al archivo con subdominios (uno por línea)
    #   record_type (str): tipo de registro a consultar
    #   nameserver (str): servidor DNS específico
    #   raw (bool): modo de salida
    
    try:
        with open(filename, 'r') as f:
            subdomains = [line.strip() for line in f if line.strip()]
        print(f"{Fore.BLUE}[+] Realizando consultas por lotes para {len(subdomains)} subdominios{Style.RESET_ALL}")
        results = {}
        for subdomain in subdomains:
            print(f"\n{Fore.MAGENTA}[*] consultando {subdomain}...{Style.RESET_ALL}")
            result = dns_lookup(subdomain, record_type, nameserver, raw)
            results[subdomain] = result  
            time.sleep(0.2)
            
        return results

    except FileNotFoundError:
        print(f"{Fore.RED}[!] Archivo {filename} no encontrado{Style.RESET_ALL}")
        return {}

def reverse_dns_lookup(ip_address, nameserver=None, raw=False):
    # Realiza una consulta DNS inversa (PTR) para una dirección IP
    # Args:
    #    ip_address (str): dirección IP a consultar
    #    nameserver (str): servidor DNS específico
    #    raw (bool): modo de salida

    try:
        # Convertir IP a formato de búsqueda PTR
        if ':' in ip_address:  # IPv6
            expanded_ip = dns.ipv6.inet_aton(ip_address)
            reversed_ip = dns.reversename.from_address(expanded_ip)
        else:  # IPv4
            reversed_ip = dns.reversename.from_address(ip_address)
        
        return dns_lookup(reversed_ip, 'PTR', nameserver, raw)
        
    except Exception as e:
        print(f"{Fore.RED}[!] Error en consulta inversa: {str(e)}{Style.RESET_ALL}")
        return []

def _trace_dns_direct(domain, record_type='A', timeout=5):
    # Realiza un trace DNS paso a paso, mostrando el camino desde los servidores raíz hasta el servidor autoritativo final.
    # Args:
    #   domain (str): dominio a resolver (e.g. "example.com")
    #   record_type (str): tipo de registro DNS (A, AAAA, MX, etc.)
    #   timeout (int): Timeout para cada consulta DNS
    
    if not check_network_connectivity():
        print(f"{Fore.RED}[!] No hay conectividad de red{Style.RESET_ALL}")
        return

    total_start_time = time.time()
    
    print(f"{Fore.CYAN}[+] Iniciando traza DNS para '{domain}' ({record_type} record){Style.RESET_ALL}")
    
    # PASO 1: Obtener servidores TLD para el dominio
    print(f"{Fore.YELLOW}[+] 1. Obteniendo servidores TLD para '{domain}'...{Style.RESET_ALL}")
    tld = domain.split('.')[-1]
    tld_servers = []
    
    # Lista de root servers
    root_servers = ['a.root-servers.net.', 'b.root-servers.net.', 'c.root-servers.net.', 'd.root-servers.net.',
                   'e.root-servers.net.', 'f.root-servers.net.', 'g.root-servers.net.', 'h.root-servers.net.',
                   'i.root-servers.net.', 'j.root-servers.net.', 'k.root-servers.net.', 'l.root-servers.net.',
                   'm.root-servers.net.']
    
    # Intentar consulta directa a root servers
    direct_query_success = False
    for root_server in root_servers:
        try:
            # Resolver la IP del servidor raíz
            root_ip = str(dns.resolver.resolve(root_server, 'A')[0])
            print(f"   Consultando {root_server} ({root_ip}) para '{tld}.'...")
            start_time = time.time()
            
            # Crear consulta directa
            query = dns.message.make_query(tld + '.', dns.rdatatype.NS)
            
            try:
                response = dns.query.udp(query, root_ip, timeout=timeout)
            except (dns.exception.Timeout, dns.query.BadResponse) as e:
                print(f"{Fore.YELLOW}   UDP falló ({e}), intentando TCP...{Style.RESET_ALL}")
                try:
                    response = dns.query.tcp(query, root_ip, timeout=timeout)
                except Exception as e2:
                    print(f"{Fore.RED}   TCP también falló: {e2}{Style.RESET_ALL}")
                    raise e2

            # Extraer servidores TLD
            ns_records = []
            for rrset in response.authority:
                if rrset.rdtype == dns.rdatatype.NS:
                    ns_records.extend([str(ns) for ns in rrset])
            
            if ns_records:
                tld_servers = ns_records
                elapsed_time = (time.time() - start_time) * 1000
                print(f"{Fore.GREEN}   -> Referido a los servidores TLD: {tld_servers}{Style.RESET_ALL}")
                print(f"   [Tiempo: {elapsed_time:.0f} ms]")
                direct_query_success = True
                break
                
        except Exception as e:
            print(f"{Fore.RED}   Error con {root_server}: {e}{Style.RESET_ALL}")
            continue
    
    # Si falla consulta directa, usar resolución normal
    if not direct_query_success:
        print(f"{Fore.YELLOW}   [Fallback] Usando resolución recursiva para obtener servidores TLD...{Style.RESET_ALL}")
        try:
            start_time = time.time()
            answer = dns.resolver.resolve(tld + '.', 'NS')
            tld_servers = [str(ns.target) for ns in answer]
            elapsed_time = (time.time() - start_time) * 1000
            print(f"{Fore.GREEN}   -> Servidores TLD obtenidos: {tld_servers}{Style.RESET_ALL}")
            print(f"   [Tiempo: {elapsed_time:.0f} ms]")
        except Exception as e:
            print(f"{Fore.RED}   Error obteniendo servidores TLD: {e}{Style.RESET_ALL}")
            return

    # PASO 2: Obtener servidores autoritativos del dominio
    print(f"{Fore.YELLOW}[+] 2. Obteniendo servidores autoritativos para '{domain}'...{Style.RESET_ALL}")
    authoritative_servers = []
    
    # Intentar consulta directa a TLD servers
    direct_query_success = False
    for tld_server in tld_servers[:3]:  # Probar primeros 3
        try:
            tld_ip = str(dns.resolver.resolve(tld_server, 'A')[0])
            print(f"   Consultando {tld_server} ({tld_ip}) para '{domain}'...")
            start_time = time.time()
            
            query = dns.message.make_query(domain, dns.rdatatype.NS)
            
            try:
                response = dns.query.udp(query, tld_ip, timeout=timeout)
            except (dns.exception.Timeout, dns.query.BadResponse) as e:
                print(f"{Fore.YELLOW}   UDP falló ({e}), intentando TCP...{Style.RESET_ALL}")
                try:
                    response = dns.query.tcp(query, tld_ip, timeout=timeout)
                except Exception as e2:
                    print(f"{Fore.RED}   TCP también falló: {e2}{Style.RESET_ALL}")
                    raise e2
            
            ns_records = []
            for rrset in response.authority:
                if rrset.rdtype == dns.rdatatype.NS:
                    ns_records.extend([str(ns) for ns in rrset])
            
            if ns_records:
                authoritative_servers = ns_records
                elapsed_time = (time.time() - start_time) * 1000
                print(f"{Fore.GREEN}   -> Referido a servidores autoritativos: {authoritative_servers}{Style.RESET_ALL}")
                print(f"   [Tiempo: {elapsed_time:.0f} ms]")
                direct_query_success = True
                break
                
        except Exception as e:
            print(f"{Fore.RED}   Error con {tld_server}: {e}{Style.RESET_ALL}")
            continue
    
    # Fallback a resolución normal
    if not direct_query_success:
        print(f"{Fore.YELLOW}   [Fallback] Usando resolución recursiva para obtener servidores autoritativos...{Style.RESET_ALL}")
        try:
            start_time = time.time()
            answer = dns.resolver.resolve(domain, 'NS')
            authoritative_servers = [str(ns.target) for ns in answer]
            elapsed_time = (time.time() - start_time) * 1000
            print(f"{Fore.GREEN}   -> Servidores autoritativos obtenidos: {authoritative_servers}{Style.RESET_ALL}")
            print(f"   [Tiempo: {elapsed_time:.0f} ms]")
        except Exception as e:
            print(f"{Fore.RED}   Error obteniendo servidores autoritativos: {e}{Style.RESET_ALL}")
            return

    # PASO 3: Consultar el registro final a servidores autoritativos
    print(f"{Fore.YELLOW}[+] 3. Consultando registro {record_type} en servidores autoritativos...{Style.RESET_ALL}")
    final_answer = None
    
    for auth_server in authoritative_servers[:3]:
        try:
            auth_ip = str(dns.resolver.resolve(auth_server, 'A')[0])
            print(f"   Consultando {auth_server} ({auth_ip}) para '{record_type}'...")
            start_time = time.time()
            
            query = dns.message.make_query(domain, record_type)
            
            try:
                response = dns.query.udp(query, auth_ip, timeout=timeout)
            except (dns.exception.Timeout, dns.query.BadResponse) as e:
                print(f"{Fore.YELLOW}   UDP falló ({e}), intentando TCP...{Style.RESET_ALL}")
                try:
                    response = dns.query.tcp(query, auth_ip, timeout=timeout)
                except Exception as e2:
                    print(f"{Fore.RED}   TCP también falló: {e2}{Style.RESET_ALL}")
                    raise e2
            
            answers = []
            for rrset in response.answer:
                for item in rrset:
                    answers.append(str(item))
            
            if answers:
                final_answer = answers
                elapsed_time = (time.time() - start_time) * 1000
                print(f"{Fore.GREEN}   -> RESPUESTA FINAL: {', '.join(answers)}{Style.RESET_ALL}")
                print(f"   [Tiempo: {elapsed_time:.0f} ms]")
    
                # MANEJO DE CNAME
                if record_type == 'CNAME' and answers:
                    cname_target = answers[0]
                    print(f"{Fore.MAGENTA}   [ℹ️] Siguiendo cadena CNAME: {domain} -> {cname_target}{Style.RESET_ALL}")
                    print(f"{Fore.MAGENTA}   [ℹ️] Consultando ahora el registro A para {cname_target}{Style.RESET_ALL}")
                    # Llamada recursiva para seguir la cadena
                    trace_dns_resolution(cname_target, 'A', timeout)
    
            break
                
        except Exception as e:
            print(f"{Fore.RED}   Error con {auth_server}: {e}{Style.RESET_ALL}")
            continue
    
    # Resultado final
    total_elapsed_time = (time.time() - total_start_time) * 1000
    print(f"{Fore.CYAN}[+] Traza completada en {total_elapsed_time:.0f} ms.{Style.RESET_ALL}")
    
    if final_answer:
        print(f"{Fore.GREEN}[+] Resolución exitosa!{Style.RESET_ALL}")
    else:
        print(f"{Fore.RED}[!] No se pudo obtener respuesta final{Style.RESET_ALL}")

def _trace_dns_recursive(domain, record_type='A', timeout=5):
    # Realiza un trace DNS paso a paso usando resolución recursiva.
    # Versión adaptada para entornos con restricciones de firewall.
    
    total_start_time = time.time()
    
    print(f"{Fore.CYAN}[+] Iniciando traza DNS para '{domain}' ({record_type} record){Style.RESET_ALL}")
    print(f"{Fore.YELLOW}[!] Modo: Resolución recursiva (consultas directas bloqueadas){Style.RESET_ALL}")
    
    try:
        # PASO 1: Obtener servidores TLD
        print(f"{Fore.YELLOW}[+] 1. Obteniendo servidores TLD para '.{domain.split('.')[-1]}'...{Style.RESET_ALL}")
        start_time = time.time()
        tld_servers = dns.resolver.resolve(domain.split('.')[-1] + '.', 'NS')
        tld_list = sorted([str(ns.target) for ns in tld_servers])
        elapsed_time = (time.time() - start_time) * 1000
        print(f"{Fore.GREEN}   -> Servidores TLD: {tld_list}{Style.RESET_ALL}")
        print(f"   [Tiempo: {elapsed_time:.0f} ms]")

        # PASO 2: Obtener servidores autoritativos
        print(f"{Fore.YELLOW}[+] 2. Obteniendo servidores autoritativos para '{domain}'...{Style.RESET_ALL}")
        start_time = time.time()
        auth_servers = dns.resolver.resolve(domain, 'NS')
        auth_list = sorted([str(ns.target) for ns in auth_servers])
        elapsed_time = (time.time() - start_time) * 1000
        print(f"{Fore.GREEN}   -> Servidores autoritativos: {auth_list}{Style.RESET_ALL}")
        print(f"   [Tiempo: {elapsed_time:.0f} ms]")

        # PASO 3: Obtener la respuesta final
        print(f"{Fore.YELLOW}[+] 3. Obteniendo registro {record_type} para '{domain}'...{Style.RESET_ALL}")
        start_time = time.time()
        final_answer = dns.resolver.resolve(domain, record_type)
        result_list = [str(r) for r in final_answer]
        elapsed_time = (time.time() - start_time) * 1000
        print(f"{Fore.GREEN}   -> Respuesta final: {result_list}{Style.RESET_ALL}")
        print(f"   [Tiempo: {elapsed_time:.0f} ms]")

        # Información adicional
        print(f"{Fore.YELLOW}[+] Información adicional:{Style.RESET_ALL}")
        print(f"   - TTL: {final_answer.rrset.ttl if hasattr(final_answer, 'rrset') else 'N/A'} segundos")
        if hasattr(final_answer, 'canonical_name'):
            print(f"   - Nombre canónico: {final_answer.canonical_name}")

        total_elapsed_time = (time.time() - total_start_time) * 1000
        print(f"{Fore.CYAN}[+] Traza completada en {total_elapsed_time:.0f} ms.{Style.RESET_ALL}")
        print(f"{Fore.GREEN}[+] Resolución exitosa!{Style.RESET_ALL}")

    except dns.resolver.NoAnswer:
        print(f"{Fore.RED}[!] El dominio existe pero no tiene registros {record_type}{Style.RESET_ALL}")
    except dns.resolver.NXDOMAIN:
        print(f"{Fore.RED}[!] El dominio {domain} no existe{Style.RESET_ALL}")
    except dns.resolver.Timeout:
        print(f"{Fore.RED}[!] Timeout en la resolución DNS{Style.RESET_ALL}")
    except dns.resolver.NoNameservers:
        print(f"{Fore.RED}[!] No se pudo encontrar servidores para resolver el dominio{Style.RESET_ALL}")
    except Exception as e:
        print(f"{Fore.RED}[!] Error inesperado: {str(e)}{Style.RESET_ALL}")

def _check_direct_dns_allowed(timeout=3):
    """Verifica si las consultas DNS directas están permitidas en la red"""
    try:
        # Intentar una consulta directa rápida a un root server conocido
        test_ip = "198.41.0.4"  # a.root-servers.net
        query = dns.message.make_query("com.", dns.rdatatype.NS)
        dns.query.udp(query, test_ip, timeout=timeout)
        return True
    except:
        return False

def trace_dns_resolution(domain, record_type='A', timeout=5):
    # Realiza un trace DNS paso a paso con detección automática del modo.
    # Intenta consultas directas primero, si fallan usa resolución recursiva.
    
    total_start_time = time.time()
    
    print(f"{Fore.CYAN}[+] Iniciando traza DNS para '{domain}' ({record_type} record){Style.RESET_ALL}")
    
    # Detectar si las consultas directas están permitidas
    direct_dns_allowed = _check_direct_dns_allowed(timeout)
    
    if not direct_dns_allowed:
        print(f"{Fore.YELLOW}[!] Consultas directas bloqueadas, usando modo resolución recursiva{Style.RESET_ALL}")
        return _trace_dns_recursive(domain, record_type, timeout)
    else:
        print(f"{Fore.GREEN}[+] Consultas directas permitidas, usando modo completo{Style.RESET_ALL}")
        return _trace_dns_direct(domain, record_type, timeout)

def handle_trace_dns_option():
    #Maneja la opción de traza DNS desde el menú interactivo

    target = input("Introduce el dominio a trazar (ej. google.com): ").strip()
    
    if not is_valid_domain(target):
        print(f"{Fore.RED}[!] Nombre de dominio no válido.{Style.RESET_ALL}")
        return
    
    record_type = input("Tipo de registro (A, AAAA, MX, etc.) [A]: ").strip().upper()
    if not record_type:
        record_type = 'A'
    
    # Validar tipo de registro
    valid_records = ['A', 'AAAA', 'MX', 'NS', 'TXT', 'CNAME', 'SOA']
    if record_type not in valid_records:
        print(f"{Fore.RED}[!] Tipo de registro no válido. Usando A por defecto.{Style.RESET_ALL}")
        record_type = 'A'
    
    try:
        timeout = int(input("Timeout por consulta (segundos) [5]: ").strip() or "5")
    except ValueError:
        timeout = 5
        print(f"{Fore.YELLOW}[!] Timeout no válido. Usando 5 segundos.{Style.RESET_ALL}")
    
    print(f"\n{Fore.BLUE}[+] Iniciando traza DNS paso a paso...{Style.RESET_ALL}")
    trace_dns_resolution(target, record_type, timeout)

def _display_raw_output(results, domain, record_type):
    # Muestra salida técnica similar a dig
    print(f"{Fore.CYAN}[+] Consulta {record_type} para {domain} (Modo técnico):{Style.RESET_ALL}")
    for result in results:
        print(f"   {result['data']}")

def _display_pentesting_output(results, domain, record_type):
    # Muestra salida formateada para análisis de pentesting
    print(f"{Fore.CYAN}[+] Consulta {record_type} para {domain} (TTL: {results[0]['ttl'] if results else 'N/A'}s){Style.RESET_ALL}")

    if record_type in ['A', 'AAAA']:
        for result in results:
            print(f"   {Fore.YELLOW}{result['data']}{Style.RESET_ALL}")
        if record_type == 'AAAA':
            print(f"   {Fore.GREEN}✅ Soporte IPv6 detectado{Style.RESET_ALL}")

    elif record_type in ['NS', 'MX', 'SOA']:
        for result in results:
            # Para MX, mostrar prioridad si está disponible
            if record_type == 'MX' and hasattr(result['raw'], 'preference'):
                print(f"   {Fore.CYAN}Prioridad {result['raw'].preference}: {result['data']}{Style.RESET_ALL}")
            else:
                print(f"   {Fore.YELLOW}{result['data']}{Style.RESET_ALL}")
            
            # Detectar servidores propios
            if record_type in ['NS', 'MX'] and domain in result['data'].lower():
                print(f"   {Fore.GREEN}   ⚡ Servidor propio detectado{Style.RESET_ALL}")
    
    elif record_type == 'TXT':
        security_records = 0
        for result in results:
            txt_data = str(result['data']).strip('"')

            # Detectar y resaltar registros de seguridad
            if 'v=spf1' in txt_data:
                print(f"   {Fore.GREEN}SPF: {txt_data}{Style.RESET_ALL}")
                security_records += 1

            elif 'v=DMARC1' in txt_data:
                print(f"   {Fore.GREEN}DMARC: {txt_data}{Style.RESET_ALL}")
                security_records += 1

            elif 'v=DKIM1' in txt_data or 'dkim=' in txt_data:
                print(f"   {Fore.GREEN}DKIM: {txt_data}{Style.RESET_ALL}")
                security_records += 1
            
            else:
                # Verificar si es una verificación de servicio
                service_keywords = ['verify', 'validation', 'key', 'code', 'google-site-verification']
                if any(keyword in txt_data.lower() for keyword in service_keywords):
                    print(f"   {Fore.BLUE}Verificación: {txt_data}{Style.RESET_ALL}")
                else:
                    print(f"   {Fore.YELLOW}{txt_data}{Style.RESET_ALL}")
            
            if security_records > 0:
                print(f"   {Fore.GREEN}✅ Se encontraron {security_records} registros de seguridad{Style.RESET_ALL}")

    elif record_type == 'CNAME':
        for result in results:
            print(f"   {Fore.YELLOW}{result['data']}{Style.RESET_ALL}")

            # Detectar servicios de terceros
            cname_target = result['data'].lower()
            cloud_services = ['cloudflare', 'azure', 'aws', 'amazon', 'google', 'shopify', 'akamai', 'fastly']
            for service in cloud_services:
                if service in cname_target:
                    print(f"   {Fore.BLUE}   🚩 Posible servicio de {service}{Style.RESET_ALL}")
                    break

