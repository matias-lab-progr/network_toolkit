import os
import platform
import subprocess
import sys
import re
import requests
import json
import dns.resolver
import dns.exception
from colorama import Fore, Style, init
import dns.reversename
import dns.ipv6
import time
import argparse

# =============================================================================
# MANEJO DE DEPENDENCIAS OPcIONALES
# =============================================================================

# Diccionario global para tracking de dependencias
OPTIONAL_DEPENDENCIES = {
    'whois': {
        'import_name': 'whois',
        'required_for': ['WHOIS lookups'],
        'install_command': 'pip install python-whois',
        'available': False
    },
    'colorama': {
        'import_name': 'colorama',
        'required_for': ['Output coloreado'],
        'install_command': 'pip install colorama',
        'available': False
    }
}

def check_optional_dependencies():
    # Verifica la disponibilidad de dependencias opcionales
    for dep_name, dep_info in OPTIONAL_DEPENDENCIES.items():
        try:
            # Intentar importar el módulo
            __import__(dep_info['import_name'])
            dep_info['available'] = True
            print(f"{Fore.GREEN}[+] Dependencia {dep_name} disponible{Style.RESET_ALL}")
        except ImportError:
            dep_info['available'] = False
            print(f"{Fore.YELLOW}[!] Dependencia {dep_name} no disponible{Style.RESET_ALL}")
            print(f"    Instalar con: {dep_info['install_command']}")

def is_dependency_available(dependency_name):
    # Verifica si una dependencia está disponible
    if dependency_name in OPTIONAL_DEPENDENCIES:
        return OPTIONAL_DEPENDENCIES[dependency_name]['available']
    return False

def init_colorama():
    # Inicializa colorama de manera segura
    try:
        from colorama import init, Fore, Style
        init()
        return Fore, Style
    except ImportError:
        # Crear clases dummy para cuando colorama no está disponible
        class DummyColor:
            def __getattr__(self, name):
                return ""
        
        dummy_fore = DummyColor()
        dummy_style = DummyColor()
        return dummy_fore, dummy_style

def run_command(command):
    """Ejecuta un comando y devuelve su salida."""
    # subprocess.run(): Es la forma segura y moderna de ejecutar comandos del sistema desde Python.
    # capture_output=True y text=True nos permiten capturar la salida del comando como una cadena de texto.
    try:
        result = subprocess.run(command, shell=True, capture_output=True, text=True, timeout=120)
        return result.stdout + result.stderr
    except subprocess.TimeoutExpired:
        return "El comando tardó demasiado en ejecutarse y fue cancelado."
    except Exception as e:
        return f"Error al ejecutar el comando: {str(e)}"

def run_command_realtime(command):
    # Ejecuta un comando y muestra la salida en tiempo real (para comandos lentos).
    try:
        process = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, bufsize=1, universal_newlines=True)
        output_lines = []
        for line in process.stdout:
            print(line, end='') # Mágica: muestra cada línea al instante
            output_lines.append(line)
        process.wait()
        return ''.join(output_lines)
    except Exception as e:
        return f"Error al ejecutar el comando: {str(e)}"

def analyse_ping_output(output, target):
    #Analiza la salida del comando ping y añade explicaciones
    analysis = "\n--- ANÁLISIS PING ---\n"

    # Buscar patrones en la salida
    lines = output.splitlines()
    lost_packets = -1
    rtt_line = ""

    for line in lines:
        if "perdidos" in line or "loss" in line:    # Español/Inglés
            # Encuentra el número antes del signo de porcentaje '%'
            # Ejemplos de líneas:
            #   "    (0% perdidos),"
            #   "    Packets: Sent = 4, Received = 4, Lost = 0 (0% loss),"
            import re
            # Busca un patrón de dígitos seguido de un % en la línea
            match = re.search(r'(\d+)%', line)
            if match:
                lost_packets = int(match.group(1))
        if "Mínimo" in line or "Minimum" in line or "Media" in line or "Average" in line:
            rtt_line = line.strip()  # Usamos strip() para limpiar espacios
    
    # 1. Análisis de pérdidas de paquetes
    analysis += f"• Pérdida de Paquetes: {lost_packets}%\n"
    if lost_packets == 0:
        analysis += " Excelente. No hay pérdida de paquetes.\n"
    elif lost_packets < 5:
        analysis += " Aceptable. Pérdida leve, podría indicar congestión.\n"
    elif lost_packets == -1:
        analysis += " No se pudo determinar el porcentaje de pérdida.\n"
    else:
        analysis += " Pobre. Pérdida alta. Problemas de conexión graves.\n"

    # 2. Análisis de Latencia (RTT)
    if rtt_line:
        analysis += f"• Latencia (RTT): {rtt_line}\n"
        # Evaluación simple de la latencia
        if "ms" in rtt_line:
            # Intentemos extraer el valor promedio
            try:
                avg_match = re.search(r'Media\s*=\s*(\d+)ms', rtt_line)  # Español
                if not avg_match:
                    avg_match = re.search(r'Average\s*=\s*(\d+)ms', rtt_line)  # Inglés
                if avg_match:
                    avg_latency = int(avg_match.group(1))
                    if avg_latency < 50:
                        analysis += f"Latencia excelente ({avg_latency}ms). Ideal para juegos y videollamadas.\n"
                    elif avg_latency < 100:
                        analysis += f"Latencia aceptable ({avg_latency}ms). Bueno para navegación y streaming.\n"
                    elif avg_latency < 200:
                        analysis += f"Latencia regular ({avg_latency}ms). Puede haber lag en aplicaciones en tiempo real.\n"
                    else:
                        analysis += f"Latencia pobre ({avg_latency}ms). Conexión muy lenta.\n"
            except:
                analysis += "No se pudo analizar en profundidad la latencia.\n"
    else:
        analysis += "• Latencia: No se pudo determinar.\n"
           
    # 3. Análisis de TTL
    ttl_found = False
    for line in lines:
        if "TTL=" in line or "ttl=" in line:
            try:
                ttl_part = re.search(r'TTL=(\d+)', line, re.IGNORECASE)
                if ttl_part:
                    ttl_value = int(ttl_part.group(1))
                    analysis += f"• TTL (Time to Live): {ttl_value}\n"
                    analysis += f"  Capa OSI: Red (3) | Capa TCP/IP: Internet (2)\n"
                    
                    # Deducir el SO inicial basado en el TTL
                    if ttl_value <= 64:
                        initial_ttl_guess = "Linux/Unix (TTL inicial: 64)"
                    elif 65 <= ttl_value <= 128:
                        initial_ttl_guess = "Windows (TTL inicial: 128)"
                    else:
                        initial_ttl_guess = "otro dispositivo/routeo complejo"
                    analysis += f"  El host remoto parece ser: {initial_ttl_guess}\n"
                    ttl_found = True
                    break
            except (ValueError, IndexError):
                continue
    
    if not ttl_found:
        analysis += "• TTL: No se pudo determinar.\n"
        
    analysis += "--------------------------------\n"
    return analysis

def get_whois_info(domain):
    """Obtiene información WHOIS con manejo mejorado de dependencias"""
    
    # Verificar si whois está disponible
    if not is_dependency_available('whois'):
        error_msg = "ERROR: La biblioteca python-whois no está disponible.\n"
        error_msg += "Para usar la funcionalidad WHOIS, instálela con:\n"
        error_msg += "  pip install python-whois\n\n"
        error_msg += "Como alternativa, puede usar el comando whois del sistema.\n"
        
        # Intentar con comando whois del sistema como fallback
        try:
            if platform.system().lower() == "windows":
                # Verificar si whois está instalado en Windows
                check_result = subprocess.run("where whois", shell=True, 
                                            capture_output=True, text=True, timeout=10)
                if check_result.returncode == 0:
                    return run_command(f"whois {domain}")
                else:
                    error_msg += "El comando whois tampoco está disponible en el sistema."
            else:
                # Linux/macOS - generalmente tiene whois instalado
                return run_command(f"whois {domain}")
        except Exception as e:
            error_msg += f"Error al intentar usar comando whois del sistema: {str(e)}"
        
        return error_msg
    
    # Si whois está disponible, usar la biblioteca
    try:
        import whois
        whois_info = whois.whois(domain)
        
        result = f"Información WHOIS para {domain}:\n\n"
        result += f"Nombre de dominio: {whois_info.domain_name}\n"
        result += f"Registrador: {whois_info.registrar}\n"
        result += f"Fecha de creación: {whois_info.creation_date}\n"
        result += f"Fecha de expiración: {whois_info.expiration_date}\n"
        result += f"Última actualización: {whois_info.updated_date}\n"
        
        if whois_info.name_servers:
            result += f"\nServidores de nombres:\n"
            for ns in whois_info.name_servers:
                result += f"  - {ns}\n"
                
        return result
        
    except Exception as e:
        return f"Error al obtener información WHOIS: {str(e)}"

# Modificar la inicialización de colorama

def get_whois_info_enhanced(domain):
    # Obtiene información WHOIS usando múltiples métodos con fallbacks inteligentes
    methods_tried = []
    result = ""
    
    # Método 1: Intentar con la biblioteca python-whois (si disponible)
    if is_dependency_available('whois'):
        try:
            methods_tried.append("python-whois library")
            import whois
            whois_info = whois.whois(domain)
            
            result += f"Información WHOIS para {domain}:\n\n"
            result += f"Nombre de dominio: {whois_info.domain_name}\n"
            result += f"Registrador: {whois_info.registrar}\n"
            result += f"Fecha de creación: {whois_info.creation_date}\n"
            result += f"Fecha de expiración: {whois_info.expiration_date}\n"
            result += f"Última actualización: {whois_info.updated_date}\n"
            
            if whois_info.name_servers:
                result += f"\nServidores de nombres:\n"
                for ns in whois_info.name_servers:
                    result += f"  - {ns}\n"
                    
            return result
        except Exception as e:
            methods_tried[-1] += f" (falló: {str(e)})"
    
    # Método 2: Intentar con comando whois del sistema
    try:
        methods_tried.append("sistema whois command")
        if platform.system().lower() == "windows":
            # Verificar si whois está instalado en Windows
            check_result = subprocess.run("where whois", shell=True, 
                                        capture_output=True, text=True, timeout=10)
            if check_result.returncode == 0:
                return run_command(f"whois {domain}")
            else:
                methods_tried[-1] += " (whois no instalado)"
                raise Exception("whois no está instalado")
        else:
            # Linux/macOS
            return run_command(f"whois {domain}")
    except Exception as e:
        methods_tried[-1] += f" (falló: {str(e)})"
    
    # Método 3: Intentar con APIs alternativas (solo como último recurso)
    apis_to_try = [
        f"https://api.whoapi.com/?domain={domain}&r=whois&apikey=demo",
        f"https://www.whois.com/whois/{domain}",
    ]
    
    for api_url in apis_to_try:
        try:
            methods_tried.append(f"API: {api_url.split('?')[0]}")
            response = requests.get(api_url, timeout=15, 
                                  headers={'User-Agent': 'Mozilla/5.0'})
            
            if response.status_code == 200:
                # Intentar parsear como JSON primero
                try:
                    data = response.json()
                    return f"Información WHOIS de API:\n{json.dumps(data, indent=2, ensure_ascii=False)}"
                except:
                    # Si no es JSON, devolver el texto
                    return f"Información WHOIS de API:\n{response.text[:2000]}..."
            else:
                methods_tried[-1] += f" (error {response.status_code})"
        except Exception as e:
            methods_tried[-1] += f" (falló: {str(e)})"
    
    # Si todos los métodos fallaron
    error_msg = "No se pudo obtener información WHOIS. Métodos intentados:\n"
    for method in methods_tried:
        error_msg += f"  - {method}\n"
    
    error_msg += "\nSoluciones posibles:\n"
    if not is_dependency_available('whois'):
        error_msg += "1. Instalar python-whois: pip install python-whois\n"
    error_msg += "2. Instalar whois para Windows: winget install Microsoft.whois\n"
    error_msg += "3. Usar un navegador web para consultar: https://whois.domaintools.com/\n"
    error_msg += "4. Verificar la conexión a internet\n"
    
    return error_msg

def analyze_traceroute_output(output, target):
    """Analiza la salida del comando traceroute y proporciona información detallada."""
    analysis = "\n--- ANÁLISIS TRACEROUTE ---\n"
    lines = output.splitlines()
    
    hops = []
    total_hops = 0
    timeout_hops = 0
    private_ips = 0
    max_latency = 0
    slow_hops = []  # Cambiamos a diccionario para agrupar por número de salto
    
    def is_private_ip(ip):
        """Verifica si una IP es privada"""
        if not ip or ip == '*' or 'Tiempo' in ip:
            return False
            
        # Método simplificado para verificar IPs privadas
        if ip.startswith('10.') or ip.startswith('192.168.') or \
           (ip.startswith('172.') and 16 <= int(ip.split('.')[1]) <= 31) or \
           ip.startswith('169.254.') or ip.startswith('127.'):
            return True
        return False
    
    # Procesar cada línea
    for line in lines:
        line = line.strip()
        
        # Saltar líneas vacías o de encabezado
        if not line or 'traceroute' in line.lower() or 'tracing' in line.lower() or 'traza' in line.lower():
            continue
        
        # Buscar líneas que comienzan con número (saltos)
        if re.match(r'^\s*\d+\s+', line):
            # Usar expresión regular para dividir correctamente
            match = re.match(r'^\s*(\d+)\s+([^\s]+)\s+([^\s]+)\s+([^\s]+)\s+(.*)$', line)
            if match:
                try:
                    hop_num = int(match.group(1))
                    time1 = match.group(2)
                    time2 = match.group(3)
                    time3 = match.group(4)
                    host = match.group(5).strip()
                    
                    # Extraer IP si está disponible
                    ip_match = re.search(r'(\d+\.\d+\.\d+\.\d+)', host)
                    ip = ip_match.group(1) if ip_match else host
                    
                    # Limpiar el hostname (quitar texto adicional)
                    if ip and ip != host:
                        # Si encontramos una IP, usarla como host principal
                        host = ip
                    
                    # Contar timeouts
                    timeouts = 0
                    for t in [time1, time2, time3]:
                        if t == '*' or 'Tiempo' in t:
                            timeouts += 1
                    
                    hops.append({
                        'hop': hop_num,
                        'times': [time1, time2, time3],
                        'host': host,
                        'ip': ip,
                        'is_private': is_private_ip(ip),
                        'timeouts': timeouts
                    })
                except (ValueError, IndexError):
                    continue
    
    # Analizar los datos recolectados
    total_hops = len(hops)
    
    # Diccionario para almacenar la máxima latencia por salto
    max_latency_by_hop = {}
    
    for hop in hops:
        # Contar timeouts
        if hop['timeouts'] > 0:
            timeout_hops += 1
        
        # Contar IPs privadas
        if hop['is_private']:
            private_ips += 1
        
        # Calcular latencia máxima por salto y global
        hop_max_latency = 0
        for time_str in hop['times']:
            if time_str != '*' and 'Tiempo' not in time_str:
                try:
                    # Extraer valor numérico (eliminar 'ms' y convertir a número)
                    latency_str = re.sub(r'[^\d]', '', time_str)
                    if latency_str:  # Asegurarse de que no esté vacío
                        latency = int(latency_str)
                        if latency > hop_max_latency:
                            hop_max_latency = latency
                        if latency > max_latency:
                            max_latency = latency
                except (ValueError, TypeError):
                    continue
        
        # Almacenar la máxima latencia por salto
        max_latency_by_hop[hop['hop']] = {
            'latency': hop_max_latency,
            'host': hop['host']
        }
        
        # Identificar saltos lentos (>100ms)
        if hop_max_latency > 100:
            slow_hops.append({
                'hop': hop['hop'],
                'latency': hop_max_latency,
                'host': hop['host']
            })
    
    # Generar análisis
    analysis += f"• Saltos totales: {total_hops}\n"
    if total_hops > 0:
        analysis += f"• Saltos con timeouts: {timeout_hops} ({timeout_hops/total_hops*100:.1f}%)\n"
    analysis += f"• IPs privadas encontradas: {private_ips}\n"
    analysis += f"• Latencia máxima: {max_latency} ms\n"
    
    # Análisis de saltos lentos (agrupados por número de salto)
    if slow_hops:
        # Eliminar duplicados y quedarnos con la máxima latencia por salto
        unique_slow_hops = {}
        for slow_hop in slow_hops:
            hop_num = slow_hop['hop']
            if hop_num not in unique_slow_hops or slow_hop['latency'] > unique_slow_hops[hop_num]['latency']:
                unique_slow_hops[hop_num] = slow_hop
        
        analysis += f"• Saltos lentos (>100ms): {len(unique_slow_hops)}\n"
        for slow_hop in sorted(unique_slow_hops.values(), key=lambda x: x['latency'], reverse=True)[:5]:
            analysis += f"  - Salto {slow_hop['hop']}: {slow_hop['latency']}ms ({slow_hop['host']})\n"
    
    # Identificar problemas de red
    if total_hops > 0 and timeout_hops / total_hops > 0.3:
        analysis += "⚠️  ALTO PORCENTAJE DE TIMEOUTS: Puede haber filtrado de paquetes o problemas de ruteo.\n"
    
    if private_ips > 0:
        analysis += "🔍 SE DETECTARON IPs PRIVADAS: La ruta pasa por redes internas/NAT.\n"
    
    # Mostrar información de cada salto
    analysis += "\n• Detalle de saltos:\n"
    for hop in hops:
        status = "🟢" if hop['timeouts'] == 0 else "🔴" if hop['timeouts'] == 3 else "🟡"
        private_flag = " (Privada)" if hop['is_private'] else ""
        
        # Mostrar latencia máxima del salto
        latency_info = ""
        if hop['hop'] in max_latency_by_hop and max_latency_by_hop[hop['hop']]['latency'] > 0:
            latency_info = f" [Máx: {max_latency_by_hop[hop['hop']]['latency']}ms]"
        
        analysis += f"  {status} Salto {hop['hop']}: {hop['host']}{private_flag}{latency_info}\n"
        if hop['timeouts'] > 0:
            analysis += f"     Timeouts: {hop['timeouts']}/3 intentos\n"
    
    analysis += "\n• Recomendaciones:\n"
    if max_latency > 200:
        analysis += "  - Latencia muy alta. Considerar proveedor de internet alternativo.\n"
    if timeout_hops > 0:
        analysis += "  - Timeouts detectados. Puede indicar filtrado de paquetes o congestión.\n"
    
    analysis += "--------------------------------\n"
    return analysis

def analyze_whois_output(output, domain):
    #Analiza la salida de WHOIS y proporciona información resumida
    analysis = "\n--- ANÁLISIS WHOIS ---\n"
    
    lines = output.split('\n')
    
    # Buscar información importante
    creation_date = None
    expiration_date = None
    updated_date = None
    registrar = None
    name_servers = []
    
    for line in lines:
        line = line.strip()
        
        # Fechas de creación (manejar formato datetime)
        if 'Fecha de creación:' in line:
            # Buscar patrones de fecha en diferentes formatos
            date_patterns = [
                r'(\d{4}[-/]\d{1,2}[-/]\d{1,2})',  # YYYY-MM-DD
                r'datetime\.datetime\((\d{4}), (\d{1,2}), (\d{1,2})',  # datetime(1997, 9, 15
                r'(\d{4}-\d{2}-\d{2})'  # Formato ISO
            ]
            
            for pattern in date_patterns:
                match = re.search(pattern, line)
                if match:
                    if 'datetime' in pattern:
                        # Formato: datetime.datetime(1997, 9, 15, 4, 0)
                        year, month, day = match.groups()[:3]
                        creation_date = f"{year}-{month.zfill(2)}-{day.zfill(2)}"
                    else:
                        creation_date = match.group(1)
                    break
        
        # Fecha de expiración
        elif 'Fecha de expiración:' in line:
            date_patterns = [
                r'(\d{4}[-/]\d{1,2}[-/]\d{1,2})',
                r'datetime\.datetime\((\d{4}), (\d{1,2}), (\d{1,2})',
                r'(\d{4}-\d{2}-\d{2})'
            ]
            
            for pattern in date_patterns:
                match = re.search(pattern, line)
                if match:
                    if 'datetime' in pattern:
                        year, month, day = match.groups()[:3]
                        expiration_date = f"{year}-{month.zfill(2)}-{day.zfill(2)}"
                    else:
                        expiration_date = match.group(1)
                    break
        
        # Última actualización
        elif 'Última actualización:' in line:
            date_patterns = [
                r'(\d{4}[-/]\d{1,2}[-/]\d{1,2})',
                r'datetime\.datetime\((\d{4}), (\d{1,2}), (\d{1,2})',
                r'(\d{4}-\d{2}-\d{2})'
            ]
            
            for pattern in date_patterns:
                match = re.search(pattern, line)
                if match:
                    if 'datetime' in pattern:
                        year, month, day = match.groups()[:3]
                        updated_date = f"{year}-{month.zfill(2)}-{day.zfill(2)}"
                    else:
                        updated_date = match.group(1)
                    break
        
        # Registrador
        elif 'Registrador:' in line:
            registrar = line.split('Registrador:')[-1].strip()
        
        # Servidores de nombres
        elif re.match(r'^\s*-\s+[A-Za-z0-9.-]+\.[A-Za-z]{2,}', line):
            ns = line.strip().lstrip('-').strip()
            if ns and ns not in name_servers:
                name_servers.append(ns)
    
    # Análisis de fechas
    analysis += "• Información del dominio:\n"
    if creation_date:
        analysis += f"  - Creación: {creation_date}\n"
    if expiration_date:
        analysis += f"  - Expiración: {expiration_date}\n"
        # Calcular días hasta expiración
        try:
            from datetime import datetime
            exp_date = datetime.strptime(expiration_date, '%Y-%m-%d')
            days_left = (exp_date - datetime.now()).days
            analysis += f"  - Días hasta expiración: {days_left}\n"
            if days_left < 30:
                analysis += "  ⚠️  ¡El dominio expira pronto!\n"
            elif days_left > 3650:  # 10 años
                analysis += "  ✅ Dominio registrado por mucho tiempo\n"
        except:
            pass
    if updated_date:
        analysis += f"  - Última actualización: {updated_date}\n"
        try:
            from datetime import datetime
            update_date = datetime.strptime(updated_date, '%Y-%m-%d')
            days_since_update = (datetime.now() - update_date).days
            if days_since_update > 365:
                analysis += f"  ⚠️  Sin actualizaciones hace {days_since_update} días\n"
        except:
            pass
    
    if registrar:
        analysis += f"• Registrador: {registrar}\n"
        # Análisis del registrador
        if 'markmonitor' in registrar.lower():
            analysis += "  ✅ Registrador profesional (empresas grandes)\n"
        elif 'godaddy' in registrar.lower() or 'namecheap' in registrar.lower():
            analysis += "  ℹ️  Registrador popular (uso general)\n"
    
    # Análisis de servidores de nombres
    if name_servers:
        analysis += f"• Servidores DNS ({len(name_servers)}):\n"
        for ns in sorted(name_servers)[:4]:
            analysis += f"  - {ns}\n"
        if len(name_servers) > 4:
            analysis += f"  - ... y {len(name_servers) - 4} más\n"
        
        # Verificar configuración DNS
        if len(name_servers) >= 2:
            analysis += "  ✅ Configuración redundante (buena práctica)\n"
        
        # Verificar si usa servidores propios
        domain_clean = domain.lower().replace('www.', '').split('.')[0]
        own_ns = sum(1 for ns in name_servers if domain_clean in ns.lower())
        
        if own_ns >= len(name_servers) / 2:
            analysis += "  ✅ Usa servidores propios (configuración profesional)\n"
        else:
            analysis += "  ℹ️  Usa servidores de terceros\n"
    
    # Estado del dominio
    analysis += "• Estado del dominio:\n"
    if creation_date:
        try:
            from datetime import datetime
            create_date = datetime.strptime(creation_date, '%Y-%m-%d')
            domain_age = (datetime.now() - create_date).days // 365
            analysis += f"  - Edad aproximada: {domain_age} años\n"
            if domain_age > 10:
                analysis += "  ✅ Dominio antiguo (mayor confianza)\n"
        except:
            pass
    
    # Recomendaciones de seguridad
    analysis += "\n• Recomendaciones:\n"
    analysis += "  - Verificar periodicamente los datos WHOIS\n"
    analysis += "  - Considerar protección de privacidad del dominio\n"
    analysis += "  - Mantener actualizada la información de contacto\n"
    
    analysis += "--------------------------------\n"
    return analysis

def analyze_dns_output(output, domain):
    """Analiza la salida de DNS Lookup y explica los registros."""
    analysis = "\n--- ANÁLISIS DNS ---\n"
    
    lines = output.split('\n')
    
    # Detectar tipos de registros
    ipv4_addresses = []
    ipv6_addresses = []
    name_servers = []
    is_authoritative = "no autoritativa" not in output.lower()
    
    for line in lines:
        line = line.strip()
        
        # Detectar direcciones IPv4 (A records)
        if re.match(r'^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$', line):
            if line not in ipv4_addresses:
                ipv4_addresses.append(line)
        
        # Detectar direcciones IPv6 (AAAA records) - patrones más específicos
        elif re.match(r'^[0-9a-fA-F:]+:[0-9a-fA-F:]+$', line) and line.count(':') >= 2:
            if line not in ipv6_addresses:
                ipv6_addresses.append(line)
        
        # Detectar servidores de nombres en respuestas de nslookup
        elif ('internet address' in line.lower() or 'addresses:' in line.lower()) and \
             not line.startswith('Server:') and not line.startswith('Address:'):
            # Extraer IPs de líneas como "Addresses:  2800:3f0:4003:c03::71"
            ips = re.findall(r'(?:[0-9]{1,3}\.){3}[0-9]{1,3}|[0-9a-fA-F:]+:[0-9a-fA-F:]+', line)
            for ip in ips:
                if ':' in ip and ip not in ipv6_addresses:
                    ipv6_addresses.append(ip)
                elif '.' in ip and ip not in ipv4_addresses:
                    ipv4_addresses.append(ip)
    
    # Análisis de autoritatividad
    analysis += f"• Respuesta: {'Autoritativa' if is_authoritative else 'No autoritativa'}\n"
    if not is_authoritative:
        analysis += "  ℹ️  Información desde caché DNS local\n"
    
    # Análisis de registros A (IPv4)
    if ipv4_addresses:
        analysis += f"• Registros A (IPv4): {len(ipv4_addresses)} direcciones\n"
        for ip in sorted(ipv4_addresses)[:3]:
            analysis += f"  - {ip}\n"
        if len(ipv4_addresses) > 3:
            analysis += f"  - ... y {len(ipv4_addresses) - 3} más\n"
        
        # Análisis de distribución de IPs
        if len(ipv4_addresses) > 1:
            analysis += "  ✅ Múltiples IPs (balanceo de carga/geo-distribución)\n"
            
            # Verificar si están en el mismo rango
            first_octets = [ip.split('.')[0] for ip in ipv4_addresses]
            if len(set(first_octets)) == 1:
                analysis += "  📍 Mismo rango de IPs (probable mismo datacenter)\n"
            else:
                analysis += "  🌍 Diferentes rangos (geo-distribución)\n"
    
    # Análisis de registros AAAA (IPv6)
    if ipv6_addresses:
        analysis += f"• Registros AAAA (IPv6): {len(ipv6_addresses)} direcciones\n"
        for ip in sorted(ipv6_addresses)[:2]:
            analysis += f"  - {ip}\n"
        analysis += "  ✅ Soporte para IPv6 (conexiones modernas)\n"
    else:
        analysis += "• IPv6: No detectado\n"
        analysis += "  ℹ️  Considerar implementar IPv6\n"
    
    # Análisis de disponibilidad
    analysis += "• Disponibilidad:\n"
    if ipv4_addresses:
        analysis += "  ✅ Servicio accesible via IPv4\n"
    if ipv6_addresses:
        analysis += "  ✅ Servicio accesible via IPv6\n"
    
    # Recomendaciones
    analysis += "\n• Recomendaciones:\n"
    if ipv4_addresses and ipv6_addresses:
        analysis += "  ✅ Excelente: Soporte dual-stack (IPv4 + IPv6)\n"
    elif len(ipv4_addresses) >= 3:
        analysis += "  ✅ Bueno: Múltiples IPs IPv4 para redundancia\n"
    
    if len(ipv4_addresses) > 5:
        analysis += "  🚀 Excelente: Alta disponibilidad con muchas IPs\n"
    
    analysis += "--------------------------------\n"
    return analysis

# Función auxiliar para mostrar todos los tipos de registros de un dominio
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

def dns_lookup(domain, record_type='A', nameserver=None, raw=False):
    # Realiza consultas DNS profesionales con salida formateada para pentesting
    # Args:
    #   domain (str): dominio a consultar (e.g. "google.com")
    #   record_type (str): tipo de registro DNS (A, AAAA, NS, MX, TXT, CNAME, SOA)
    #   nameserver (str): servidor DNS específico (e.g. "1.1.1.1")
    #   raw (bool): Si True, muestra salida técnica; si False, muestra resumen para pestesting
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
    except dns.resolver.Timeout:
        print(f"{Fore.RED}[!] Timeout en la consulta DNS{Style.RESET_ALL}")
    except dns.exception.DNSException as e:
        print(f"{Fore.RED}[!] Error DNS: {str(e)}{Style.RESET_ALL}")
    except Exception as e:
        print(f"{Fore.RED}[!] Error inesperado: {str(e)}{Style.RESET_ALL}")

    return results

def check_network_connectivity():
    try:
        dns.resolver.resolve('google.com', 'A')
        return True
    except:
        return False

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

# Función para consulta por lotes desde archivo
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

# Función para consulta inversa (PTR)
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

# Función para manejar argumentos de línea de comandos
def _handle_cli_arguments():
    # Maneja los argumentos pasados por línea de comandos
    parser = argparse.ArgumentParser(description='Network Toolkit - Herramientas de red y DNS')
    subparsers = parser.add_subparsers(dest='command', help='Comando a ejecutar')
    
    # Parser para consulta DNS
    dns_parser = subparsers.add_parser('dns', help='Consulta DNS')
    dns_parser.add_argument('domain', help='Dominio a consultar')
    dns_parser.add_argument('-t', '--type', default='A', help='Tipo de registro (A, AAAA, NS, MX, TXT, CNAME, SOA)')
    dns_parser.add_argument('-n', '--nameserver', help='Servidor DNS específico')
    dns_parser.add_argument('-r', '--raw', action='store_true', help='Mostrar salida técnica en lugar de resumen')
    
    # Parser para escaneo completo
    scan_parser = subparsers.add_parser('scan', help='Escaneo DNS completo')
    scan_parser.add_argument('domain', help='Dominio a escanear')
    scan_parser.add_argument('-n', '--nameserver', help='Servidor DNS específico')
    scan_parser.add_argument('-r', '--raw', action='store_true', help='Mostrar salida técnica en lugar de resumen')
    
    # Parser para consulta por lotes
    batch_parser = subparsers.add_parser('batch', help='Consulta DNS por lotes')
    batch_parser.add_argument('file', help='Archivo con subdominios')
    batch_parser.add_argument('-t', '--type', default='A', help='Tipo de registro (A, AAAA, NS, MX, TXT, CNAME, SOA)')
    batch_parser.add_argument('-n', '--nameserver', help='Servidor DNS específico')
    batch_parser.add_argument('-r', '--raw', action='store_true', help='Mostrar salida técnica en lugar de resumen')
    
    # Parser para consulta inversa
    reverse_parser = subparsers.add_parser('reverse', help='Consulta DNS inversa (PTR)')
    reverse_parser.add_argument('ip', help='Dirección IP para consulta inversa')
    reverse_parser.add_argument('-n', '--nameserver', help='Servidor DNS específico')
    reverse_parser.add_argument('-r', '--raw', action='store_true', help='Mostrar salida técnica en lugar de resumen')
    
    trace_parser = subparsers.add_parser('trace-dns', help='Trace DNS paso a paso')
    trace_parser.add_argument('domain', help='Dominio a trazar')
    trace_parser.add_argument('-t', '--type', default='A', help='Tipo de registro (A, AAAA, MX, NS, etc.)')
    trace_parser.add_argument('--timeout', type=int, default=5, help='Timeout por consulta en segundos')

    args = parser.parse_args()
    
    if args.command == 'dns':
        dns_lookup(args.domain, args.type, args.nameserver, args.raw)
    elif args.command == 'scan':
        comprehensive_dns_scan(args.domain, args.nameserver, args.raw)
    elif args.command == 'batch':
        batch_dns_lookup(args.file, args.type, args.nameserver, args.raw)
    elif args.command == 'reverse':
        reverse_dns_lookup(args.ip, args.nameserver, args.raw)
    elif args.command == 'trace-dns':
        trace_dns_resolution(args.domain, args.type, args.timeout)
    else:
        parser.print_help()

def get_raw_mode_input():
    # Solicita y valida la entrada para el modo raw (técnico)
    while True:
        raw_mode = input("Modo técnico (raw)? (s/n): ").strip().lower()
        if raw_mode in ['s', 'si', 'sí', 'y', 'yes']:
            return True
        elif raw_mode in ['n', 'no']:
            return False
        else:
            print(f"{Fore.RED}[!] Entrada no válida. Por favor ingresa 's' para sí o 'n' para no.{Style.RESET_ALL}")

def handle_ping_option(current_os):
    # Maneja la opción de ping
    target = input("Introduce el objetivo (ej. google.com): ").strip()

    # Validar que sea un objetivo válido (IP o dominio)
    if not is_valid_target(target):
        print(f"{Fore.RED}[!] Objetivo no válido. Debe ser una IP o dominio válido.{Style.RESET_ALL}")
        return

    if current_os == "windows":
        command = f"ping -n 4 {target}"
    else:
        command = f"ping -c 4 {target}"
    output = run_command(command)
    print(f"\n[*] Resultados de Ping para {target}:\n{output}")
    analysis = analyse_ping_output(output, target)
    print(analysis)

def handle_traceroute_option(current_os):
    # Maneja la opción de traceroute
    target = input("Introduce el objetivo (ej. google.com): ").strip()
    if current_os == "windows":
        command = f"tracert -h 15 {target}"
    else:
        command = f"traceroute -m 15 {target}"
    
    print(f"\n[*] Ejecutando Traceroute para {target}:\n")
    output = run_command_realtime(command)
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

    raw = get_raw_mode_input()
    dns_lookup(target, record_type,nameserver, raw)

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
    
    raw = get_raw_mode_input()
    comprehensive_dns_scan(target, nameserver, raw)

def handle_batch_dns_lookup():
    #Maneja la opción de consulta DNS por lotes
    filename = input("Ruta al archivo con subdominios: ").strip()
    record_type = input("Tipo de registro (A, AAAA, NS, MX, TXT, CNAME, SOA) [A]: ").strip().upper()
    if not record_type:
        record_type = 'A'
    
    nameserver = input("Servidor DNS específico (opcional, Enter para usar por defecto): ").strip()
    if not nameserver:
        nameserver = None

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
    
    raw = get_raw_mode_input()
    reverse_dns_lookup(ip_address, nameserver, raw)

def is_valid_ip(ip):
    # Valida si una cadena es una dirección IP válida (IPv4 o IPv6)

    # Validar IPv4
    ipv4_pattern = r'^(\d{1,3}\.){3}\d{1,3}$'
    if re.match(ipv4_pattern, ip):
        parts = ip.split('.')
        if all(0 <= int(part) <= 255 for part in parts):
            return True
    
    # Validar IPv6
    ipv6_pattern = r'^([0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}$|^::1$|^::$|^([0-9a-fA-F]{1,4}:){1,7}:$|^([0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}$|^([0-9a-fA-F]{1,4}:){1,5}(:[0-9a-fA-F]{1,4}){1,2}$|^([0-9a-fA-F]{1,4}:){1,4}(:[0-9a-fA-F]{1,4}){1,3}$|^([0-9a-fA-F]{1,4}:){1,3}(:[0-9a-fA-F]{1,4}){1,4}$|^([0-9a-fA-F]{1,4}:){1,2}(:[0-9a-fA-F]{1,4}){1,5}$|^[0-9a-fA-F]{1,4}:((:[0-9a-fA-F]{1,4}){1,6})$|^:((:[0-9a-fA-F]{1,4}){1,7}|:)$'
    if re.match(ipv6_pattern, ip):
        return True
    
    return False

def is_valid_domain(domain):
    # Valida si una cadena es un nombre de dominio válido
    domain_pattern = r'^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*$'
    return re.match(domain_pattern, domain) is not None

def is_valid_target(target):
    # Valida si un objetivo es una IP o dominio válido
    return is_valid_ip(target) or is_valid_domain(target)

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
    print (f" [*] Sistema Operativo detectado: {current_os}")

   # Verificar si se pasaron argumentos de línea de comandos
    if len(sys.argv) > 1:
        try:
            _handle_cli_arguments()
            return
        except Exception as e:
            print(f"{Fore.RED}[!] Error procesando argumentos de línea de comandos: {e}{Style.RESET_ALL}")
            sys.exit(1)

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
        print("10. Salir")
        
        choice = input("\nSelecciona una opción (1-10): ").strip()

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
                print("¡Saliendo! Hasta luego")
                sys.exit(0)
            else:
                print("Opción no válida. Por favor, elige 1-9.")
        
        except KeyboardInterrupt:
            print("\n\nOperación cancelada por el usuario.")
        except Exception as e:
            print(f"{Fore.RED}[!] Error inesperado: {str(e)}{Style.RESET_ALL}")
            print("Por favor, intenta de nuevo.")


if __name__ == "__main__":
    main()
