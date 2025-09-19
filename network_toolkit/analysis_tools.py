# network_toolkit/analysis_tools.py
"""
Módulo de análisis para Network Toolkit - Análisis y procesamiento de resultados
"""

import re
from colorama import Fore, Style

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