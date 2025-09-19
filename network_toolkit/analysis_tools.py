# network_toolkit/analysis_tools.py
"""
Módulo de análisis para Network Toolkit - Análisis y procesamiento de resultados
"""

import re
from colorama import Fore, Style

def analyse_ping_output(output, target):
    """
    Analiza la salida del comando ping (Linux/macOS/Windows, ES/EN) y devuelve
    un texto explicativo en español con métricas y recomendaciones.
    """
    import re
    import math
    from colorama import Fore, Style

    # Helpers
    def safe_float(x, default=None):
        try:
            return float(x)
        except:
            return default

    def parse_int(x, default=None):
        try:
            return int(x)
        except:
            return default

    def fmt_ms(v):
        if v is None:
            return "N/A"
        return f"{v:.2f} ms"

    # Inicialización
    analysis_lines = []
    header = f"{Fore.CYAN}--- ANÁLISIS PING: {target} ---{Style.RESET_ALL}"
    analysis_lines.append(header)

    # Métricas que trataremos de obtener
    metrics = {
        "sent": None,
        "received": None,
        "lost": None,
        "loss_percent": None,
        "rtt_min": None,
        "rtt_avg": None,
        "rtt_max": None,
        "rtt_mdev": None,
        "rtt_stddev": None,
        "jitter": None,
        "sample_times": [],   # lista de tiempos individuales (ms)
        "ttl": None
    }

    lines = [ln.strip() for ln in output.splitlines() if ln.strip()]

    # 1) Intentar extraer paquetes (Unix: "4 packets transmitted, 4 received, 0% packet loss")
    # Linux/mac pattern
    for ln in lines:
        # packets transmitted, received, packet loss
        m = re.search(r'(\d+)\s+packets\s+transmitted[, ]+\s*(\d+)\s+(?:received|received,)\b.*?(\d+)%', ln, re.IGNORECASE)
        if m:
            metrics["sent"] = parse_int(m.group(1))
            metrics["received"] = parse_int(m.group(2))
            metrics["loss_percent"] = parse_int(m.group(3))
            metrics["lost"] = None if metrics["sent"] is None or metrics["received"] is None else metrics["sent"] - metrics["received"]
            break

    # Windows pattern: "Packets: Sent = 4, Received = 4, Lost = 0 (0% loss),"
    if metrics["sent"] is None:
        for ln in lines:
            m = re.search(r'Sent\s*=\s*(\d+)\s*,\s*Received\s*=\s*(\d+)\s*,\s*Lost\s*=\s*(\d+)', ln, re.IGNORECASE)
            if m:
                metrics["sent"] = parse_int(m.group(1))
                metrics["received"] = parse_int(m.group(2))
                metrics["lost"] = parse_int(m.group(3))
                # buscar % loss si aparece
                m2 = re.search(r'\((\d+)%\s*loss\)|\((\d+)%\s*perdidos\)', ln, re.IGNORECASE)
                if m2:
                    metrics["loss_percent"] = parse_int(m2.group(1) or m2.group(2))
                elif metrics["sent"] is not None:
                    metrics["loss_percent"] = 0 if metrics["lost"] == 0 else round(metrics["lost"] / metrics["sent"] * 100, 2)
                break

    # Si aún no se detectó, intentar patrón en español "4 paquetes transmitidos, 4 recibidos, 0% perdidos"
    if metrics["sent"] is None:
        for ln in lines:
            m = re.search(r'(\d+)\s+paquetes\s+transmitidos[, ]+\s*(\d+)\s+(?:recibidos|recibido)[, ]+.*?(\d+)%', ln, re.IGNORECASE)
            if m:
                metrics["sent"] = parse_int(m.group(1))
                metrics["received"] = parse_int(m.group(2))
                metrics["loss_percent"] = parse_int(m.group(3))
                metrics["lost"] = None if metrics["sent"] is None or metrics["received"] is None else metrics["sent"] - metrics["received"]
                break

    # 2) Extraer valores RTT (Unix: rtt min/avg/max/mdev = 0.123/0.123/0.123/0.000 ms)
    for ln in lines:
        m = re.search(r'=\s*([\d.]+)\/([\d.]+)\/([\d.]+)\/([\d.]+)\s*ms', ln)  # iputils
        if not m:
            m = re.search(r'round-trip.*=\s*([\d.]+)\/([\d.]+)\/([\d.]+)\/([\d.]+)\s*ms', ln, re.IGNORECASE)
        if m:
            metrics["rtt_min"] = safe_float(m.group(1))
            metrics["rtt_avg"] = safe_float(m.group(2))
            metrics["rtt_max"] = safe_float(m.group(3))
            metrics["rtt_mdev"] = safe_float(m.group(4))
            break

    # 2b) Windows block: look for "Minimum = Xms, Maximum = Yms, Average = Zms"
    if metrics["rtt_avg"] is None:
        for ln in lines:
            m = re.search(r'Minimum\s*=\s*([\d<>]+)ms.*Maximum\s*=\s*([\d<>]+)ms.*Average\s*=\s*([\d<>]+)ms', ln, re.IGNORECASE)
            if m:
                def interpret_ms(s):
                    if '<' in s:
                        return 0.5
                    return safe_float(re.sub(r'[^\d.]','',s))
                metrics["rtt_min"] = interpret_ms(m.group(1))
                metrics["rtt_max"] = interpret_ms(m.group(2))
                metrics["rtt_avg"] = interpret_ms(m.group(3))
                break

    # 3) Si no hay resumen RTT, extraer todos los "time=" de respuestas y calcular estadísticas
    if metrics["rtt_avg"] is None:
        times = []
        for ln in lines:
            # ejemplos: time=0.123 ms  | time=1ms | time<1ms
            m = re.search(r'time[=<]?\s*([\d.]+)\s*ms', ln, re.IGNORECASE)
            if m:
                val = safe_float(m.group(1))
                if val is not None:
                    times.append(val)
                continue
            # Windows format "time<1ms" -> approximate
            if re.search(r'time\s*<\s*1\s*ms', ln, re.IGNORECASE):
                times.append(0.5)
        if times:
            metrics["sample_times"] = times
            metrics["rtt_min"] = min(times)
            metrics["rtt_max"] = max(times)
            metrics["rtt_avg"] = sum(times) / len(times)
            # stddev
            if len(times) > 1:
                mean = metrics["rtt_avg"]
                variance = sum((t - mean) ** 2 for t in times) / len(times)
                metrics["rtt_stddev"] = math.sqrt(variance)
                metrics["rtt_mdev"] = metrics["rtt_stddev"]
            else:
                metrics["rtt_stddev"] = 0.0
                metrics["rtt_mdev"] = 0.0

    # 4) TTL: buscar la primera aparición de TTL= o ttl=
    for ln in lines:
        m = re.search(r'TTL=(\d+)', ln, re.IGNORECASE)
        if not m:
            m = re.search(r'ttl=(\d+)', ln, re.IGNORECASE)
        if m:
            metrics["ttl"] = parse_int(m.group(1))
            break

    # 5) Si no tenemos loss_percent pero sí sent/received, calcularlo
    if metrics["loss_percent"] is None and metrics["sent"] is not None and metrics["received"] is not None:
        metrics["lost"] = metrics["sent"] - metrics["received"]
        try:
            metrics["loss_percent"] = round(metrics["lost"] / metrics["sent"] * 100, 2) if metrics["sent"] > 0 else None
        except:
            metrics["loss_percent"] = None

    # --- Generar análisis en texto (español) ---
    # 1. Pérdida de paquetes
    lp = metrics["loss_percent"]
    if lp is None:
        analysis_lines.append(f"• Pérdida de paquetes: {Fore.YELLOW}No disponible{Style.RESET_ALL}")
    else:
        loss_color = Fore.GREEN if lp == 0 else (Fore.YELLOW if lp <= 2 else (Fore.MAGENTA if lp <= 5 else Fore.RED))
        analysis_lines.append(f"• Pérdida de paquetes: {loss_color}{lp}%{Style.RESET_ALL}")
        # Interpretación
        if lp == 0:
            analysis_lines.append("  → Excelente: no hay pérdida de paquetes.")
        elif lp <= 2:
            analysis_lines.append("  → Muy buena: pérdida mínima, es tolerable.")
        elif lp <= 5:
            analysis_lines.append("  → Aceptable pero a vigilar: posible congestión intermitente.")
        else:
            analysis_lines.append("  → Problemática: pérdida significativa. Revisar conexión/ISP/infraestructura.")

    # 2. Latencia (RTT) y jitter/stddev
    if metrics["rtt_avg"] is not None:
        avg = metrics["rtt_avg"]
        maxv = metrics["rtt_max"]
        minv = metrics["rtt_min"]
        stddev = metrics.get("rtt_stddev", metrics.get("rtt_mdev"))
        analysis_lines.append(f"• Latencia (RTT): min={fmt_ms(minv)}, avg={fmt_ms(avg)}, max={fmt_ms(maxv)}")
        if stddev is not None:
            analysis_lines.append(f"  → Jitter/StdDev aproximado: {fmt_ms(stddev)}")
        # Categorizar
        if avg < 50:
            analysis_lines.append(f"  → Latencia excelente ({avg:.1f} ms). Adecuada para juegos/videollamadas.")
        elif avg < 100:
            analysis_lines.append(f"  → Latencia buena ({avg:.1f} ms). Adecuada para la mayoría de usos.")
        elif avg < 200:
            analysis_lines.append(f"  → Latencia moderada ({avg:.1f} ms). Puede afectar aplicaciones en tiempo real.")
        else:
            analysis_lines.append(f"  → Latencia alta ({avg:.1f} ms). Revisar ruta/ISP.")

    else:
        analysis_lines.append(f"• Latencia (RTT): {Fore.YELLOW}No disponible{Style.RESET_ALL}")

    # 3. TTL y deducción SO aproximada
    if metrics["ttl"] is not None:
        ttl = metrics["ttl"]
        analysis_lines.append(f"• TTL (Time To Live): {Fore.WHITE}{ttl}{Style.RESET_ALL}")
        if ttl <= 64:
            guess = "Linux/Unix (TTL inicial típico: 64)"
        elif 65 <= ttl <= 128:
            guess = "Windows (TTL inicial típico: 128)"
        else:
            guess = "Dispositivo/entorno con TTL alto o salto de red complejo"
        analysis_lines.append(f"  → Estimación rápida del SO/stack: {guess}")
    else:
        analysis_lines.append("• TTL: No detectado en la salida.")

    # 4. Recomendaciones prácticas (diagnóstico)
    analysis_lines.append("\n• Recomendaciones / siguientes pasos:")
    # Prioritizar según métricas
    if lp is not None and lp > 5:
        analysis_lines.append("  - Alta pérdida detectada: Ejecutar pruebas desde otro punto de la red (otra máquina), comprobar cableado/puerto, y contactar ISP si el problema persiste.")
        analysis_lines.append("  - Ejecutar `mtr <host>` (Linux/macOS) o `pathping <host>` (Windows) para identificar dónde ocurre la pérdida.")
        analysis_lines.append("  - Repetir ping con más paquetes: `ping -c 50 <host>` (Linux) / `ping -n 50 <host>` (Windows).")
    elif metrics["rtt_avg"] is not None and metrics["rtt_avg"] > 200:
        analysis_lines.append("  - Latencia muy alta: probar trazas (`traceroute` / `tracert`) y contactar al proveedor si el cuello de botella está fuera de la red local.")
    else:
        analysis_lines.append("  - Si observas jitter o picos, realiza pruebas sostenidas (MTR) para localizar el salto problemático.")
        analysis_lines.append("  - Para pruebas más precisas, usar `ping` con payload y tamano: `ping -s 1400 <host>` (Linux).")
    analysis_lines.append("  - Comprueba la carga del equipo local (CPU/uso de NIC) y evita Wi-Fi si buscas diagnóstico de calidad de enlace.")
    analysis_lines.append("  - Si es una red empresarial: revisa duplex mismatch y configuración del switch hacia el host.")

    # 5. Append raw summary metrics en formato compacto (útil para logging)
    analysis_lines.append("\n• Métricas detectadas (resumen):")
    analysis_lines.append(f"  - Sent: {metrics['sent']}, Received: {metrics['received']}, Lost: {metrics['lost']}, Loss%: {metrics['loss_percent']}")
    analysis_lines.append(f"  - RTT min/avg/max (ms): {metrics['rtt_min']}/{metrics['rtt_avg']}/{metrics['rtt_max']}")
    if metrics.get("rtt_stddev") is not None:
        analysis_lines.append(f"  - RTT stddev: {metrics['rtt_stddev']:.2f} ms")

    # Pie
    analysis_lines.append(f"{Fore.CYAN}{'-'*40}{Style.RESET_ALL}")

    return "\n".join(analysis_lines)


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