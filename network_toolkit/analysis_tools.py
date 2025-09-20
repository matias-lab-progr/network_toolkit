# network_toolkit/analysis_tools.py
"""
Módulo de análisis para Network Toolkit - Análisis y procesamiento de resultados
"""

from datetime import datetime
from typing import Any, Dict, Tuple
from colorama import Fore, Style
import re
from colorama import Fore, Style

def analyse_ping_output(output, target):
    """
    Analiza la salida del comando ping (Linux/macOS/Windows, ES/EN) y devuelve
    un texto explicativo en español con métricas y recomendaciones.
    
    Returns:
        Tuple[str, Dict]: Análisis en texto y métricas estructuradas
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

    # Métricas que trataremos de obtener (estructura compatible con el nuevo sistema)
    metrics = {
        "target": target,
        "timestamp": datetime.now().isoformat(),
        "sent": 0,
        "received": 0,
        "lost": 0,
        "loss_percent": 0.0,
        "rtt_min": 0.0,
        "rtt_avg": 0.0,
        "rtt_max": 0.0,
        "rtt_stddev": 0.0,
        "ttl": 0,
        "reachable": False,
        "sample_times": []   # lista de tiempos individuales (ms)
    }

    lines = [ln.strip() for ln in output.splitlines() if ln.strip()]

    # Verificar si el host es alcanzable
    if "Destination Host Unreachable" in output or "100% loss" in output:
        metrics["reachable"] = False
        analysis_lines.append(f"{Fore.RED}❌ Host {target} no alcanzable{Style.RESET_ALL}")
        return "\n".join(analysis_lines), metrics
    
    # Asumir que es alcanzable inicialmente
    metrics["reachable"] = True
    analysis_lines.append(f"{Fore.GREEN}✅ Host {target} alcanzable{Style.RESET_ALL}")

    # 1) Extraer tiempos individuales de las respuestas (para Windows y Unix)
    times = []
    ttl_values = []
    response_count = 0
    
    for ln in lines:
        # Patrón para respuestas de Windows: "Respuesta desde 192.168.1.1: bytes=32 tiempo=15ms TTL=64"
        m = re.search(r'Respuesta desde .+? tiempo[=:]([\d<>]+)\s*ms.*TTL[=:](\d+)', ln, re.IGNORECASE)
        if not m:
            # Patrón alternativo para Windows: "Reply from 192.168.1.1: bytes=32 time=15ms TTL=64"
            m = re.search(r'Reply from .+? time[=:]([\d<>]+)\s*ms.*TTL[=:](\d+)', ln, re.IGNORECASE)
        if not m:
            # Patrón para Unix: "64 bytes from 192.168.1.1: icmp_seq=1 ttl=64 time=15.3 ms"
            m = re.search(r'from .+? ttl=(\d+).*time[=:]([\d.]+)\s*ms', ln, re.IGNORECASE)
            if m:
                ttl_values.append(parse_int(m.group(1)))
                times.append(safe_float(m.group(2)))
                response_count += 1
                continue
        
        if m:
            # Para patrones de Windows
            time_val = m.group(1)
            ttl_val = m.group(2) if len(m.groups()) > 1 else None
            
            # Procesar tiempo (puede ser "<1ms")
            if '<' in time_val:
                times.append(0.5)
            else:
                times.append(safe_float(re.sub(r'[^\d.]', '', time_val)))
            
            if ttl_val:
                ttl_values.append(parse_int(ttl_val))
            
            response_count += 1

    # 2) Extraer estadísticas de paquetes
    # Windows pattern: "Paquetes: enviados = 4, recibidos = 4, perdidos = 0"
    for ln in lines:
        # Patrón español Windows
        m = re.search(r'enviados\s*=\s*(\d+)\s*,\s*recibidos\s*=\s*(\d+)\s*,\s*perdidos\s*=\s*(\d+)', ln, re.IGNORECASE)
        if not m:
            # Patrón inglés Windows
            m = re.search(r'Sent\s*=\s*(\d+)\s*,\s*Received\s*=\s*(\d+)\s*,\s*Lost\s*=\s*(\d+)', ln, re.IGNORECASE)
        if not m:
            # Patrón Unix
            m = re.search(r'(\d+)\s+packets\s+transmitted[, ]+\s*(\d+)\s+received', ln, re.IGNORECASE)
        
        if m:
            metrics["sent"] = parse_int(m.group(1))
            metrics["received"] = parse_int(m.group(2))
            if len(m.groups()) > 2:
                metrics["lost"] = parse_int(m.group(3))
            else:
                metrics["lost"] = metrics["sent"] - metrics["received"] if metrics["sent"] is not None and metrics["received"] is not None else 0
            
            # Calcular porcentaje de pérdida
            if metrics["sent"] and metrics["sent"] > 0:
                metrics["loss_percent"] = round((metrics["lost"] / metrics["sent"]) * 100, 2)
            break

    # 3) Extraer estadísticas RTT de Windows: "Mínimo = 80ms, Máximo = 93ms, Media = 85ms"
    for ln in lines:
        m = re.search(r'M[ií]nimo\s*=\s*([\d<>]+)\s*ms.*M[áa]ximo\s*=\s*([\d<>]+)\s*ms.*Media\s*=\s*([\d<>]+)\s*ms', ln, re.IGNORECASE)
        if not m:
            m = re.search(r'Minimum\s*=\s*([\d<>]+)\s*ms.*Maximum\s*=\s*([\d<>]+)\s*ms.*Average\s*=\s*([\d<>]+)\s*ms', ln, re.IGNORECASE)
        
        if m:
            def parse_ms_value(val):
                if '<' in val:
                    return 0.5
                return safe_float(re.sub(r'[^\d.]', '', val))
            
            metrics["rtt_min"] = parse_ms_value(m.group(1))
            metrics["rtt_max"] = parse_ms_value(m.group(2))
            metrics["rtt_avg"] = parse_ms_value(m.group(3))
            break

    # 4) Si no tenemos estadísticas RTT pero tenemos tiempos individuales, calcularlas
    if metrics["rtt_avg"] is None and times:
        metrics["sample_times"] = times
        metrics["rtt_min"] = min(times)
        metrics["rtt_max"] = max(times)
        metrics["rtt_avg"] = sum(times) / len(times)
        if len(times) > 1:
            mean = metrics["rtt_avg"]
            variance = sum((t - mean) ** 2 for t in times) / len(times)
            metrics["rtt_stddev"] = math.sqrt(variance)
        else:
            metrics["rtt_stddev"] = 0.0

    # 5) Extraer TTL si no se encontró en las respuestas individuales
    if not ttl_values and metrics["ttl"] == 0:
        for ln in lines:
            m = re.search(r'TTL[=:](\d+)', ln, re.IGNORECASE)
            if m:
                metrics["ttl"] = parse_int(m.group(1))
                break

    # 6) Si no tenemos métricas de paquetes pero tenemos respuestas, inferirlas
    if metrics["sent"] == 0 and response_count > 0:
        metrics["received"] = response_count
        metrics["sent"] = response_count  # Asumimos que todos los paquetes enviados fueron recibidos
        metrics["lost"] = 0
        metrics["loss_percent"] = 0.0

    # VERIFICACIÓN FINAL: Si no se recibió ningún paquete, no es alcanzable
    if metrics.get("received", 0) == 0:
        metrics["reachable"] = False
        if "✅ Host" in analysis_lines[1]:
            analysis_lines[1] = f"{Fore.RED}❌ Host {target} NO alcanzable{Style.RESET_ALL}"
    else:
        metrics["reachable"] = True
        if "❌ Host" in analysis_lines[1]:
            analysis_lines[1] = f"{Fore.GREEN}✅ Host {target} alcanzable{Style.RESET_ALL}"

    # --- Generar análisis en texto (español) ---
    # 1. Pérdida de paquetes
    lp = metrics["loss_percent"]
    if lp is None:
        analysis_lines.append(f"• Pérdida de paquetes: {Fore.YELLOW}No disponible{Style.RESET_ALL}")
    else:
        loss_color = Fore.GREEN if lp == 0 else (Fore.YELLOW if lp <= 2 else (Fore.MAGENTA if lp <= 5 else Fore.RED))
        analysis_lines.append(f"• Pérdida de paquetes: {loss_color}{lp}%{Style.RESET_ALL}")
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
        stddev = metrics.get("rtt_stddev")
        analysis_lines.append(f"• Latencia (RTT): min={fmt_ms(minv)}, avg={fmt_ms(avg)}, max={fmt_ms(maxv)}")
        if stddev is not None:
            analysis_lines.append(f"  → Jitter/StdDev aproximado: {fmt_ms(stddev)}")
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
    if metrics["ttl"] is not None and metrics["ttl"] > 0:
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
    if lp is not None and lp > 5:
        analysis_lines.append("  - Alta pérdida detectada: Ejecutar pruebas desde otro punto de la red (otra máquina), comprobar cableado/puerto, y contactar ISP si el problema persiste.")
        analysis_lines.append("  - Ejecutar `mtr <host>` (Linux/macOS) o `pathping <host>` (Windows) para identificar dónde ocurre la pérdida.")
        analysis_lines.append("  - Repetir ping con más paquetes: `ping -c 50 <host>` (Linux) / `ping -n 50 <host>` (Windows).")
    elif metrics["rtt_avg"] is not None and metrics["rtt_avg"] > 200:
        analysis_lines.append("  - Latencia muy alta: probar trazas (`traceroute` / `tracert`) y contactar al proveedor si el cuello de botella está fuera de la red local.")
    else:
        analysis_lines.append("  - Si observas jitter o picos, realiza pruebas sostenidas (MTR) para localizar el salto problemático.")
        analysis_lines.append("  - Para pruebas más precisas, usar `ping` con payload y tamaño: `ping -s 1400 <host>` (Linux).")
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

    return "\n".join(analysis_lines), metrics

def analyze_traceroute_output(output, target):
    """Analiza la salida del comando traceroute y proporciona información detallada."""
    import re
    from colorama import Fore, Style
    
    analysis_lines = []
    analysis_lines.append(f"{Fore.CYAN}--- ANÁLISIS TRACEROUTE: {target} ---{Style.RESET_ALL}")

    # Métricas estructuradas
    metrics = {
        "target": target,
        "total_hops": 0,
        "timeout_hops": 0,
        "private_ips": 0,
        "max_latency": 0,
        "hops": [],
        "slow_hops": [],
        "reachable": False,
        "raw_output": output  # Guardar output original para debugging
    }

    # Si el output está vacío o es un mensaje de error
    if not output or "Error" in output or "error" in output:
        analysis_lines.append(f"{Fore.RED}❌ Error en traceroute: {output}{Style.RESET_ALL}")
        return "\n".join(analysis_lines), metrics

    lines = output.splitlines()
    
    hops = []
    total_hops = 0
    timeout_hops = 0
    private_ips = 0
    max_latency = 0
    slow_hops = []
    
    def is_private_ip(ip):
        """Verifica si una IP es privada"""
        if not ip or ip == '*' or ip in ['Tiempo', 'timeout', 'time', 'exceeded']:
            return False
            
        # Método simplificado para verificar IPs privadas
        if ip.startswith('10.') or ip.startswith('192.168.') or \
           (ip.startswith('172.') and 16 <= int(ip.split('.')[1]) <= 31) or \
           ip.startswith('169.254.') or ip.startswith('127.'):
            return True
        return False
    
    # Procesar cada línea - patrones para Windows tracert
    for line in lines:
        line = line.strip()
        
        # Saltar líneas vacías o de encabezado
        if not line or 'traceroute' in line.lower() or 'tracing' in line.lower() or 'traza' in line.lower():
            continue
        
        # Patrón para Windows tracert: "1     1 ms     1 ms     1 ms  192.168.1.1"
        if re.match(r'^\s*\d+\s+', line):
            # Dividir la línea en partes
            parts = re.split(r'\s{2,}', line)  # Dividir por 2+ espacios
            if len(parts) >= 5:
                try:
                    hop_num = int(parts[0].strip())
                    time1 = parts[1].strip()
                    time2 = parts[2].strip()
                    time3 = parts[3].strip()
                    host = parts[4].strip()
                    
                    # Extraer IP si está disponible
                    ip_match = re.search(r'(\d+\.\d+\.\d+\.\d+)', host)
                    ip = ip_match.group(1) if ip_match else host
                    
                    # Contar timeouts
                    timeouts = 0
                    for t in [time1, time2, time3]:
                        if t == '*' or 'timeout' in t.lower() or 'exceeded' in t.lower():
                            timeouts += 1
                    
                    hop_data = {
                        'hop': hop_num,
                        'times': [time1, time2, time3],
                        'host': host,
                        'ip': ip,
                        'is_private': is_private_ip(ip),
                        'timeouts': timeouts
                    }
                    
                    hops.append(hop_data)
                    metrics["hops"].append(hop_data)
                except (ValueError, IndexError):
                    continue
    
    # Analizar los datos recolectados
    total_hops = len(hops)
    metrics["total_hops"] = total_hops

    # Verificar si llegó al destino (último salto contiene el target o IP relacionada)
    if hops:
        last_hop = hops[-1]
        target_clean = target.replace('www.', '').lower()
        last_hop_host = last_hop['host'].lower()
        last_hop_ip = last_hop['ip'].lower()
    
        # Verificar si llegó al destino de varias maneras
        reached_destination = (
            target_clean in last_hop_host or
            target_clean in last_hop_ip or
            any(target_clean in hop['host'].lower() for hop in hops) or
            any(target_clean in hop['ip'].lower() for hop in hops) or
            # Si el último salto es una IP pública (no privada) probablemente llegó
            (not last_hop['is_private'] and last_hop['timeouts'] == 0)
        )
    
        if reached_destination:
            metrics["reachable"] = True
            analysis_lines.append(f"{Fore.GREEN}✅ Ruta completada hasta el destino{Style.RESET_ALL}")
        else:
            metrics["reachable"] = False
            analysis_lines.append(f"{Fore.YELLOW}⚠️  Ruta no completada hasta el destino{Style.RESET_ALL}")
    else:
        metrics["reachable"] = False
        analysis_lines.append(f"{Fore.RED}❌ No se detectaron saltos en el traceroute{Style.RESET_ALL}")
    
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
                    latency_str = re.sub(r'[^\d.]', '', time_str)
                    if latency_str:  # Asegurarse de que no esté vacío
                        latency = float(latency_str)
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
    
    metrics["timeout_hops"] = timeout_hops
    metrics["private_ips"] = private_ips
    metrics["max_latency"] = max_latency
    metrics["slow_hops"] = slow_hops
    
    # Generar análisis
    analysis_lines.append(f"• Saltos totales: {total_hops}")
    if total_hops > 0:
        analysis_lines.append(f"• Saltos con timeouts: {timeout_hops} ({timeout_hops/total_hops*100:.1f}%)")
    analysis_lines.append(f"• IPs privadas encontradas: {private_ips}")
    analysis_lines.append(f"• Latencia máxima: {max_latency} ms")
    
    # Análisis de saltos lentos (agrupados por número de salto)
    if slow_hops:
        # Eliminar duplicados y quedarnos con la máxima latencia por salto
        unique_slow_hops = {}
        for slow_hop in slow_hops:
            hop_num = slow_hop['hop']
            if hop_num not in unique_slow_hops or slow_hop['latency'] > unique_slow_hops[hop_num]['latency']:
                unique_slow_hops[hop_num] = slow_hop
        
        analysis_lines.append(f"• Saltos lentos (>100ms): {len(unique_slow_hops)}")
        for slow_hop in sorted(unique_slow_hops.values(), key=lambda x: x['latency'], reverse=True)[:5]:
            analysis_lines.append(f"  - Salto {slow_hop['hop']}: {slow_hop['latency']}ms ({slow_hop['host']})")
    
    # Identificar problemas de red
    if total_hops > 0 and timeout_hops / total_hops > 0.3:
        analysis_lines.append("⚠️  ALTO PORCENTAJE DE TIMEOUTS: Puede haber filtrado de paquetes o problemas de ruteo.")
    
    if private_ips > 0:
        analysis_lines.append("🔍 SE DETECTARON IPs PRIVADAS: La ruta pasa por redes internas/NAT.")
    
    # Mostrar información de cada salto
    analysis_lines.append("\n• Detalle de saltos:")
    for hop in hops:
        status = "🟢" if hop['timeouts'] == 0 else "🔴" if hop['timeouts'] == 3 else "🟡"
        private_flag = " (Privada)" if hop['is_private'] else ""
        
        # Mostrar latencia máxima del salto
        latency_info = ""
        if hop['hop'] in max_latency_by_hop and max_latency_by_hop[hop['hop']]['latency'] > 0:
            latency_info = f" [Máx: {max_latency_by_hop[hop['hop']]['latency']}ms]"
        
        analysis_lines.append(f"  {status} Salto {hop['hop']}: {hop['host']}{private_flag}{latency_info}")
        if hop['timeouts'] > 0:
            analysis_lines.append(f"     Timeouts: {hop['timeouts']}/3 intentos")
    
    analysis_lines.append("\n• Recomendaciones:")
    if max_latency > 200:
        analysis_lines.append("  - Latencia muy alta. Considerar proveedor de internet alternativo.")
    if timeout_hops > 0:
        analysis_lines.append("  - Timeouts detectados. Puede indicar filtrado de paquetes o congestión.")
    
    analysis_lines.append(f"{Fore.CYAN}{'-'*40}{Style.RESET_ALL}")

    return "\n".join(analysis_lines), metrics

def analyze_whois_output(output: str, domain: str) -> Tuple[str, Dict[str, Any]]:
    """Analiza la salida de WHOIS y devuelve análisis y métricas"""
    
    analysis_lines = []
    analysis_lines.append(f"{Fore.CYAN}--- ANÁLISIS WHOIS: {domain} ---{Style.RESET_ALL}")

    # Métricas estructuradas
    metrics = {
        "domain": domain,
        "creation_date": None,
        "expiration_date": None,
        "updated_date": None,
        "registrar": None,
        "name_servers": [],
        "domain_age_years": None,
        "days_until_expiration": None,
        "success": False,
        "timestamp": datetime.now().isoformat()
    }

    lines = output.split('\n')
    
    # Buscar información importante
    creation_date = None
    expiration_date = None
    updated_date = None
    registrar = None
    name_servers = []
    
    for line in lines:
        line = line.strip()
    
        # Fechas de creación - manejar múltiples formatos
        if 'creation_date' in line.lower() or 'fecha de creación' in line.lower():
            # Buscar patrones de fecha
            date_patterns = [
                r'(\d{4}[-/]\d{1,2}[-/]\d{1,2})',
                r'(\d{1,2}[-/]\d{1,2}[-/]\d{4})',
                r'(\d{4}-\d{2}-\d{2})',
                r'(\d{2}-\w{3}-\d{4})',  # 15-Sep-1997
                r'datetime\.datetime\((\d{4}), (\d{1,2}), (\d{1,2})'
            ]
        
            for pattern in date_patterns:
                match = re.search(pattern, line, re.IGNORECASE)
                if match:
                    if 'datetime' in pattern:
                        # Formato: datetime.datetime(1997, 9, 15, 4, 0)
                        year, month, day = match.groups()[:3]
                        creation_date = f"{year}-{month.zfill(2)}-{day.zfill(2)}"
                    else:
                        creation_date = match.group(1)
                    metrics["creation_date"] = creation_date
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
                    metrics["expiration_date"] = expiration_date
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
                    metrics["updated_date"] = updated_date
                    break
        
        # Registrador
        elif 'Registrador:' in line:
            registrar = line.split('Registrador:')[-1].strip()
            metrics["registrar"] = registrar
        
        # Servidores de nombres
        elif re.match(r'^\s*-\s+[A-Za-z0-9.-]+\.[A-Za-z]{2,}', line):
            ns = line.strip().lstrip('-').strip()
            if ns and ns not in name_servers:
                name_servers.append(ns)
                metrics["name_servers"].append(ns)
    
    # Calcular métricas adicionales
    if metrics["creation_date"]:
        try:
            creation_dt = datetime.strptime(metrics["creation_date"], '%Y-%m-%d')
            domain_age = (datetime.now() - creation_dt).days // 365
            metrics["domain_age_years"] = domain_age
        except:
            pass
    
    if metrics["expiration_date"]:
        try:
            expiration_dt = datetime.strptime(metrics["expiration_date"], '%Y-%m-%d')
            days_until_exp = (expiration_dt - datetime.now()).days
            metrics["days_until_expiration"] = days_until_exp
            metrics["success"] = True
        except:
            pass
    
    # Generar análisis en texto
    analysis_lines.append("• Información del dominio:")
    if creation_date:
        analysis_lines.append(f"  - Creación: {creation_date}")
    if expiration_date:
        analysis_lines.append(f"  - Expiración: {expiration_date}")
        if metrics["days_until_expiration"] is not None:
            days_left = metrics["days_until_expiration"]
            analysis_lines.append(f"  - Días hasta expiración: {days_left}")
            if days_left < 30:
                analysis_lines.append(f"  {Fore.RED}⚠️  ¡El dominio expira pronto!{Style.RESET_ALL}")
            elif days_left > 3650:
                analysis_lines.append(f"  {Fore.GREEN}✅ Dominio registrado por mucho tiempo{Style.RESET_ALL}")
    if updated_date:
        analysis_lines.append(f"  - Última actualización: {updated_date}")
        try:
            update_date = datetime.strptime(updated_date, '%Y-%m-%d')
            days_since_update = (datetime.now() - update_date).days
            if days_since_update > 365:
                analysis_lines.append(f"  {Fore.YELLOW}⚠️  Sin actualizaciones hace {days_since_update} días{Style.RESET_ALL}")
        except:
            pass
    
    if registrar:
        analysis_lines.append(f"• Registrador: {registrar}")
        if 'markmonitor' in registrar.lower():
            analysis_lines.append(f"  {Fore.GREEN}✅ Registrador profesional (empresas grandes){Style.RESET_ALL}")
        elif 'godaddy' in registrar.lower() or 'namecheap' in registrar.lower():
            analysis_lines.append(f"  {Fore.BLUE}ℹ️  Registrador popular (uso general){Style.RESET_ALL}")
    
    # Análisis de servidores de nombres
    if name_servers:
        analysis_lines.append(f"• Servidores DNS ({len(name_servers)}):")
        for ns in sorted(name_servers)[:4]:
            analysis_lines.append(f"  - {ns}")
        if len(name_servers) > 4:
            analysis_lines.append(f"  - ... y {len(name_servers) - 4} más")
        
        if len(name_servers) >= 2:
            analysis_lines.append(f"  {Fore.GREEN}✅ Configuración redundante (buena práctica){Style.RESET_ALL}")
        
        # Verificar si usa servidores propios
        domain_clean = domain.lower().replace('www.', '').split('.')[0]
        own_ns = sum(1 for ns in name_servers if domain_clean in ns.lower())
        
        if own_ns >= len(name_servers) / 2:
            analysis_lines.append(f"  {Fore.GREEN}✅ Usa servidores propios (configuración profesional){Style.RESET_ALL}")
        else:
            analysis_lines.append(f"  {Fore.BLUE}ℹ️  Usa servidores de terceros{Style.RESET_ALL}")
    
    # Estado del dominio
    analysis_lines.append("• Estado del dominio:")
    if metrics["domain_age_years"] is not None:
        domain_age = metrics["domain_age_years"]
        analysis_lines.append(f"  - Edad aproximada: {domain_age} años")
        if domain_age > 10:
            analysis_lines.append(f"  {Fore.GREEN}✅ Dominio antiguo (mayor confianza){Style.RESET_ALL}")
    
    # Recomendaciones de seguridad
    analysis_lines.append("\n• Recomendaciones:")
    analysis_lines.append("  - Verificar periodicamente los datos WHOIS")
    analysis_lines.append("  - Considerar protección de privacidad del dominio")
    analysis_lines.append("  - Mantener actualizada la información de contacto")
    
    analysis_lines.append(f"{Fore.CYAN}{'-'*40}{Style.RESET_ALL}")

    return "\n".join(analysis_lines), metrics

def analyze_dns_output_simple(output, domain, record_type='A'):
    """
    Análisis DNS simplificado sin métricas complejas
    """
    analysis_lines = []
    analysis_lines.append(f"{Fore.CYAN}--- ANÁLISIS DNS: {domain} ({record_type}) ---{Style.RESET_ALL}")

    lines = output.split('\n')
    ip_addresses = []
    
    for line in lines:
        line = line.strip()
        
        # Buscar IP addresses (IPv4 e IPv6)
        ipv4_match = re.search(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', line)
        ipv6_match = re.search(r'([0-9a-fA-F:]+:+)+[0-9a-fA-F]+', line)
        
        if ipv4_match:
            ip = ipv4_match.group()
            # Excluir IPs locales
            if not ip.startswith(('10.', '192.168.', '172.16.', '172.17.', '172.18.', '172.19.', 
                                '172.20.', '172.21.', '172.22.', '172.23.', '172.24.', '172.25.',
                                '172.26.', '172.27.', '172.28.', '172.29.', '172.30.', '172.31.')):
                if ip not in ip_addresses:
                    ip_addresses.append(ip)
        
        if ipv6_match:
            ip = ipv6_match.group()
            # Excluir IPs locales
            if not ip.startswith(('fe80:', '::1', 'fc00:', 'fd00:')):
                if ip not in ip_addresses:
                    ip_addresses.append(ip)
    
    # Generar análisis simple
    analysis_lines.append(f"• Dominio: {domain}")
    analysis_lines.append(f"• Tipo de registro: {record_type}")
    analysis_lines.append(f"• Direcciones encontradas: {len(ip_addresses)}")
    
    if ip_addresses:
        analysis_lines.append(f"• IPs encontradas:")
        for ip in ip_addresses[:6]:  # Mostrar máximo 6 IPs
            analysis_lines.append(f"  - {ip}")
        if len(ip_addresses) > 6:
            analysis_lines.append(f"  - ... y {len(ip_addresses) - 6} más")
    else:
        analysis_lines.append(f"{Fore.YELLOW}• No se encontraron registros {record_type}{Style.RESET_ALL}")
    
    # Recomendaciones básicas
    analysis_lines.append(f"\n{Fore.CYAN}• Recomendaciones:{Style.RESET_ALL}")
    if record_type == 'A' and len(ip_addresses) > 1:
        analysis_lines.append("  - Múltiples IPs: posible balanceo de carga o CDN")
    elif len(ip_addresses) == 0:
        analysis_lines.append("  - Intentar con otros tipos de registro (AAAA, MX, NS, TXT)")
    
    analysis_lines.append(f"{Fore.CYAN}{'-'*50}{Style.RESET_ALL}")

    return "\n".join(analysis_lines)


