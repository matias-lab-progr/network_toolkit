# network_toolkit/utils.py
"""
Módulo de utilidades para Network Toolkit - Funciones auxiliares y de configuración
"""
import json
import os
import subprocess
import re
from colorama import Fore, Style, init
import dns

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
    # Ejecuta un comando y devuelve su salida.
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

def check_network_connectivity():
    try:
        dns.resolver.resolve('google.com', 'A')
        return True
    except:
        return False

def load_ip_ranges():
    """
    Carga los rangos de IP desde el archivo JSON.
    """
    try:
        # Obtener la ruta al archivo data/ip_ranges.json
        current_dir = os.path.dirname(os.path.abspath(__file__))
        data_file = os.path.join(current_dir, 'data', 'ip_ranges.json')
        
        with open(data_file, 'r', encoding='utf-8') as f:
            return json.load(f)
            
    except FileNotFoundError:
        print(f"{Fore.YELLOW}[!] Archivo de rangos IP no encontrado{Style.RESET_ALL}")
        return {}
    except json.JSONDecodeError:
        print(f"{Fore.RED}[!] Error leyendo archivo de rangos IP{Style.RESET_ALL}")
        return {}
    except Exception as e:
        print(f"{Fore.RED}[!] Error cargando rangos IP: {str(e)}{Style.RESET_ALL}")
        return {}



