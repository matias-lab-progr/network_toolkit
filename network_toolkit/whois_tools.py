# network_toolkit/whois_tools.py
"""
Módulo de herramientas WHOIS para Network Toolkit - Consultas de información de dominio
"""

import platform
import subprocess
import requests
import json
from colorama import Fore, Style

from .utils import is_dependency_available, run_command

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

