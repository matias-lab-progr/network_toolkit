# network_toolkit/whois_tools.py
"""
Módulo de herramientas WHOIS para Network Toolkit - Consultas de información de dominio
"""

import platform
import subprocess
import requests
import json
import re
from datetime import datetime
from colorama import Fore, Style
from typing import Dict, Any, Tuple

from .utils import is_dependency_available, run_command

def get_whois_info(domain: str) -> Tuple[str, Dict[str, Any]]:
    """Obtiene información WHOIS y devuelve tanto el output como métricas estructuradas"""
    
    output = ""
    metrics = {
        "domain": domain,
        "creation_date": None,
        "expiration_date": None,
        "updated_date": None,
        "registrar": None,
        "name_servers": [],
        "domain_age_years": None,
        "days_until_expiration": None,
        "success": False
    }
    
    # Verificar si whois está disponible
    if not is_dependency_available('whois'):
        error_msg = "ERROR: La biblioteca python-whois no está disponible.\n"
        error_msg += "Para usar la funcionalidad WHOIS, instálela con:\n"
        error_msg += "  pip install python-whois\n\n"
        error_msg += "Como alternativa, puede usar el comando whois del sistema.\n"
        
        # Intentar con comando whois del sistema como fallback
        try:
            if platform.system().lower() == "windows":
                check_result = subprocess.run("where whois", shell=True, 
                                            capture_output=True, text=True, timeout=10)
                if check_result.returncode == 0:
                    output = run_command(f"whois {domain}")
                    metrics["success"] = True
                    return output, metrics
                else:
                    error_msg += "El comando whois tampoco está disponible en el sistema."
            else:
                # Linux/macOS
                output = run_command(f"whois {domain}")
                metrics["success"] = True
                return output, metrics
        except Exception as e:
            error_msg += f"Error al intentar usar comando whois del sistema: {str(e)}"
        
        return error_msg, metrics
    
    # Si whois está disponible, usar la biblioteca
    try:
        import whois
        whois_info = whois.whois(domain)
        
        output = f"Información WHOIS para {domain}:\n\n"
        output += f"Nombre de dominio: {whois_info.domain_name}\n"
        output += f"Registrador: {whois_info.registrar}\n"
        output += f"Fecha de creación: {whois_info.creation_date}\n"
        output += f"Fecha de expiración: {whois_info.expiration_date}\n"
        output += f"Última actualización: {whois_info.updated_date}\n"
        
        if whois_info.name_servers:
            output += f"\nServidores de nombres:\n"
            for ns in whois_info.name_servers:
                output += f"  - {ns}\n"
        
        # Extraer métricas estructuradas
        metrics["success"] = True
        metrics["registrar"] = str(whois_info.registrar) if whois_info.registrar else None
        metrics["name_servers"] = [str(ns) for ns in whois_info.name_servers] if whois_info.name_servers else []
        
        # Procesar fechas
        def parse_whois_date(date_obj):
            if isinstance(date_obj, list) and date_obj:
                date_obj = date_obj[0]
            if isinstance(date_obj, datetime):
                return date_obj.isoformat()
            elif isinstance(date_obj, str):
                try:
                    # Intentar parsear diferentes formatos de fecha
                    for fmt in ['%Y-%m-%d', '%d-%b-%Y', '%Y/%m/%d', '%Y.%m.%d']:
                        try:
                            return datetime.strptime(date_obj[:10], fmt).isoformat()
                        except:
                            continue
                except:
                    pass
            return None
        
        metrics["creation_date"] = parse_whois_date(whois_info.creation_date)
        metrics["expiration_date"] = parse_whois_date(whois_info.expiration_date)
        metrics["updated_date"] = parse_whois_date(whois_info.updated_date)
        
        # Calcular edad del dominio y días hasta expiración
        if metrics["creation_date"]:
            try:
                creation_dt = datetime.fromisoformat(metrics["creation_date"])
                domain_age = (datetime.now() - creation_dt).days // 365
                metrics["domain_age_years"] = domain_age
            except:
                pass
        
        if metrics["expiration_date"]:
            try:
                expiration_dt = datetime.fromisoformat(metrics["expiration_date"])
                days_until_exp = (expiration_dt - datetime.now()).days
                metrics["days_until_expiration"] = days_until_exp
            except:
                pass
        
        return output, metrics
        
    except Exception as e:
        error_msg = f"Error al obtener información WHOIS: {str(e)}"
        return error_msg, metrics


def parse_whois_date(date_obj):
    """Convierte objetos de fecha WHOIS a string ISO format"""
    if date_obj is None:
        return None
    
    # Si es una lista, tomar el primer elemento
    if isinstance(date_obj, list) and date_obj:
        date_obj = date_obj[0]
    
    # Si ya es datetime, convertirlo a ISO
    if isinstance(date_obj, datetime):
        return date_obj.isoformat()
    
    # Si es string, intentar parsearlo
    elif isinstance(date_obj, str):
        try:
            # Intentar diferentes formatos de fecha comunes en WHOIS
            date_formats = [
                '%Y-%m-%d %H:%M:%S',
                '%Y-%m-%d',
                '%d-%b-%Y',
                '%Y/%m/%d',
                '%Y.%m.%d',
                '%Y-%m-%dT%H:%M:%S%z',
                '%Y-%m-%dT%H:%M:%S.%f%z',
                '%Y-%m-%d %H:%M:%S.%f%z'
            ]
            
            for fmt in date_formats:
                try:
                    parsed_date = datetime.strptime(date_obj, fmt)
                    return parsed_date.isoformat()
                except ValueError:
                    continue
            
            # Si ninguno funciona, intentar extraer la parte de fecha
            date_match = re.search(r'(\d{4}[-/]\d{1,2}[-/]\d{1,2})', date_obj)
            if date_match:
                return date_match.group(1)
                
        except Exception:
            pass
    
    return None