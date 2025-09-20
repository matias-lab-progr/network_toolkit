import json
from pathlib import Path
from typing import Dict, List, Optional, Any, Union
from datetime import datetime
import os

class NetworkHistoryManager:
    def __init__(self, data_dir: str = None, max_entries_per_host: int = 200):
        # Usar ruta relativa al directorio del paquete
        if data_dir is None:
            base_dir = Path(__file__).parent
            self.data_dir = base_dir / "data"
        else:
            self.data_dir = Path(data_dir)
            
        self.history_file = self.data_dir / "network_history.json"
        self.max_entries_per_host = max_entries_per_host
        self._ensure_data_dir()
    
    def _ensure_data_dir(self) -> None:
        """Asegura que el directorio data existe"""
        self.data_dir.mkdir(exist_ok=True)
        if not self.history_file.exists():
            self.history_file.write_text("{}")
    
    def save_result(self, target: str, tool_type: str, metrics: Dict[str, Any]) -> bool:
        """
        Guarda los resultados de cualquier herramienta de red en el historial
        
        Args:
            target: IP o dominio
            tool_type: Tipo de herramienta ('ping', 'traceroute', 'dns', 'whois', 'geoip')
            metrics: Métricas del comando
        
        Returns:
            bool: True si se guardó correctamente
        """
        try:
            # Leer historial existente
            history = self._load_history()
            
            # Crear clave única para este host y tipo de herramienta
            history_key = f"{target}_{tool_type}"
            
            # Asegurar que existe la entrada para este host+tool
            if history_key not in history:
                history[history_key] = []
            
            # Agregar timestamp a las métricas
            metrics_with_timestamp = metrics.copy()
            metrics_with_timestamp["timestamp"] = datetime.now().isoformat()
            metrics_with_timestamp["tool_type"] = tool_type
            
            # Agregar nueva entrada
            history[history_key].append(metrics_with_timestamp)
            
            # Limitar número de entradas por host+tool
            if len(history[history_key]) > self.max_entries_per_host:
                history[history_key] = history[history_key][-self.max_entries_per_host:]
            
            # Guardar historial
            self._save_history(history)
            return True
        except Exception as e:
            print(f"Error guardando historial: {e}")
            return False
    
    def load_results(self, target: Optional[str] = None, tool_type: Optional[str] = None) -> Dict[str, Any]:
        """
        Carga resultados del historial
    
        Args:
            target: IP o dominio específico (None para todos)
            tool_type: Tipo de herramienta específica (None para todas)
    
        Returns:
            Dict: Historial filtrado
        """
        history = self._load_history()
        filtered_history = {}
    
        for key, entries in history.items():
            # Extraer target y tipo de la clave (formato: target_tooltype)
            if '_' in key:
                # Dividir por el último guión bajo
                parts = key.rsplit('_', 1)
                if len(parts) == 2:
                    key_target = parts[0]  # Todo antes del último _
                    key_tool = parts[1]    # Último elemento después del _
                else:
                    key_target = key
                    key_tool = "unknown"
            else:
                key_target = key
                key_tool = "unknown"
        
            # Filtrar por target si se especifica
            if target and key_target != target:
                continue
            
            # Filtrar por tipo de herramienta si se especifica
            if tool_type and key_tool != tool_type:
                continue
        
            filtered_history[key] = entries
    
        return filtered_history
    
    def get_history_summary(self) -> List[Dict[str, Any]]:
        """
        Obtiene un resumen del historial completo
    
        Returns:
            List: Resumen con última métrica de cada host+tool
        """
        history = self._load_history()
        summary = []
    
        for key, entries in history.items():
            if entries:
                # Extraer target y tipo de la clave (formato: target_tooltype)
                if '_' in key:
                    parts = key.rsplit('_', 1)
                    if len(parts) == 2:
                        target = parts[0]
                        tool_type = parts[1]
                    else:
                        target = key
                        tool_type = "unknown"
                else:
                    target = key
                    tool_type = "unknown"
            
                latest = entries[-1]  # Última entrada
                summary.append({
                    "target": target,
                    "tool_type": tool_type,
                    "last_check": latest.get("timestamp", ""),
                    "reachable": latest.get("reachable", None),
                    "metrics": {k: v for k, v in latest.items() if k not in ['timestamp', 'tool_type']}
                })
    
        return summary
    
    def clear_history(self, target: Optional[str] = None, tool_type: Optional[str] = None) -> bool:
        """
        Borra el historial completo o de un host específico
    
        Args:
            target: IP o dominio específico (None para borrar todo)
            tool_type: Tipo de herramienta específica (None para todas)
    
        Returns:
            bool: True si se borró correctamente
        """
        try:
            if target is None and tool_type is None:
                # Borrar todo
                self.history_file.write_text("{}")
            else:
                # Borrar selectivamente
                history = self._load_history()
                keys_to_delete = []
            
                for key in history.keys():
                    # Extraer target y tipo de la clave
                    if '_' in key:
                        parts = key.rsplit('_', 1)
                        if len(parts) == 2:
                            key_target = parts[0]
                            key_tool = parts[1]
                        else:
                            key_target = key
                            key_tool = "unknown"
                    else:
                        key_target = key
                        key_tool = "unknown"
                
                    # Verificar si cumple con los criterios de borrado
                    delete = True
                    if target and key_target != target:
                        delete = False
                    if tool_type and key_tool != tool_type:
                        delete = False
                
                    if delete:
                        keys_to_delete.append(key)
            
                # Eliminar las claves seleccionadas
                for key in keys_to_delete:
                    if key in history:
                        del history[key]
            
                self._save_history(history)
            return True
        except Exception as e:
            print(f"Error borrando historial: {e}")
            return False
    
    def _load_history(self) -> Dict[str, Any]:
        """Carga el historial desde el archivo JSON"""
        try:
            if self.history_file.exists():
                return json.loads(self.history_file.read_text())
            return {}
        except:
            return {}
    
    def _save_history(self, history: Dict[str, Any]) -> None:
        """Guarda el historial en el archivo JSON"""
        self.history_file.write_text(json.dumps(history, indent=2))

# Instancia global para fácil acceso
network_history = NetworkHistoryManager()