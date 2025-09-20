"""Tests de humo - verificar que todo se puede importar y funciona básicamente"""
import pytest

class TestSmoke:
    """Tests de humo para verificar imports básicos"""
    
    def test_import_main_modules(self):
        """Test que los módulos principales se pueden importar"""
        # Esto no debería fallar
        from network_toolkit import network_tools
        from network_toolkit import analysis_tools
        from network_toolkit import history_tools
        from network_toolkit import whois_tools
        from network_toolkit import utils
        
        assert True  # Si llegamos aquí, los imports funcionan
    
    def test_import_main_functions(self):
        """Test que las funciones principales existen"""
        from network_toolkit.network_tools import ping_target, traceroute_target
        from network_toolkit.analysis_tools import analyse_ping_output, analyze_traceroute_output, analyze_whois_output
        from network_toolkit.whois_tools import get_whois_info
        from network_toolkit.history_tools import NetworkHistoryManager
        
        # Verificar que son callables (funciones)
        assert callable(ping_target)
        assert callable(traceroute_target)
        assert callable(analyse_ping_output)
        assert callable(analyze_traceroute_output)
        assert callable(analyze_whois_output)
        assert callable(get_whois_info)
        
        # Verificar que NetworkHistoryManager es una clase
        assert isinstance(NetworkHistoryManager, type)
    
    def test_colorama_available(self):
        """Test que colorama está disponible"""
        try:
            from network_toolkit.utils import init_colorama
            fore, style = init_colorama()
            assert fore is not None
            assert style is not None
            assert hasattr(fore, 'RED')
            assert hasattr(style, 'RESET_ALL')
        except ImportError:
            pytest.skip("Colorama no está disponible")
