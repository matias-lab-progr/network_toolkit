"""Tests unitarios para network_tools.py"""
import subprocess
import pytest
from unittest.mock import Mock, patch, MagicMock
from network_toolkit.network_tools import ping_target, traceroute_target

class TestNetworkTools:
    """Tests para las herramientas de red"""
    
    @patch('network_toolkit.network_tools.subprocess.run')
    def test_ping_target_linux(self, mock_subprocess):
        """Test ping_target en Linux"""
        # Configurar mock
        mock_result = Mock()
        mock_result.returncode = 0
        mock_result.stdout = "64 bytes from google.com: icmp_seq=1 ttl=115 time=15.3 ms"
        mock_subprocess.return_value = mock_result
        
        # Ejecutar
        result = ping_target("google.com", "linux", count=2)
        
        # Verificar
        assert "google.com" in result
        mock_subprocess.assert_called_once()
    
    @patch('network_toolkit.network_tools.subprocess.run')
    def test_ping_target_windows(self, mock_subprocess):
        """Test ping_target en Windows"""
        mock_result = Mock()
        mock_result.returncode = 0
        # Output REAL de Windows
        mock_result.stdout = """
    Haciendo ping a google.com [172.217.16.14] con 32 bytes de datos:
    Respuesta desde 172.217.16.14: bytes=32 tiempo=15ms TTL=115
    Respuesta desde 172.217.16.14: bytes=32 tiempo=16ms TTL=115
    Respuesta desde 172.217.16.14: bytes=32 tiempo=15ms TTL=115
    Respuesta desde 172.217.16.14: bytes=32 tiempo=16ms TTL=115

    Estadísticas de ping para 172.217.16.14:
        Paquetes: enviados = 4, recibidos = 4, perdidos = 0
        (0% perdidos),
    """
        mock_subprocess.return_value = mock_result
    
        result = ping_target("google.com", "windows", count=4)
    
        assert "google.com" in result or "172.217.16.14" in result
        mock_subprocess.assert_called_once()
    
    @patch('network_toolkit.network_tools.subprocess.run')
    def test_ping_target_timeout(self, mock_subprocess):
        """Test ping_target con timeout"""
        mock_subprocess.side_effect = TimeoutError("Timeout")
        
        result = ping_target("google.com", "linux", count=2)
        
        assert "Timeout" in result or "Error" in result
    
    @patch('network_toolkit.network_tools.subprocess.run')
    @patch('network_toolkit.network_tools.platform.system')
    def test_traceroute_linux(self, mock_run, mock_system):
        """Test traceroute en Linux con output simulado."""
        mock_system.return_value = 'Linux'

        # Simular output real de traceroute en Linux
        traceroute_output = """traceroute to example.com (93.184.216.34), 30 hops max, 60 byte packets
    1  192.168.1.1 (192.168.1.1)  1.234 ms  1.456 ms  1.678 ms
    2  10.0.0.1 (10.0.0.1)  5.432 ms  5.678 ms  5.901 ms
    3  93.184.216.34 (93.184.216.34)  15.123 ms  15.456 ms  15.789 ms
    """

        mock_run.return_value = subprocess.CompletedProcess(
            args=['traceroute', 'example.com'],
            returncode=0,
            stdout=traceroute_output,
            stderr=''
        )

        # Pasar el SO explícitamente para evitar detección automática
        result = traceroute_target('example.com', 'Linux')  # ← Añadir 'Linux' aquí
        assert 'hops' in result
        assert '93.184.216.34' in result
        assert '192.168.1.1' in result
    
    @patch('network_toolkit.network_tools.subprocess.run')
    @patch('network_toolkit.network_tools.platform.system')
    def test_traceroute_windows(self, mock_run, mock_system):
        """Test traceroute en Windows con output simulado."""
        mock_system.return_value = 'Windows'

        # Simular output real de tracert en Windows
        tracert_output = """Traza de ruta a example.com [93.184.216.34]
    sobre un máximo de 30 saltos:

    1    <1 ms    <1 ms    <1 ms  192.168.1.1
    2     5 ms     6 ms     5 ms  10.0.0.1
    3    15 ms    16 ms    15 ms  93.184.216.34

    Traza completa.
    """

        mock_run.return_value = subprocess.CompletedProcess(
            args=['tracert', 'example.com'],
            returncode=0,
            stdout=tracert_output,
            stderr=''
        )

        # Pasar el SO explícitamente para evitar detección automática
        result = traceroute_target('example.com', 'Windows')  # ← Añadir 'Windows' aquí
        assert 'saltos' in result or 'hops' in result
        assert '93.184.216.34' in result


