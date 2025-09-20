import pytest
import platform
import subprocess
from unittest.mock import MagicMock, patch, mock_open
from network_toolkit.whois_tools import (
    get_whois_info,
    get_whois_info_enhanced
)

class TestWhoisTools:
    """Test cases for whois_tools module"""

    @patch('network_toolkit.whois_tools.is_dependency_available')
    @patch('network_toolkit.whois_tools.subprocess.run')
    def test_get_whois_info_whois_not_available_windows(self, mock_subprocess, mock_is_dependency):
        """Test get_whois_info when whois is not available on Windows"""
        mock_is_dependency.return_value = False
        
        # Mock Windows platform
        with patch('platform.system', return_value='Windows'):
            # Mock where command failing (whois not installed)
            mock_check_result = MagicMock()
            mock_check_result.returncode = 1
            mock_subprocess.return_value = mock_check_result
            
            result = get_whois_info('example.com')
            
            assert 'python-whois no está disponible' in result
            assert 'pip install python-whois' in result
            mock_subprocess.assert_called_once_with("where whois", shell=True, capture_output=True, text=True, timeout=10)

    @patch('network_toolkit.whois_tools.is_dependency_available')
    @patch('network_toolkit.whois_tools.subprocess.run')
    def test_get_whois_info_whois_not_available_linux(self, mock_subprocess, mock_is_dependency):
        """Test get_whois_info when whois is not available on Linux"""
        mock_is_dependency.return_value = False
        
        # Mock Linux platform
        with patch('platform.system', return_value='Linux'):
            # Mock run_command for whois
            with patch('network_toolkit.whois_tools.run_command') as mock_run_command:
                mock_run_command.return_value = 'whois results'
                
                result = get_whois_info('example.com')
                
                mock_run_command.assert_called_once_with('whois example.com')

    @patch('network_toolkit.whois_tools.is_dependency_available')
    def test_get_whois_info_with_whois_available(self, mock_is_dependency):
        """Test get_whois_info when whois library is available"""
        mock_is_dependency.return_value = True
        
        # Mock whois library
        with patch('network_toolkit.whois_tools.whois') as mock_whois:
            mock_whois_info = MagicMock()
            mock_whois_info.domain_name = 'example.com'
            mock_whois_info.registrar = 'Example Registrar'
            mock_whois_info.creation_date = '2020-01-01'
            mock_whois_info.expiration_date = '2025-01-01'
            mock_whois_info.updated_date = '2023-01-01'
            mock_whois_info.name_servers = ['ns1.example.com', 'ns2.example.com']
            
            mock_whois.whois.return_value = mock_whois_info
            
            result = get_whois_info('example.com')
            
            assert 'example.com' in result
            assert 'Example Registrar' in result
            assert 'ns1.example.com' in result
            assert 'ns2.example.com' in result

    @patch('network_toolkit.whois_tools.is_dependency_available')
    def test_get_whois_info_whois_exception(self, mock_is_dependency):
        """Test get_whois_info when whois library raises exception"""
        mock_is_dependency.return_value = True
        
        # Mock whois library raising exception
        with patch('network_toolkit.whois_tools.whois') as mock_whois:
            mock_whois.whois.side_effect = Exception('WHOIS query failed')
            
            result = get_whois_info('example.com')
            
            assert 'Error al obtener información WHOIS' in result

    @patch('network_toolkit.whois_tools.is_dependency_available')
    @patch('network_toolkit.whois_tools.subprocess.run')
    @patch('network_toolkit.whois_tools.run_command')
    def test_get_whois_info_enhanced_whois_available(self, mock_run_command, mock_subprocess, mock_is_dependency):
        """Test get_whois_info_enhanced with whois library available"""
        mock_is_dependency.return_value = True
        
        # Mock whois library
        with patch('network_toolkit.whois_tools.whois') as mock_whois:
            mock_whois_info = MagicMock()
            mock_whois_info.domain_name = 'example.com'
            mock_whois_info.registrar = 'Example Registrar'
            mock_whois_info.creation_date = '2020-01-01'
            mock_whois_info.expiration_date = '2025-01-01'
            mock_whois_info.updated_date = '2023-01-01'
            mock_whois_info.name_servers = ['ns1.example.com']
            
            mock_whois.whois.return_value = mock_whois_info
            
            result = get_whois_info_enhanced('example.com')
            
            assert 'example.com' in result
            assert 'Example Registrar' in result
            assert 'ns1.example.com' in result

    @patch('network_toolkit.whois_tools.is_dependency_available')
    @patch('network_toolkit.whois_tools.subprocess.run')
    @patch('network_toolkit.whois_tools.run_command')
    def test_get_whois_info_enhanced_system_command(self, mock_run_command, mock_subprocess, mock_is_dependency):
        """Test get_whois_info_enhanced using system command"""
        mock_is_dependency.return_value = False
        
        # Mock Windows platform with whois installed
        with patch('platform.system', return_value='Windows'):
            # Mock where command success
            mock_check_result = MagicMock()
            mock_check_result.returncode = 0
            mock_subprocess.return_value = mock_check_result
            
            # Mock run_command for whois
            mock_run_command.return_value = 'whois command results'
            
            result = get_whois_info_enhanced('example.com')
            
            mock_run_command.assert_called_once_with('whois example.com')
            assert result == 'whois command results'

    @patch('network_toolkit.whois_tools.is_dependency_available')
    @patch('network_toolkit.whois_tools.subprocess.run')
    @patch('network_toolkit.whois_tools.run_command')
    def test_get_whois_info_enhanced_linux_system_command(self, mock_run_command, mock_subprocess, mock_is_dependency):
        """Test get_whois_info_enhanced on Linux using system command"""
        mock_is_dependency.return_value = False
        
        # Mock Linux platform
        with patch('platform.system', return_value='Linux'):
            # Mock run_command for whois
            mock_run_command.return_value = 'whois results linux'
            
            result = get_whois_info_enhanced('example.com')
            
            mock_run_command.assert_called_once_with('whois example.com')
            assert result == 'whois results linux'

    @patch('network_toolkit.whois_tools.is_dependency_available')
    @patch('network_toolkit.whois_tools.subprocess.run')
    @patch('network_toolkit.whois_tools.run_command')
    @patch('network_toolkit.whois_tools.requests.get')
    def test_get_whois_info_enhanced_api_fallback(self, mock_requests, mock_run_command, mock_subprocess, mock_is_dependency):
        """Test get_whois_info_enhanced falling back to API"""
        mock_is_dependency.return_value = False
        
        # Mock Windows platform without whois
        with patch('platform.system', return_value='Windows'):
            # Mock where command failing
            mock_check_result = MagicMock()
            mock_check_result.returncode = 1
            mock_subprocess.return_value = mock_check_result
            
            # Mock run_command failing
            mock_run_command.side_effect = Exception('Command failed')
            
            # Mock API response
            mock_response = MagicMock()
            mock_response.status_code = 200
            mock_response.json.return_value = {'domain': 'example.com', 'registrar': 'Test Registrar'}
            mock_requests.return_value = mock_response
            
            result = get_whois_info_enhanced('example.com')
            
            assert 'example.com' in result
            assert 'Test Registrar' in result
            mock_requests.assert_called()

    @patch('network_toolkit.whois_tools.is_dependency_available')
    @patch('network_toolkit.whois_tools.subprocess.run')
    @patch('network_toolkit.whois_tools.run_command')
    @patch('network_toolkit.whois_tools.requests.get')
    def test_get_whois_info_enhanced_all_methods_fail(self, mock_requests, mock_run_command, mock_subprocess, mock_is_dependency):
        """Test get_whois_info_enhanced when all methods fail"""
        mock_is_dependency.return_value = False
        
        # Mock Windows platform without whois
        with patch('platform.system', return_value='Windows'):
            # Mock where command failing
            mock_check_result = MagicMock()
            mock_check_result.returncode = 1
            mock_subprocess.return_value = mock_check_result
            
            # Mock run_command failing
            mock_run_command.side_effect = Exception('Command failed')
            
            # Mock API failing
            mock_requests.side_effect = Exception('API failed')
            
            result = get_whois_info_enhanced('example.com')
            
            assert 'No se pudo obtener información WHOIS' in result
            assert 'Métodos intentados' in result
            assert 'Soluciones posibles' in result

    @patch('network_toolkit.whois_tools.is_dependency_available')
    @patch('network_toolkit.whois_tools.whois')
    def test_get_whois_info_enhanced_whois_exception(self, mock_whois, mock_is_dependency):
        """Test get_whois_info_enhanced when whois library raises exception"""
        mock_is_dependency.return_value = True
        mock_whois.whois.side_effect = Exception('WHOIS failed')
        
        # Mock subsequent methods
        with patch('network_toolkit.whois_tools.subprocess.run') as mock_subprocess:
            with patch('network_toolkit.whois_tools.run_command') as mock_run_command:
                mock_run_command.return_value = 'system whois results'
                
                result = get_whois_info_enhanced('example.com')
                
                assert result == 'system whois results'

    @patch('network_toolkit.whois_tools.is_dependency_available')
    @patch('network_toolkit.whois_tools.requests.get')
    def test_get_whois_info_enhanced_api_json_response(self, mock_requests, mock_is_dependency):
        """Test get_whois_info_enhanced with API returning JSON"""
        mock_is_dependency.return_value = False
        
        # Mock all previous methods failing
        with patch('platform.system', return_value='Windows'):
            with patch('network_toolkit.whois_tools.subprocess.run') as mock_subprocess:
                with patch('network_toolkit.whois_tools.run_command') as mock_run_command:
                    mock_subprocess.return_value.returncode = 1
                    mock_run_command.side_effect = Exception('Command failed')
                    
                    # Mock API JSON response
                    mock_response = MagicMock()
                    mock_response.status_code = 200
                    mock_response.json.return_value = {
                        'domain': 'example.com',
                        'registrar': 'JSON Registrar',
                        'creation_date': '2020-01-01'
                    }
                    mock_requests.return_value = mock_response
                    
                    result = get_whois_info_enhanced('example.com')
                    
                    assert 'JSON Registrar' in result
                    assert '2020-01-01' in result

    @patch('network_toolkit.whois_tools.is_dependency_available')
    @patch('network_toolkit.whois_tools.requests.get')
    def test_get_whois_info_enhanced_api_text_response(self, mock_requests, mock_is_dependency):
        """Test get_whois_info_enhanced with API returning text"""
        mock_is_dependency.return_value = False
        
        # Mock all previous methods failing
        with patch('platform.system', return_value='Windows'):
            with patch('network_toolkit.whois_tools.subprocess.run') as mock_subprocess:
                with patch('network_toolkit.whois_tools.run_command') as mock_run_command:
                    mock_subprocess.return_value.returncode = 1
                    mock_run_command.side_effect = Exception('Command failed')
                    
                    # Mock API text response (not JSON)
                    mock_response = MagicMock()
                    mock_response.status_code = 200
                    mock_response.json.side_effect = ValueError('Not JSON')
                    mock_response.text = 'Raw WHOIS text information'
                    mock_requests.return_value = mock_response
                    
                    result = get_whois_info_enhanced('example.com')
                    
                    assert 'Raw WHOIS text information' in result

    @patch('network_toolkit.whois_tools.is_dependency_available')
    @patch('network_toolkit.whois_tools.requests.get')
    def test_get_whois_info_enhanced_api_http_error(self, mock_requests, mock_is_dependency):
        """Test get_whois_info_enhanced with API HTTP error"""
        mock_is_dependency.return_value = False
        
        # Mock all previous methods failing
        with patch('platform.system', return_value='Windows'):
            with patch('network_toolkit.whois_tools.subprocess.run') as mock_subprocess:
                with patch('network_toolkit.whois_tools.run_command') as mock_run_command:
                    mock_subprocess.return_value.returncode = 1
                    mock_run_command.side_effect = Exception('Command failed')
                    
                    # Mock API HTTP error
                    mock_response = MagicMock()
                    mock_response.status_code = 404
                    mock_requests.return_value = mock_response
                    
                    result = get_whois_info_enhanced('example.com')
                    
                    # Should continue to next API
                    mock_requests.assert_called()

    @patch('network_toolkit.whois_tools.is_dependency_available')
    def test_get_whois_info_enhanced_whois_no_name_servers(self, mock_is_dependency):
        """Test get_whois_info_enhanced with whois but no name servers"""
        mock_is_dependency.return_value = True
        
        # Mock whois library
        with patch('network_toolkit.whois_tools.whois') as mock_whois:
            mock_whois_info = MagicMock()
            mock_whois_info.domain_name = 'example.com'
            mock_whois_info.registrar = 'Example Registrar'
            mock_whois_info.creation_date = '2020-01-01'
            mock_whois_info.expiration_date = '2025-01-01'
            mock_whois_info.updated_date = '2023-01-01'
            mock_whois_info.name_servers = None  # No name servers
            
            mock_whois.whois.return_value = mock_whois_info
            
            result = get_whois_info_enhanced('example.com')
            
            assert 'example.com' in result
            assert 'Example Registrar' in result
            # Should not crash with None name_servers

    @patch('network_toolkit.whois_tools.is_dependency_available')
    @patch('network_toolkit.whois_tools.subprocess.run')
    def test_get_whois_info_windows_whois_installed(self, mock_subprocess, mock_is_dependency):
        """Test get_whois_info on Windows with whois installed"""
        mock_is_dependency.return_value = False
        
        # Mock Windows platform with whois installed
        with patch('platform.system', return_value='Windows'):
            # Mock where command success
            mock_check_result = MagicMock()
            mock_check_result.returncode = 0
            mock_subprocess.return_value = mock_check_result
            
            # Mock run_command for whois
            with patch('network_toolkit.whois_tools.run_command') as mock_run_command:
                mock_run_command.return_value = 'Windows whois results'
                
                result = get_whois_info('example.com')
                
                mock_run_command.assert_called_once_with('whois example.com')
                assert result == 'Windows whois results'