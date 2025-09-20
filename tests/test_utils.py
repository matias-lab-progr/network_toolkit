import pytest
import json
import os
import subprocess
import re
from unittest.mock import MagicMock, patch, mock_open
from network_toolkit.utils import (
    OPTIONAL_DEPENDENCIES,
    check_optional_dependencies,
    is_dependency_available,
    init_colorama,
    run_command,
    run_command_realtime,
    is_valid_ip,
    is_valid_domain,
    is_valid_target,
    get_raw_mode_input,
    check_network_connectivity,
    load_ip_ranges
)

class TestUtils:
    """Test cases for utils module"""

    @patch('network_toolkit.utils.__import__')
    def test_check_optional_dependencies_available(self, mock_import):
        """Test checking optional dependencies when available"""
        # Mock successful import
        mock_import.return_value = MagicMock()
        
        check_optional_dependencies()
        
        # All dependencies should be marked as available
        for dep_info in OPTIONAL_DEPENDENCIES.values():
            assert dep_info['available'] == True

    @patch('network_toolkit.utils.__import__')
    def test_check_optional_dependencies_unavailable(self, mock_import):
        """Test checking optional dependencies when unavailable"""
        # Mock import failure
        mock_import.side_effect = ImportError('Module not found')
        
        check_optional_dependencies()
        
        # All dependencies should be marked as unavailable
        for dep_info in OPTIONAL_DEPENDENCIES.values():
            assert dep_info['available'] == False

    def test_is_dependency_available_true(self):
        """Test is_dependency_available when dependency is available"""
        # Set a dependency as available
        OPTIONAL_DEPENDENCIES['colorama']['available'] = True
        
        result = is_dependency_available('colorama')
        assert result == True

    def test_is_dependency_available_false(self):
        """Test is_dependency_available when dependency is unavailable"""
        # Set a dependency as unavailable
        OPTIONAL_DEPENDENCIES['colorama']['available'] = False
        
        result = is_dependency_available('colorama')
        assert result == False

    def test_is_dependency_available_unknown(self):
        """Test is_dependency_available for unknown dependency"""
        result = is_dependency_available('unknown_dependency')
        assert result == False

    @patch('network_toolkit.utils.init')
    def test_init_colorama_success(self, mock_init):
        """Test init_colorama when colorama is available"""
        from colorama import Fore, Style
        
        result_fore, result_style = init_colorama()
        
        assert result_fore == Fore
        assert result_style == Style
        mock_init.assert_called_once()

    @patch('network_toolkit.utils.init')
    def test_init_colorama_import_error(self, mock_init):
        """Test init_colorama when colorama is not available"""
        mock_init.side_effect = ImportError('Colorama not available')
        
        result_fore, result_style = init_colorama()
        
        # Should return dummy objects
        assert hasattr(result_fore, 'RED')
        assert hasattr(result_style, 'RESET_ALL')
        # Dummy objects should return empty strings
        assert result_fore.RED == ''
        assert result_style.RESET_ALL == ''

    @patch('subprocess.run')
    def test_run_command_success(self, mock_run):
        """Test run_command with successful execution"""
        mock_result = MagicMock()
        mock_result.stdout = 'Command output'
        mock_result.stderr = ''
        mock_run.return_value = mock_result
        
        result = run_command('echo test')
        
        assert result == 'Command output'
        mock_run.assert_called_once_with('echo test', shell=True, capture_output=True, text=True, timeout=120)

    @patch('subprocess.run')
    def test_run_command_timeout(self, mock_run):
        """Test run_command with timeout"""
        mock_run.side_effect = subprocess.TimeoutExpired('echo test', 120)
        
        result = run_command('echo test')
        
        assert 'demasiado' in result or 'cancelado' in result

    @patch('subprocess.run')
    def test_run_command_exception(self, mock_run):
        """Test run_command with exception"""
        mock_run.side_effect = Exception('Test error')
        
        result = run_command('echo test')
        
        assert 'Error' in result

    @patch('subprocess.Popen')
    def test_run_command_realtime_success(self, mock_popen):
        """Test run_command_realtime with successful execution"""
        mock_process = MagicMock()
        mock_process.stdout = ['line 1\n', 'line 2\n']
        mock_process.wait.return_value = None
        mock_popen.return_value = mock_process
        
        result = run_command_realtime('echo test')
        
        assert 'line 1' in result
        assert 'line 2' in result
        mock_popen.assert_called_once_with('echo test', shell=True, stdout=subprocess.PIPE, 
                                         stderr=subprocess.STDOUT, text=True, bufsize=1, 
                                         universal_newlines=True)

    @patch('subprocess.Popen')
    def test_run_command_realtime_exception(self, mock_popen):
        """Test run_command_realtime with exception"""
        mock_popen.side_effect = Exception('Test error')
        
        result = run_command_realtime('echo test')
        
        assert 'Error' in result

    def test_is_valid_ip_ipv4_valid(self):
        """Test is_valid_ip with valid IPv4 addresses"""
        valid_ips = [
            '192.168.1.1',
            '8.8.8.8',
            '255.255.255.255',
            '0.0.0.0',
            '127.0.0.1'
        ]
        
        for ip in valid_ips:
            assert is_valid_ip(ip) == True

    def test_is_valid_ip_ipv4_invalid(self):
        """Test is_valid_ip with invalid IPv4 addresses"""
        invalid_ips = [
            '256.256.256.256',
            '192.168.1',
            '192.168.1.256',
            '192.168.1.-1',
            'abc.def.ghi.jkl'
        ]
        
        for ip in invalid_ips:
            assert is_valid_ip(ip) == False

    def test_is_valid_ip_ipv6_valid(self):
        """Test is_valid_ip with valid IPv6 addresses"""
        valid_ips = [
            '2001:0db8:85a3:0000:0000:8a2e:0370:7334',
            '2001:db8:85a3::8a2e:370:7334',
            '::1',
            '::',
            '2001:db8::1'
        ]
        
        for ip in valid_ips:
            assert is_valid_ip(ip) == True

    def test_is_valid_ip_ipv6_invalid(self):
        """Test is_valid_ip with invalid IPv6 addresses"""
        invalid_ips = [
            '2001:0db8:85a3:0000:0000:8a2e:0370:7334:extra',
            '2001::db8::1',
            'zzzz::1',
            '2001:db8:85a3:0:0:8a2e:0370:73345'
        ]
        
        for ip in invalid_ips:
            assert is_valid_ip(ip) == False

    def test_is_valid_domain_valid(self):
        """Test is_valid_domain with valid domains"""
        valid_domains = [
            'example.com',
            'google.com',
            'sub.domain.co.uk',
            'xn--example-9ua.com',  # Punycode
            'a' * 63 + '.com',  # Max length label
            'example-test.com'
        ]
        
        for domain in valid_domains:
            assert is_valid_domain(domain) == True

    def test_is_valid_domain_invalid(self):
        """Test is_valid_domain with invalid domains"""
        invalid_domains = [
            'example..com',
            '-example.com',
            'example-.com',
            '.example.com',
            'example.com-',
            'http://example.com',
            'example' + 'a' * 64 + '.com'  # Label too long
        ]
        
        for domain in invalid_domains:
            assert is_valid_domain(domain) == False

    def test_is_valid_target_valid(self):
        """Test is_valid_target with valid targets"""
        valid_targets = [
            'example.com',
            '192.168.1.1',
            '2001:db8::1',
            'google.com'
        ]
        
        for target in valid_targets:
            assert is_valid_target(target) == True

    def test_is_valid_target_invalid(self):
        """Test is_valid_target with invalid targets"""
        invalid_targets = [
            'example..com',
            '256.256.256.256',
            'http://example.com',
            'not a domain'
        ]
        
        for target in invalid_targets:
            assert is_valid_target(target) == False

    @patch('builtins.input')
    def test_get_raw_mode_input_yes(self, mock_input):
        """Test get_raw_mode_input with yes responses"""
        yes_responses = ['s', 'si', 'sí', 'y', 'yes']
        
        for response in yes_responses:
            mock_input.return_value = response
            result = get_raw_mode_input()
            assert result == True

    @patch('builtins.input')
    def test_get_raw_mode_input_no(self, mock_input):
        """Test get_raw_mode_input with no responses"""
        no_responses = ['n', 'no']
        
        for response in no_responses:
            mock_input.return_value = response
            result = get_raw_mode_input()
            assert result == False

    @patch('builtins.input')
    def test_get_raw_mode_input_invalid_then_valid(self, mock_input):
        """Test get_raw_mode_input with invalid then valid response"""
        mock_input.side_effect = ['invalid', 's']
        
        result = get_raw_mode_input()
        
        assert result == True
        assert mock_input.call_count == 2

    @patch('dns.resolver.Resolver.resolve')
    def test_check_network_connectivity_success(self, mock_resolve):
        """Test check_network_connectivity when successful"""
        mock_resolve.return_value = MagicMock()
        
        result = check_network_connectivity()
        assert result == True

    @patch('dns.resolver.Resolver.resolve')
    def test_check_network_connectivity_failure(self, mock_resolve):
        """Test check_network_connectivity when failed"""
        mock_resolve.side_effect = Exception('DNS error')
        
        result = check_network_connectivity()
        assert result == False

    @patch('builtins.open', new_callable=mock_open, read_data='{"Google": ["8.8.8.0/24"]}')
    @patch('os.path.join')
    @patch('os.path.dirname')
    @patch('os.path.abspath')
    def test_load_ip_ranges_success(self, mock_abspath, mock_dirname, mock_join, mock_file):
        """Test load_ip_ranges with successful file load"""
        mock_abspath.return_value = '/test/path'
        mock_dirname.return_value = '/test'
        mock_join.return_value = '/test/data/ip_ranges.json'
        
        result = load_ip_ranges()
        
        assert result == {'Google': ['8.8.8.0/24']}
        mock_file.assert_called_once_with('/test/data/ip_ranges.json', 'r', encoding='utf-8')

    @patch('builtins.open')
    @patch('os.path.join')
    @patch('os.path.dirname')
    @patch('os.path.abspath')
    def test_load_ip_ranges_file_not_found(self, mock_abspath, mock_dirname, mock_join, mock_file):
        """Test load_ip_ranges with file not found"""
        mock_abspath.return_value = '/test/path'
        mock_dirname.return_value = '/test'
        mock_join.return_value = '/test/data/ip_ranges.json'
        mock_file.side_effect = FileNotFoundError()
        
        result = load_ip_ranges()
        
        assert result == {}

    @patch('builtins.open', new_callable=mock_open, read_data='invalid json')
    @patch('os.path.join')
    @patch('os.path.dirname')
    @patch('os.path.abspath')
    def test_load_ip_ranges_json_error(self, mock_abspath, mock_dirname, mock_join, mock_file):
        """Test load_ip_ranges with invalid JSON"""
        mock_abspath.return_value = '/test/path'
        mock_dirname.return_value = '/test'
        mock_join.return_value = '/test/data/ip_ranges.json'
        
        result = load_ip_ranges()
        
        assert result == {}

    @patch('builtins.open')
    @patch('os.path.join')
    @patch('os.path.dirname')
    @patch('os.path.abspath')
    def test_load_ip_ranges_general_exception(self, mock_abspath, mock_dirname, mock_join, mock_file):
        """Test load_ip_ranges with general exception"""
        mock_abspath.return_value = '/test/path'
        mock_dirname.return_value = '/test'
        mock_join.return_value = '/test/data/ip_ranges.json'
        mock_file.side_effect = Exception('Test error')
        
        result = load_ip_ranges()
        
        assert result == {}