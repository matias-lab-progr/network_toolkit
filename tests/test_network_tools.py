import pytest
import socket
from unittest.mock import MagicMock, patch, mock_open
from network_toolkit.network_tools import (
    ping_target,
    traceroute_target,
    geolocate_ip,
    display_geolocation,
    get_detailed_asn_info,
    display_detailed_asn_info,
    scan_common_ports,
    display_port_scan_results,
    extended_reverse_dns,
    display_extended_dns_info,
    detect_provider,
    normalize_provider_name,
    update_ip_ranges
)

class TestNetworkTools:
    """Test cases for network_tools module"""

    @patch('network_toolkit.network_tools.run_command')
    def test_ping_target_windows(self, mock_run_command):
        """Test ping command on Windows"""
        mock_run_command.return_value = "Ping results"
        
        result = ping_target("example.com", "windows")
        mock_run_command.assert_called_once_with("ping -n 4 example.com")
        assert result == "Ping results"

    @patch('network_toolkit.network_tools.run_command')
    def test_ping_target_linux(self, mock_run_command):
        """Test ping command on Linux"""
        mock_run_command.return_value = "Ping results"
        
        result = ping_target("example.com", "linux")
        mock_run_command.assert_called_once_with("ping -c 4 example.com")
        assert result == "Ping results"

    @patch('network_toolkit.network_tools.run_command_realtime')
    def test_traceroute_target_windows(self, mock_run_command_realtime):
        """Test traceroute command on Windows"""
        mock_run_command_realtime.return_value = "Traceroute results"
        
        result = traceroute_target("example.com", "windows")
        mock_run_command_realtime.assert_called_once_with("tracert -h 15 example.com")
        assert result == "Traceroute results"

    @patch('network_toolkit.network_tools.run_command_realtime')
    def test_traceroute_target_linux(self, mock_run_command_realtime):
        """Test traceroute command on Linux"""
        mock_run_command_realtime.return_value = "Traceroute results"
        
        result = traceroute_target("example.com", "linux")
        mock_run_command_realtime.assert_called_once_with("traceroute -m 15 example.com")
        assert result == "Traceroute results"

    @patch('network_toolkit.network_tools.requests.get')
    def test_geolocate_ip_success(self, mock_get):
        """Test successful IP geolocation"""
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            'ip': '8.8.8.8',
            'city': 'Mountain View',
            'region': 'California',
            'country_name': 'United States',
            'postal': '94043',
            'latitude': 37.4056,
            'longitude': -122.0775,
            'timezone': 'America/Los_Angeles',
            'org': 'Google LLC',
            'asn': 'AS15169'
        }
        mock_get.return_value = mock_response
        
        result = geolocate_ip('8.8.8.8')
        
        assert result['ip'] == '8.8.8.8'
        assert result['city'] == 'Mountain View'
        assert result['country'] == 'United States'
        mock_get.assert_called_once_with("http://ipapi.co/8.8.8.8/json/", timeout=10)

    @patch('network_toolkit.network_tools.requests.get')
    def test_geolocate_ip_failure(self, mock_get):
        """Test IP geolocation failure"""
        mock_response = MagicMock()
        mock_response.status_code = 404
        mock_get.return_value = mock_response
        
        result = geolocate_ip('8.8.8.8')
        assert 'error' in result

    @patch('network_toolkit.network_tools.requests.get')
    def test_get_detailed_asn_info_success(self, mock_get):
        """Test successful ASN info retrieval"""
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            'status': 'success',
            'query': '8.8.8.8',
            'as': 'AS15169 Google LLC',
            'isp': 'Google LLC',
            'org': 'Google LLC'
        }
        mock_get.return_value = mock_response
        
        result = get_detailed_asn_info('8.8.8.8')
        
        assert result['ip'] == '8.8.8.8'
        assert result['asn'] == 'AS15169 Google LLC'
        assert result['isp'] == 'Google LLC'

    @patch('network_toolkit.network_tools.requests.get')
    def test_get_detailed_asn_info_failure(self, mock_get):
        """Test ASN info retrieval failure"""
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {'status': 'fail'}
        mock_get.return_value = mock_response
        
        result = get_detailed_asn_info('8.8.8.8')
        assert 'error' in result

    @patch('network_toolkit.network_tools.socket.socket')
    def test_scan_common_ports_success(self, mock_socket):
        """Test common port scanning"""
        mock_sock_instance = MagicMock()
        mock_socket.return_value.__enter__.return_value = mock_sock_instance
        mock_sock_instance.connect_ex.return_value = 0  # Port open
        
        result = scan_common_ports('127.0.0.1')
        
        assert 'open_ports' in result
        assert 'total_scanned' in result
        assert 'ports_info' in result
        assert isinstance(result['open_ports'], dict)

    @patch('network_toolkit.network_tools.socket.socket')
    def test_scan_common_ports_closed(self, mock_socket):
        """Test common port scanning with closed ports"""
        mock_sock_instance = MagicMock()
        mock_socket.return_value.__enter__.return_value = mock_sock_instance
        mock_sock_instance.connect_ex.return_value = 1  # Port closed
        
        result = scan_common_ports('127.0.0.1')
        
        assert len(result['open_ports']) == 0
        assert result['total_scanned'] > 0

    @patch('network_toolkit.network_tools.dns.resolver.Resolver')
    def test_extended_reverse_dns_success(self, mock_resolver):
        """Test extended reverse DNS lookup"""
        mock_instance = MagicMock()
        mock_resolver.return_value = mock_instance
        
        mock_answer = MagicMock()
        mock_answer.rrset = MagicMock()
        mock_answer.rrset.to_text.return_value = 'example.com.'
        mock_instance.resolve.return_value = [mock_answer]
        
        result = extended_reverse_dns('8.8.8.8')
        
        assert 'ptr_records' in result
        assert result['has_ptr'] == True

    @patch('network_toolkit.network_tools.dns.resolver.Resolver')
    def test_extended_reverse_dns_failure(self, mock_resolver):
        """Test extended reverse DNS lookup failure"""
        mock_instance = MagicMock()
        mock_resolver.return_value = mock_instance
        mock_instance.resolve.side_effect = Exception('DNS error')
        
        result = extended_reverse_dns('8.8.8.8')
        
        assert 'ptr_records' in result
        assert result['has_ptr'] == False

    def test_normalize_provider_name_google(self):
        """Test provider name normalization for Google"""
        result = normalize_provider_name('Google LLC')
        assert result == 'Google'

    def test_normalize_provider_name_aws(self):
        """Test provider name normalization for AWS"""
        result = normalize_provider_name('Amazon Web Services')
        assert result == 'Amazon AWS'

    def test_normalize_provider_name_azure(self):
        """Test provider name normalization for Azure"""
        result = normalize_provider_name('Microsoft Azure')
        assert result == 'Microsoft Azure'

    def test_normalize_provider_name_unknown(self):
        """Test provider name normalization for unknown provider"""
        result = normalize_provider_name('Some Unknown Provider')
        assert result == 'Some Unknown Provider'

    @patch('network_toolkit.network_tools.load_ip_ranges')
    @patch('network_toolkit.network_tools.get_detailed_asn_info')
    def test_detect_provider_from_ranges(self, mock_get_asn, mock_load_ranges):
        """Test provider detection from IP ranges"""
        mock_load_ranges.return_value = {
            'Google': ['8.8.8.0/24'],
            'Cloudflare': ['1.1.1.0/24']
        }
        mock_get_asn.return_value = {'org': 'Google LLC'}
        
        result = detect_provider('8.8.8.8')
        assert result == 'Google'

    @patch('network_toolkit.network_tools.load_ip_ranges')
    @patch('network_toolkit.network_tools.get_detailed_asn_info')
    def test_detect_provider_from_asn(self, mock_get_asn, mock_load_ranges):
        """Test provider detection from ASN info"""
        mock_load_ranges.return_value = {}
        mock_get_asn.return_value = {
            'org': 'Google LLC',
            'isp': 'Google LLC',
            'asn': 'AS15169'
        }
        
        result = detect_provider('8.8.8.8')
        assert result == 'Google'

    @patch('network_toolkit.network_tools.load_ip_ranges')
    @patch('network_toolkit.network_tools.get_detailed_asn_info')
    def test_detect_provider_unknown(self, mock_get_asn, mock_load_ranges):
        """Test provider detection for unknown IP"""
        mock_load_ranges.return_value = {}
        mock_get_asn.return_value = {'error': 'Not found'}
        
        result = detect_provider('192.168.1.1')
        assert result == 'Desconocido'

    def test_display_geolocation_with_error(self):
        """Test geolocation display with error"""
        import io
        from contextlib import redirect_stdout
        
        error_info = {'error': 'Test error message'}
        
        f = io.StringIO()
        with redirect_stdout(f):
            display_geolocation(error_info)
        
        output = f.getvalue()
        assert 'Test error message' in output

    def test_display_detailed_asn_info_with_error(self):
        """Test ASN info display with error"""
        import io
        from contextlib import redirect_stdout
        
        error_info = {'error': 'Test error message'}
        
        f = io.StringIO()
        with redirect_stdout(f):
            display_detailed_asn_info(error_info)
        
        output = f.getvalue()
        assert 'Test error message' in output

    def test_display_port_scan_results_with_error(self):
        """Test port scan results display with error"""
        import io
        from contextlib import redirect_stdout
        
        error_info = {'error': 'Test error message'}
        
        f = io.StringIO()
        with redirect_stdout(f):
            display_port_scan_results(error_info, '8.8.8.8')
        
        output = f.getvalue()
        assert 'Test error message' in output

    def test_display_extended_dns_info_with_error(self):
        """Test extended DNS info display with error"""
        import io
        from contextlib import redirect_stdout
        
        error_info = {'error': 'Test error message'}
        
        f = io.StringIO()
        with redirect_stdout(f):
            display_extended_dns_info(error_info, '8.8.8.8')
        
        output = f.getvalue()
        assert 'Test error message' in output

    @patch('builtins.print')
    def test_update_ip_ranges(self, mock_print):
        """Test IP ranges update function"""
        result = update_ip_ranges()
        assert result == True
        mock_print.assert_called()