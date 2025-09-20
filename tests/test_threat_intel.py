import pytest
import requests
from unittest.mock import MagicMock, patch
from network_toolkit.threat_intel import (
    get_public_ip_report,
    check_abuseipdb_public,
    check_virustotal_public,
    get_ipinfo_public,
    generate_recommendations,
    display_threat_intel_results
)

class TestThreatIntel:
    """Test cases for threat_intel module"""

    @patch('network_toolkit.threat_intel.check_abuseipdb_public')
    @patch('network_toolkit.threat_intel.check_virustotal_public')
    @patch('network_toolkit.threat_intel.get_ipinfo_public')
    def test_get_public_ip_report_success(self, mock_ipinfo, mock_virustotal, mock_abuseipdb):
        """Test getting public IP report with successful results"""
        # Mock all services
        mock_abuseipdb.return_value = {
            'success': True,
            'abuse_confidence': 75,
            'total_reports': 10,
            'country': 'United States',
            'isp': 'Example ISP'
        }
        mock_virustotal.return_value = {
            'success': True,
            'detected_malicious': 3,
            'undetected': 60
        }
        mock_ipinfo.return_value = {
            'success': True,
            'country': 'US',
            'region': 'California',
            'city': 'Los Angeles',
            'org': 'Example Corp'
        }
        
        result = get_public_ip_report('8.8.8.8')
        
        assert result['ip'] == '8.8.8.8'
        assert result['threat_level'] == 'high'  # 75 + 3*10 = 105 > 50
        assert len(result['recommendations']) > 0
        mock_abuseipdb.assert_called_once_with('8.8.8.8')
        mock_virustotal.assert_called_once_with('8.8.8.8')
        mock_ipinfo.assert_called_once_with('8.8.8.8')

    @patch('network_toolkit.threat_intel.check_abuseipdb_public')
    @patch('network_toolkit.threat_intel.check_virustotal_public')
    @patch('network_toolkit.threat_intel.get_ipinfo_public')
    def test_get_public_ip_report_clean(self, mock_ipinfo, mock_virustotal, mock_abuseipdb):
        """Test getting public IP report with clean IP"""
        mock_abuseipdb.return_value = {
            'success': True,
            'abuse_confidence': 0,
            'total_reports': 0
        }
        mock_virustotal.return_value = {
            'success': True,
            'detected_malicious': 0
        }
        mock_ipinfo.return_value = {
            'success': True,
            'country': 'US'
        }
        
        result = get_public_ip_report('1.1.1.1')
        
        assert result['threat_level'] == 'clean'
        assert 'LIMPIO' in str(result['recommendations'])

    @patch('network_toolkit.threat_intel.check_abuseipdb_public')
    @patch('network_toolkit.threat_intel.check_virustotal_public')
    @patch('network_toolkit.threat_intel.get_ipinfo_public')
    def test_get_public_ip_report_service_failures(self, mock_ipinfo, mock_virustotal, mock_abuseipdb):
        """Test getting public IP report with service failures"""
        mock_abuseipdb.return_value = {'error': 'Service unavailable'}
        mock_virustotal.return_value = {'error': 'Service unavailable'}
        mock_ipinfo.return_value = {'error': 'Service unavailable'}
        
        result = get_public_ip_report('8.8.8.8')
        
        assert result['ip'] == '8.8.8.8'
        assert result['threat_level'] == 'unknown'
        assert 'No hay suficiente información' in str(result['recommendations'])

    @patch('requests.get')
    def test_check_abuseipdb_public_success(self, mock_get):
        """Test AbuseIPDB public check with successful response"""
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.text = """
        Abuse Confidence Score: 75%
        Total reports: 10
        Country: United States
        ISP: Example ISP
        """
        mock_get.return_value = mock_response
        
        result = check_abuseipdb_public('8.8.8.8')
        
        assert result['success'] == True
        assert result['abuse_confidence'] == 75
        assert result['total_reports'] == 10
        assert result['country'] == 'United States'
        assert result['isp'] == 'Example ISP'

    @patch('requests.get')
    def test_check_abuseipdb_public_no_data(self, mock_get):
        """Test AbuseIPDB public check with no data found"""
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.text = "No relevant data found"
        mock_get.return_value = mock_response
        
        result = check_abuseipdb_public('8.8.8.8')
        
        assert result['success'] == True
        assert result['abuse_confidence'] == 0
        assert result['total_reports'] == 0

    @patch('requests.get')
    def test_check_abuseipdb_public_http_error(self, mock_get):
        """Test AbuseIPDB public check with HTTP error"""
        mock_response = MagicMock()
        mock_response.status_code = 404
        mock_get.return_value = mock_response
        
        result = check_abuseipdb_public('8.8.8.8')
        
        assert 'error' in result
        assert '404' in result['error']

    @patch('requests.get')
    def test_check_abuseipdb_public_exception(self, mock_get):
        """Test AbuseIPDB public check with exception"""
        mock_get.side_effect = Exception('Connection failed')
        
        result = check_abuseipdb_public('8.8.8.8')
        
        assert 'error' in result
        assert 'Connection failed' in result['error']

    @patch('requests.get')
    def test_check_virustotal_public_success(self, mock_get):
        """Test VirusTotal public check with successful response"""
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.text = "5 security vendors detected this as malicious"
        mock_get.return_value = mock_response
        
        result = check_virustotal_public('8.8.8.8')
        
        assert result['success'] == True
        assert result['detected_malicious'] == 5

    @patch('requests.get')
    def test_check_virustotal_public_no_detections(self, mock_get):
        """Test VirusTotal public check with no detections"""
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.text = "No detections found"
        mock_get.return_value = mock_response
        
        result = check_virustotal_public('8.8.8.8')
        
        assert result['success'] == True
        assert result['detected_malicious'] == 0

    @patch('requests.get')
    def test_check_virustotal_public_http_error(self, mock_get):
        """Test VirusTotal public check with HTTP error"""
        mock_response = MagicMock()
        mock_response.status_code = 403
        mock_get.return_value = mock_response
        
        result = check_virustotal_public('8.8.8.8')
        
        assert 'error' in result
        assert '403' in result['error']

    @patch('requests.get')
    def test_get_ipinfo_public_success(self, mock_get):
        """Test IPinfo public check with successful response"""
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            'country': 'US',
            'region': 'California',
            'city': 'Los Angeles',
            'org': 'Example Corp',
            'hostname': 'one.one.one.one'
        }
        mock_get.return_value = mock_response
        
        result = get_ipinfo_public('1.1.1.1')
        
        assert result['success'] == True
        assert result['country'] == 'US'
        assert result['region'] == 'California'
        assert result['city'] == 'Los Angeles'
        assert result['org'] == 'Example Corp'

    @patch('requests.get')
    def test_get_ipinfo_public_http_error(self, mock_get):
        """Test IPinfo public check with HTTP error"""
        mock_response = MagicMock()
        mock_response.status_code = 500
        mock_get.return_value = mock_response
        
        result = get_ipinfo_public('1.1.1.1')
        
        assert 'error' in result
        assert '500' in result['error']

    def test_generate_recommendations_high_threat(self):
        """Test generating recommendations for high threat level"""
        results = {'threat_level': 'high'}
        generate_recommendations(results)
        
        assert len(results['recommendations']) > 0
        assert 'ALTA PROBABILIDAD' in results['recommendations'][0]
        assert 'Bloquear' in results['recommendations'][1]

    def test_generate_recommendations_medium_threat(self):
        """Test generating recommendations for medium threat level"""
        results = {'threat_level': 'medium'}
        generate_recommendations(results)
        
        assert len(results['recommendations']) > 0
        assert 'MODERADOS' in results['recommendations'][0]
        assert 'Monitorear' in results['recommendations'][1]

    def test_generate_recommendations_low_threat(self):
        """Test generating recommendations for low threat level"""
        results = {'threat_level': 'low'}
        generate_recommendations(results)
        
        assert len(results['recommendations']) > 0
        assert 'BAJA REPUTACIÓN' in results['recommendations'][0]
        assert 'monitoreo básico' in results['recommendations'][1]

    def test_generate_recommendations_clean(self):
        """Test generating recommendations for clean threat level"""
        results = {'threat_level': 'clean'}
        generate_recommendations(results)
        
        assert len(results['recommendations']) > 0
        assert 'LIMPIA' in results['recommendations'][0]
        assert 'No se requiere acción' in results['recommendations'][1]

    def test_generate_recommendations_unknown(self):
        """Test generating recommendations for unknown threat level"""
        results = {'threat_level': 'unknown'}
        generate_recommendations(results)
        
        assert len(results['recommendations']) > 0
        assert 'DESCONOCIDA' in results['recommendations'][0]
        assert 'No hay suficiente información' in results['recommendations'][1]

    @patch('builtins.print')
    def test_display_threat_intel_results_high_threat(self, mock_print):
        """Test displaying threat intel results for high threat"""
        results = {
            'ip': '8.8.8.8',
            'threat_level': 'high',
            'services': {
                'abuseipdb': {
                    'success': True,
                    'abuse_confidence': 75,
                    'total_reports': 10,
                    'country': 'United States',
                    'isp': 'Example ISP',
                    'url': 'https://abuseipdb.com/check/8.8.8.8'
                },
                'virustotal': {
                    'success': True,
                    'detected_malicious': 5,
                    'url': 'https://virustotal.com/gui/ip-address/8.8.8.8'
                },
                'ipinfo': {
                    'success': True,
                    'country': 'US',
                    'region': 'California',
                    'city': 'Los Angeles',
                    'org': 'Example Corp'
                }
            },
            'recommendations': ['Test recommendation 1', 'Test recommendation 2']
        }
        
        display_threat_intel_results(results)
        
        # Should display all information
        assert mock_print.call_count > 10
        call_args = str(mock_print.call_args_list)
        assert '8.8.8.8' in call_args
        assert 'ALTO' in call_args
        assert 'United States' in call_args
        assert 'Example ISP' in call_args

    @patch('builtins.print')
    def test_display_threat_intel_results_service_failures(self, mock_print):
        """Test displaying threat intel results with service failures"""
        results = {
            'ip': '8.8.8.8',
            'threat_level': 'unknown',
            'services': {
                'abuseipdb': {'error': 'Service unavailable'},
                'virustotal': {'error': 'Service unavailable'},
                'ipinfo': {'error': 'Service unavailable'}
            },
            'recommendations': ['Test recommendation']
        }
        
        display_threat_intel_results(results)
        
        # Should still display without crashing
        assert mock_print.call_count > 5
        call_args = str(mock_print.call_args_list)
        assert '8.8.8.8' in call_args

    @patch('requests.get')
    def test_check_virustotal_public_complex_html(self, mock_get):
        """Test VirusTotal public check with complex HTML content"""
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.text = """
        <div>Some random text</div>
        <span>5 security vendors and no sandboxes flagged this as malicious</span>
        <div>More random text</div>
        """
        mock_get.return_value = mock_response
        
        result = check_virustotal_public('8.8.8.8')
        
        assert result['success'] == True
        assert result['detected_malicious'] == 5

    @patch('requests.get')
    def test_check_abuseipdb_public_complex_html(self, mock_get):
        """Test AbuseIPDB public check with complex HTML content"""
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.text = """
        <tr><td>Abuse Confidence Score:</td><td>85%</td></tr>
        <tr><td>Total reports:</td><td>15</td></tr>
        <tr><td>Country:</td><td>Germany</td></tr>
        <tr><td>ISP:</td><td>Deutsche Telekom</td></tr>
        """
        mock_get.return_value = mock_response
        
        result = check_abuseipdb_public('8.8.8.8')
        
        assert result['success'] == True
        assert result['abuse_confidence'] == 85
        assert result['total_reports'] == 15
        assert result['country'] == 'Germany'
        assert result['isp'] == 'Deutsche Telekom'

    @patch('network_toolkit.threat_intel.check_abuseipdb_public')
    @patch('network_toolkit.threat_intel.check_virustotal_public')
    @patch('network_toolkit.threat_intel.get_ipinfo_public')
    def test_threat_score_calculation(self, mock_ipinfo, mock_virustotal, mock_abuseipdb):
        """Test threat score calculation logic"""
        # Test case 1: High threat
        mock_abuseipdb.return_value = {'success': True, 'abuse_confidence': 60}
        mock_virustotal.return_value = {'success': True, 'detected_malicious': 3}
        mock_ipinfo.return_value = {'success': True}
        
        result = get_public_ip_report('8.8.8.8')
        assert result['threat_level'] == 'high'  # 60 + 3*10 = 90 > 50
        
        # Test case 2: Medium threat
        mock_abuseipdb.return_value = {'success': True, 'abuse_confidence': 25}
        mock_virustotal.return_value = {'success': True, 'detected_malicious': 2}
        
        result = get_public_ip_report('8.8.8.8')
        assert result['threat_level'] == 'medium'  # 25 + 2*10 = 45 > 20
        
        # Test case 3: Low threat
        mock_abuseipdb.return_value = {'success': True, 'abuse_confidence': 15}
        mock_virustotal.return_value = {'success': True, 'detected_malicious': 0}
        
        result = get_public_ip_report('8.8.8.8')
        assert result['threat_level'] == 'low'  # 15 + 0 = 15 > 0
        
        # Test case 4: Clean
        mock_abuseipdb.return_value = {'success': True, 'abuse_confidence': 0}
        mock_virustotal.return_value = {'success': True, 'detected_malicious': 0}
        
        result = get_public_ip_report('8.8.8.8')
        assert result['threat_level'] == 'clean'  # 0 + 0 = 0