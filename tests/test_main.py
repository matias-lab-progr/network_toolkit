import pytest
import sys
from unittest.mock import MagicMock, patch, mock_open
from network_toolkit.main import (
    handle_ping_option,
    handle_traceroute_option,
    handle_whois_option,
    handle_dns_lookup_option,
    handle_professional_dns_option,
    handle_comprehensive_dns_scan,
    handle_batch_dns_lookup,
    handle_reverse_dns_lookup,
    handle_geolocation_option,
    handle_asn_analysis_option,
    handle_port_scan_option,
    handle_extended_dns_option,
    handle_update_ip_ranges,
    handle_ssl_analysis_option,
    handle_subdomain_enumeration_option,
    handle_threat_intel_option,
    handle_ct_search_option,
    handle_comprehensive_subdomain_enum_option,
    main
)

class TestMain:
    """Test cases for main module"""

    @patch('network_toolkit.main.is_valid_target')
    @patch('network_toolkit.main.ping_target')
    @patch('network_toolkit.main.analyse_ping_output')
    @patch('builtins.input')
    def test_handle_ping_option_valid(self, mock_input, mock_analyse, mock_ping, mock_is_valid):
        """Test handle ping option with valid target"""
        mock_input.return_value = 'example.com'
        mock_is_valid.return_value = True
        mock_ping.return_value = 'Ping results'
        mock_analyse.return_value = 'Analysis results'
        
        handle_ping_option('linux')
        
        mock_is_valid.assert_called_once_with('example.com')
        mock_ping.assert_called_once_with('example.com', 'linux')
        mock_analyse.assert_called_once_with('Ping results', 'example.com')

    @patch('network_toolkit.main.is_valid_target')
    @patch('builtins.input')
    def test_handle_ping_option_invalid(self, mock_input, mock_is_valid):
        """Test handle ping option with invalid target"""
        mock_input.return_value = 'invalid-target'
        mock_is_valid.return_value = False
        
        handle_ping_option('linux')
        
        mock_is_valid.assert_called_once_with('invalid-target')

    @patch('network_toolkit.main.traceroute_target')
    @patch('network_toolkit.main.analyze_traceroute_output')
    @patch('builtins.input')
    def test_handle_traceroute_option(self, mock_input, mock_analyze, mock_traceroute):
        """Test handle traceroute option"""
        mock_input.return_value = 'example.com'
        mock_traceroute.return_value = 'Traceroute results'
        mock_analyze.return_value = 'Analysis results'
        
        handle_traceroute_option('linux')
        
        mock_traceroute.assert_called_once_with('example.com', 'linux')
        mock_analyze.assert_called_once_with('Traceroute results', 'example.com')

    @patch('network_toolkit.main.is_valid_domain')
    @patch('network_toolkit.main.get_whois_info')
    @patch('network_toolkit.main.analyze_whois_output')
    @patch('builtins.input')
    def test_handle_whois_option_valid(self, mock_input, mock_analyze, mock_whois, mock_is_valid):
        """Test handle whois option with valid domain"""
        mock_input.return_value = 'example.com'
        mock_is_valid.return_value = True
        mock_whois.return_value = 'Whois results'
        mock_analyze.return_value = 'Analysis results'
        
        handle_whois_option()
        
        mock_is_valid.assert_called_once_with('example.com')
        mock_whois.assert_called_once_with('example.com')
        mock_analyze.assert_called_once_with('Whois results', 'example.com')

    @patch('network_toolkit.main.is_valid_domain')
    @patch('builtins.input')
    def test_handle_whois_option_invalid(self, mock_input, mock_is_valid):
        """Test handle whois option with invalid domain"""
        mock_input.return_value = 'invalid-domain'
        mock_is_valid.return_value = False
        
        handle_whois_option()
        
        mock_is_valid.assert_called_once_with('invalid-domain')

    @patch('network_toolkit.main.is_valid_domain')
    @patch('network_toolkit.main.run_command')
    @patch('network_toolkit.main.analyze_dns_output')
    @patch('builtins.input')
    def test_handle_dns_lookup_option_linux(self, mock_input, mock_analyze, mock_run, mock_is_valid):
        """Test handle DNS lookup option on Linux"""
        mock_input.return_value = 'example.com'
        mock_is_valid.return_value = True
        mock_run.return_value = 'DNS results'
        mock_analyze.return_value = 'Analysis results'
        
        handle_dns_lookup_option('linux')
        
        mock_run.assert_called_once_with('dig example.com')
        mock_analyze.assert_called_once_with('DNS results', 'example.com')

    @patch('network_toolkit.main.is_valid_domain')
    @patch('network_toolkit.main.run_command')
    @patch('network_toolkit.main.analyze_dns_output')
    @patch('builtins.input')
    def test_handle_dns_lookup_option_windows(self, mock_input, mock_analyze, mock_run, mock_is_valid):
        """Test handle DNS lookup option on Windows"""
        mock_input.return_value = 'example.com'
        mock_is_valid.return_value = True
        mock_run.return_value = 'DNS results'
        mock_analyze.return_value = 'Analysis results'
        
        handle_dns_lookup_option('windows')
        
        mock_run.assert_called_once_with('nslookup example.com')
        mock_analyze.assert_called_once_with('DNS results', 'example.com')

    @patch('network_toolkit.main.is_valid_domain')
    @patch('network_toolkit.main.dns_lookup')
    @patch('network_toolkit.main.get_raw_mode_input')
    @patch('builtins.input')
    def test_handle_professional_dns_option(self, mock_input, mock_raw, mock_dns_lookup, mock_is_valid):
        """Test handle professional DNS option"""
        mock_input.side_effect = ['example.com', 'A', '']
        mock_is_valid.return_value = True
        mock_raw.return_value = False
        
        handle_professional_dns_option()
        
        mock_dns_lookup.assert_called_once_with('example.com', 'A', None, False)

    @patch('network_toolkit.main.is_valid_domain')
    @patch('network_toolkit.main.comprehensive_dns_scan')
    @patch('network_toolkit.main.get_raw_mode_input')
    @patch('builtins.input')
    def test_handle_comprehensive_dns_scan(self, mock_input, mock_raw, mock_scan, mock_is_valid):
        """Test handle comprehensive DNS scan"""
        mock_input.side_effect = ['example.com', '']
        mock_is_valid.return_value = True
        mock_raw.return_value = False
        
        handle_comprehensive_dns_scan()
        
        mock_scan.assert_called_once_with('example.com', None, False)

    @patch('builtins.open', new_callable=mock_open, read_data='sub1.example.com\nsub2.example.com\n')
    @patch('network_toolkit.main.batch_dns_lookup')
    @patch('network_toolkit.main.get_raw_mode_input')
    @patch('builtins.input')
    def test_handle_batch_dns_lookup(self, mock_input, mock_raw, mock_batch, mock_file):
        """Test handle batch DNS lookup"""
        mock_input.side_effect = ['subdomains.txt', 'A', '']
        mock_raw.return_value = False
        
        handle_batch_dns_lookup()
        
        mock_batch.assert_called_once_with('subdomains.txt', 'A', None, False)

    @patch('network_toolkit.main.is_valid_ip')
    @patch('network_toolkit.main.reverse_dns_lookup')
    @patch('network_toolkit.main.get_raw_mode_input')
    @patch('builtins.input')
    def test_handle_reverse_dns_lookup_valid(self, mock_input, mock_raw, mock_reverse, mock_is_valid):
        """Test handle reverse DNS lookup with valid IP"""
        mock_input.side_effect = ['8.8.8.8', '']
        mock_is_valid.return_value = True
        mock_raw.return_value = False
        
        handle_reverse_dns_lookup()
        
        mock_reverse.assert_called_once_with('8.8.8.8', None, False)

    @patch('network_toolkit.main.is_valid_ip')
    @patch('builtins.input')
    def test_handle_reverse_dns_lookup_invalid(self, mock_input, mock_is_valid):
        """Test handle reverse DNS lookup with invalid IP"""
        mock_input.return_value = 'invalid-ip'
        mock_is_valid.return_value = False
        
        handle_reverse_dns_lookup()
        
        mock_is_valid.assert_called_once_with('invalid-ip')

    @patch('network_toolkit.main.is_valid_ip')
    @patch('network_toolkit.main.geolocate_ip')
    @patch('network_toolkit.main.display_geolocation')
    @patch('builtins.input')
    def test_handle_geolocation_option(self, mock_input, mock_display, mock_geolocate, mock_is_valid):
        """Test handle geolocation option"""
        mock_input.return_value = '8.8.8.8'
        mock_is_valid.return_value = True
        mock_geolocate.return_value = {'ip': '8.8.8.8', 'city': 'Mountain View'}
        
        handle_geolocation_option()
        
        mock_geolocate.assert_called_once_with('8.8.8.8')
        mock_display.assert_called_once_with({'ip': '8.8.8.8', 'city': 'Mountain View'})

    @patch('network_toolkit.main.is_valid_ip')
    @patch('network_toolkit.main.get_detailed_asn_info')
    @patch('network_toolkit.main.display_detailed_asn_info')
    @patch('builtins.input')
    def test_handle_asn_analysis_option(self, mock_input, mock_display, mock_get_asn, mock_is_valid):
        """Test handle ASN analysis option"""
        mock_input.return_value = '8.8.8.8'
        mock_is_valid.return_value = True
        mock_get_asn.return_value = {'asn': 'AS15169'}
        
        handle_asn_analysis_option()
        
        mock_get_asn.assert_called_once_with('8.8.8.8')
        mock_display.assert_called_once_with({'asn': 'AS15169'})

    @patch('network_toolkit.main.is_valid_ip')
    @patch('network_toolkit.main.scan_common_ports')
    @patch('network_toolkit.main.display_port_scan_results')
    @patch('builtins.input')
    def test_handle_port_scan_option(self, mock_input, mock_display, mock_scan, mock_is_valid):
        """Test handle port scan option"""
        mock_input.return_value = '8.8.8.8'
        mock_is_valid.return_value = True
        mock_scan.return_value = {'open_ports': {80: 'HTTP'}}
        
        handle_port_scan_option()
        
        mock_scan.assert_called_once_with('8.8.8.8')
        mock_display.assert_called_once_with({'open_ports': {80: 'HTTP'}}, '8.8.8.8')

    @patch('network_toolkit.main.is_valid_ip')
    @patch('network_toolkit.main.extended_reverse_dns')
    @patch('network_toolkit.main.display_extended_dns_info')
    @patch('builtins.input')
    def test_handle_extended_dns_option(self, mock_input, mock_display, mock_extended, mock_is_valid):
        """Test handle extended DNS option"""
        mock_input.return_value = '8.8.8.8'
        mock_is_valid.return_value = True
        mock_extended.return_value = {'ptr_records': ['dns.google.']}
        
        handle_extended_dns_option()
        
        mock_extended.assert_called_once_with('8.8.8.8')
        mock_display.assert_called_once_with({'ptr_records': ['dns.google.']}, '8.8.8.8')

    @patch('network_toolkit.main.update_ip_ranges')
    def test_handle_update_ip_ranges(self, mock_update):
        """Test handle update IP ranges"""
        handle_update_ip_ranges()
        mock_update.assert_called_once()

    @patch('network_toolkit.main.is_valid_domain')
    @patch('network_toolkit.main.get_ssl_certificate')
    @patch('network_toolkit.main.analyze_ssl_certificate')
    @patch('network_toolkit.main.check_ssl_security')
    @patch('network_toolkit.main.display_ssl_analysis')
    @patch('builtins.input')
    def test_handle_ssl_analysis_option_success(self, mock_input, mock_display, mock_check, mock_analyze, mock_get_cert, mock_is_valid):
        """Test handle SSL analysis option successful"""
        mock_input.return_value = 'example.com'
        mock_is_valid.return_value = True
        mock_get_cert.return_value = {'success': True, 'certificate': 'cert', 'cipher': 'TLS_AES_256_GCM_SHA384', 'version': 'TLSv1.3'}
        mock_analyze.return_value = {'success': True, 'subject': 'example.com'}
        mock_check.return_value = {'grade': 'A+'}
        
        handle_ssl_analysis_option()
        
        mock_get_cert.assert_called_once_with('example.com')
        mock_analyze.assert_called_once_with('cert')
        mock_check.assert_called_once_with({'success': True, 'subject': 'example.com'}, 'TLS_AES_256_GCM_SHA384')

    @patch('network_toolkit.main.is_valid_domain')
    @patch('network_toolkit.main.get_ssl_certificate')
    @patch('builtins.input')
    def test_handle_ssl_analysis_option_failure(self, mock_input, mock_get_cert, mock_is_valid):
        """Test handle SSL analysis option failure"""
        mock_input.return_value = 'example.com'
        mock_is_valid.return_value = True
        mock_get_cert.return_value = {'success': False, 'error': 'SSL handshake failed'}
        
        handle_ssl_analysis_option()
        
        mock_get_cert.assert_called_once_with('example.com')

    @patch('network_toolkit.main.is_valid_domain')
    @patch('network_toolkit.main.dns_subdomain_enumeration')
    @patch('network_toolkit.main.display_subdomain_results')
    @patch('builtins.input')
    def test_handle_subdomain_enumeration_option_brute_force(self, mock_input, mock_display, mock_enum, mock_is_valid):
        """Test handle subdomain enumeration option with brute force"""
        mock_input.side_effect = ['example.com', '1']
        mock_is_valid.return_value = True
        mock_enum.return_value = {'subdomains': ['www.example.com']}
        
        handle_subdomain_enumeration_option()
        
        mock_enum.assert_called_once_with('example.com')
        mock_display.assert_called_once_with({'subdomains': ['www.example.com']})

    @patch('network_toolkit.main.is_valid_domain')
    @patch('network_toolkit.main.passive_subdomain_enumeration')
    @patch('network_toolkit.main.display_passive_subdomain_results')
    @patch('builtins.input')
    def test_handle_subdomain_enumeration_option_passive(self, mock_input, mock_display, mock_enum, mock_is_valid):
        """Test handle subdomain enumeration option with passive"""
        mock_input.side_effect = ['example.com', '2']
        mock_is_valid.return_value = True
        mock_enum.return_value = {'subdomains': ['api.example.com']}
        
        handle_subdomain_enumeration_option()
        
        mock_enum.assert_called_once_with('example.com')
        mock_display.assert_called_once_with({'subdomains': ['api.example.com']})

    @patch('network_toolkit.main.is_valid_ip')
    @patch('network_toolkit.main.get_public_ip_report')
    @patch('network_toolkit.main.display_threat_intel_results')
    @patch('builtins.input')
    def test_handle_threat_intel_option(self, mock_input, mock_display, mock_report, mock_is_valid):
        """Test handle threat intelligence option"""
        mock_input.return_value = '8.8.8.8'
        mock_is_valid.return_value = True
        mock_report.return_value = {'reputation': 'good'}
        
        handle_threat_intel_option()
        
        mock_report.assert_called_once_with('8.8.8.8')
        mock_display.assert_called_once_with({'reputation': 'good'})

    @patch('network_toolkit.main.is_valid_domain')
    @patch('network_toolkit.main.certificate_transparency_search')
    @patch('network_toolkit.main.display_ct_results')
    @patch('builtins.input')
    def test_handle_ct_search_option(self, mock_input, mock_display, mock_search, mock_is_valid):
        """Test handle certificate transparency search option"""
        mock_input.return_value = 'example.com'
        mock_is_valid.return_value = True
        mock_search.return_value = {'certificates': []}
        
        handle_ct_search_option()
        
        mock_search.assert_called_once_with('example.com')
        mock_display.assert_called_once_with({'certificates': []})

    @patch('network_toolkit.main.is_valid_domain')
    @patch('network_toolkit.main.comprehensive_subdomain_enumeration')
    @patch('network_toolkit.main.display_comprehensive_results')
    @patch('builtins.input')
    def test_handle_comprehensive_subdomain_enum_option(self, mock_input, mock_display, mock_enum, mock_is_valid):
        """Test handle comprehensive subdomain enumeration option"""
        mock_input.return_value = 'example.com'
        mock_is_valid.return_value = True
        mock_enum.return_value = {'subdomains': ['www.example.com', 'api.example.com']}
        
        handle_comprehensive_subdomain_enum_option()
        
        mock_enum.assert_called_once_with('example.com')
        mock_display.assert_called_once_with({'subdomains': ['www.example.com', 'api.example.com']})

    @patch('network_toolkit.main.init_colorama')
    @patch('network_toolkit.main.platform.system')
    @patch('network_toolkit.main.check_optional_dependencies')
    @patch('builtins.input')
    @patch('builtins.print')
    def test_main_exit(self, mock_print, mock_input, mock_check, mock_platform, mock_colorama):
        """Test main function exit option"""
        mock_colorama.return_value = (MagicMock(), MagicMock())
        mock_platform.return_value = 'Linux'
        mock_input.side_effect = ['20']  # Exit option
        
        with pytest.raises(SystemExit):
            main()
        
        mock_colorama.assert_called_once()
        mock_platform.assert_called_once()
        mock_check.assert_called_once()

    @patch('network_toolkit.main.init_colorama')
    @patch('network_toolkit.main.platform.system')
    @patch('network_toolkit.main.check_optional_dependencies')
    @patch('builtins.input')
    @patch('builtins.print')
    def test_main_invalid_option(self, mock_print, mock_input, mock_check, mock_platform, mock_colorama):
        """Test main function with invalid option"""
        mock_colorama.return_value = (MagicMock(), MagicMock())
        mock_platform.return_value = 'Linux'
        mock_input.side_effect = ['invalid', '20']  # Invalid then exit
        
        with pytest.raises(SystemExit):
            main()
        
        # Should handle invalid option and continue

    @patch('network_toolkit.main.init_colorama')
    @patch('network_toolkit.main.platform.system')
    @patch('network_toolkit.main.check_optional_dependencies')
    @patch('builtins.input')
    @patch('builtins.print')
    def test_main_keyboard_interrupt(self, mock_print, mock_input, mock_check, mock_platform, mock_colorama):
        """Test main function handling keyboard interrupt"""
        mock_colorama.return_value = (MagicMock(), MagicMock())
        mock_platform.return_value = 'Linux'
        mock_input.side_effect = KeyboardInterrupt()
        
        with pytest.raises(SystemExit):
            main()

    @patch('network_toolkit.main.init_colorama')
    @patch('network_toolkit.main.platform.system')
    @patch('network_toolkit.main.check_optional_dependencies')
    @patch('builtins.input')
    @patch('builtins.print')
    def test_main_general_exception(self, mock_print, mock_input, mock_check, mock_platform, mock_colorama):
        """Test main function handling general exception"""
        mock_colorama.return_value = (MagicMock(), MagicMock())
        mock_platform.return_value = 'Linux'
        mock_input.side_effect = Exception('Test error')
        
        # Should handle exception and continue
        mock_input.side_effect = ['20']  # Then exit
        with pytest.raises(SystemExit):
            main()