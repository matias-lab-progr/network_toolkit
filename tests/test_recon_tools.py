import pytest
import os
import dns.resolver
from unittest.mock import MagicMock, patch, mock_open
from datetime import datetime
from network_toolkit.recon_tools import (
    load_subdomain_wordlist,
    dns_subdomain_enumeration,
    passive_subdomain_enumeration,
    display_subdomain_results,
    certificate_transparency_search,
    display_ct_results,
    comprehensive_subdomain_enumeration,
    display_comprehensive_results,
    get_data_directory,
    export_subdomains_to_file,
    list_previous_exports,
    compare_with_previous_export
)

class TestReconTools:
    """Test cases for recon_tools module"""

    def test_load_subdomain_wordlist(self):
        """Test loading subdomain wordlist"""
        wordlist = load_subdomain_wordlist()
        
        assert isinstance(wordlist, list)
        assert len(wordlist) > 0
        assert 'www' in wordlist
        assert 'admin' in wordlist
        assert 'api' in wordlist

    @patch('dns.resolver.Resolver')
    def test_dns_subdomain_enumeration_success(self, mock_resolver):
        """Test DNS subdomain enumeration with successful results"""
        mock_instance = MagicMock()
        mock_resolver.return_value = mock_instance
        
        # Mock successful DNS resolution
        mock_answer = MagicMock()
        mock_answer.__iter__ = lambda self: iter([MagicMock()])
        mock_instance.resolve.side_effect = [
            mock_answer,  # www.example.com
            dns.resolver.NXDOMAIN(),  # mail.example.com
            mock_answer,  # api.example.com
        ]
        
        result = dns_subdomain_enumeration('example.com', ['www', 'mail', 'api'])
        
        assert result['domain'] == 'example.com'
        assert len(result['found_subdomains']) == 2  # www and api should be found
        assert result['total_tested'] == 3

    @patch('dns.resolver.Resolver')
    def test_dns_subdomain_enumeration_no_results(self, mock_resolver):
        """Test DNS subdomain enumeration with no results"""
        mock_instance = MagicMock()
        mock_resolver.return_value = mock_instance
        mock_instance.resolve.side_effect = dns.resolver.NXDOMAIN()
        
        result = dns_subdomain_enumeration('example.com', ['www', 'mail'])
        
        assert result['domain'] == 'example.com'
        assert len(result['found_subdomains']) == 0
        assert result['total_tested'] == 2

    @patch('concurrent.futures.ThreadPoolExecutor')
    def test_dns_subdomain_enumeration_with_threads(self, mock_executor):
        """Test DNS subdomain enumeration with threading"""
        mock_executor_instance = MagicMock()
        mock_executor.return_value.__enter__.return_value = mock_executor_instance
        
        # Mock future results
        mock_future = MagicMock()
        mock_future.result.return_value = ('www.example.com', ['192.168.1.1'])
        mock_executor_instance.submit.return_value = mock_future
        mock_executor_instance.__enter__.return_value.as_completed.return_value = [mock_future]
        
        result = dns_subdomain_enumeration('example.com', ['www'], threads=10)
        
        assert len(result['found_subdomains']) == 1
        assert result['found_subdomains'][0][0] == 'www.example.com'

    def test_passive_subdomain_enumeration_not_implemented(self):
        """Test passive subdomain enumeration (not implemented)"""
        result = passive_subdomain_enumeration('example.com')
        
        assert result['domain'] == 'example.com'
        assert result['method'] == 'passive'
        assert len(result['found_subdomains']) == 0

    @patch('builtins.print')
    def test_display_subdomain_results_with_results(self, mock_print):
        """Test displaying subdomain results with found subdomains"""
        results = {
            'domain': 'example.com',
            'found_subdomains': [('www.example.com', ['192.168.1.1']), ('api.example.com', ['192.168.1.2'])],
            'total_tested': 100,
            'elapsed_time': 5.5
        }
        
        display_subdomain_results(results)
        
        # Verify that print was called multiple times
        assert mock_print.call_count > 5
        # Should display domain and results
        call_args = str(mock_print.call_args_list)
        assert 'example.com' in call_args
        assert 'www.example.com' in call_args

    @patch('builtins.print')
    def test_display_subdomain_results_no_results(self, mock_print):
        """Test displaying subdomain results with no results"""
        results = {
            'domain': 'example.com',
            'found_subdomains': [],
            'total_tested': 100,
            'elapsed_time': 5.5
        }
        
        display_subdomain_results(results)
        
        # Should display "No se encontraron subdominios"
        call_args = str(mock_print.call_args_list)
        assert 'No se encontraron subdominios' in call_args

    @patch('requests.get')
    def test_certificate_transparency_search_success(self, mock_get):
        """Test certificate transparency search with successful response"""
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = [
            {'name_value': 'www.example.com'},
            {'name_value': 'api.example.com'},
            {'name_value': 'test.example.com\ndev.example.com'}  # Multiple subdomains
        ]
        mock_get.return_value = mock_response
        
        result = certificate_transparency_search('example.com')
        
        assert result['success'] == True
        assert result['domain'] == 'example.com'
        assert len(result['subdomains']) >= 3  # Should include all found subdomains
        assert 'www.example.com' in result['subdomains']
        assert 'api.example.com' in result['subdomains']

    @patch('requests.get')
    def test_certificate_transparency_search_failure(self, mock_get):
        """Test certificate transparency search with failed response"""
        mock_response = MagicMock()
        mock_response.status_code = 404
        mock_get.return_value = mock_response
        
        result = certificate_transparency_search('example.com')
        
        assert result['success'] == False
        assert 'Error HTTP' in result['error']

    @patch('requests.get')
    def test_certificate_transparency_search_timeout(self, mock_get):
        """Test certificate transparency search with timeout"""
        mock_get.side_effect = Exception('Timeout')
        
        result = certificate_transparency_search('example.com')
        
        assert result['success'] == False
        assert 'Error' in result['error']

    @patch('builtins.print')
    def test_display_ct_results_success(self, mock_print):
        """Test displaying CT results with successful results"""
        results = {
            'success': True,
            'domain': 'example.com',
            'subdomains': ['www.example.com', 'api.example.com', 'test.example.com'],
            'total_found': 3,
            'source': 'crt.sh',
            'url': 'https://crt.sh/?q=%.example.com'
        }
        
        display_ct_results(results)
        
        # Should display results
        assert mock_print.call_count > 5
        call_args = str(mock_print.call_args_list)
        assert 'example.com' in call_args
        assert 'crt.sh' in call_args

    @patch('builtins.print')
    def test_display_ct_results_failure(self, mock_print):
        """Test displaying CT results with failed results"""
        results = {
            'success': False,
            'error': 'Test error',
            'domain': 'example.com'
        }
        
        display_ct_results(results)
        
        # Should display error message
        call_args = str(mock_print.call_args_list)
        assert 'Test error' in call_args

    @patch('network_toolkit.recon_tools.certificate_transparency_search')
    @patch('network_toolkit.recon_tools.dns_subdomain_enumeration')
    @patch('network_toolkit.recon_tools.passive_subdomain_enumeration')
    def test_comprehensive_subdomain_enumeration(self, mock_passive, mock_dns, mock_ct):
        """Test comprehensive subdomain enumeration"""
        # Mock all methods
        mock_ct.return_value = {
            'success': True,
            'subdomains': ['www.example.com', 'api.example.com']
        }
        mock_dns.return_value = {
            'found_subdomains': [('test.example.com', ['192.168.1.1'])]
        }
        mock_passive.return_value = {
            'found_subdomains': ['dev.example.com']
        }
        
        result = comprehensive_subdomain_enumeration('example.com')
        
        assert result['success'] == True
        assert result['domain'] == 'example.com'
        assert len(result['subdomains']) == 4  # All unique subdomains
        assert 'www.example.com' in result['subdomains']
        assert 'test.example.com' in result['subdomains']
        assert 'dev.example.com' in result['subdomains']
        assert 'api.example.com' in result['subdomains']

    @patch('builtins.print')
    def test_display_comprehensive_results(self, mock_print):
        """Test displaying comprehensive results"""
        results = {
            'success': True,
            'domain': 'example.com',
            'subdomains': ['www.example.com', 'api.example.com', 'test.example.com'],
            'total_found': 3,
            'summary': {
                'ct_count': 2,
                'dns_count': 1,
                'passive_count': 1
            }
        }
        
        display_comprehensive_results(results)
        
        # Should display comprehensive results
        assert mock_print.call_count > 5
        call_args = str(mock_print.call_args_list)
        assert 'example.com' in call_args
        assert 'COMPLETA' in call_args

    def test_get_data_directory(self):
        """Test getting data directory path"""
        data_dir = get_data_directory()
        
        assert isinstance(data_dir, str)
        assert data_dir.endswith('data')
        assert 'network_toolkit' in data_dir

    @patch('os.makedirs')
    @patch('builtins.open', new_callable=mock_open)
    @patch('os.path.exists')
    def test_export_subdomains_to_file(self, mock_exists, mock_open, mock_makedirs):
        """Test exporting subdomains to file"""
        mock_exists.return_value = False  # Directory doesn't exist
        
        results = {
            'domain': 'example.com',
            'subdomains': ['www.example.com', 'api.example.com'],
            'total_found': 2,
            'summary': {
                'ct_count': 1,
                'dns_count': 1,
                'passive_count': 0
            }
        }
        
        result_path = export_subdomains_to_file(results)
        
        # Should create directory and file
        mock_makedirs.assert_called_once()
        mock_open.assert_called_once()
        assert result_path is not None

    @patch('os.listdir')
    @patch('os.path.getmtime')
    @patch('os.path.getsize')
    def test_list_previous_exports(self, mock_getsize, mock_getmtime, mock_listdir):
        """Test listing previous exports"""
        mock_listdir.return_value = ['example.com_subdomains_20231201_120000.txt']
        mock_getmtime.return_value = 1701446400  # Fixed timestamp
        mock_getsize.return_value = 1024
        
        exports = list_previous_exports('example.com')
        
        assert len(exports) == 1
        assert exports[0]['filename'] == 'example.com_subdomains_20231201_120000.txt'
        assert exports[0]['size'] == 1024

    @patch('builtins.open', new_callable=mock_open, read_data='www.example.com\napi.example.com\n')
    @patch('network_toolkit.recon_tools.list_previous_exports')
    def test_compare_with_previous_export(self, mock_list_exports, mock_file):
        """Test comparing with previous export"""
        mock_list_exports.return_value = [{
            'filename': 'example.com_subdomains_20231201_120000.txt',
            'path': '/fake/path',
            'time': datetime(2023, 12, 1, 12, 0, 0),
            'size': 1024
        }]
        
        current_results = {
            'domain': 'example.com',
            'subdomains': ['www.example.com', 'api.example.com', 'new.example.com']
        }
        
        comparison = compare_with_previous_export(current_results)
        
        assert comparison is not None
        assert comparison['previous_total'] == 2
        assert comparison['current_total'] == 3
        assert comparison['new_subdomains'] == ['new.example.com']
        assert comparison['removed_subdomains'] == []

    @patch('network_toolkit.recon_tools.list_previous_exports')
    def test_compare_with_previous_export_no_exports(self, mock_list_exports):
        """Test comparing with previous export when no exports exist"""
        mock_list_exports.return_value = []
        
        current_results = {
            'domain': 'example.com',
            'subdomains': ['www.example.com']
        }
        
        comparison = compare_with_previous_export(current_results)
        
        assert comparison is None

    @patch('dns.resolver.Resolver')
    def test_dns_subdomain_enumeration_empty_wordlist(self, mock_resolver):
        """Test DNS subdomain enumeration with empty wordlist"""
        mock_instance = MagicMock()
        mock_resolver.return_value = mock_instance
        
        result = dns_subdomain_enumeration('example.com', [])
        
        assert result['domain'] == 'example.com'
        assert len(result['found_subdomains']) == 0
        assert result['total_tested'] == 0

    @patch('builtins.print')
    def test_display_subdomain_results_error(self, mock_print):
        """Test displaying subdomain results with error"""
        results = {
            'error': 'Test error message'
        }
        
        display_subdomain_results(results)
        
        # Should display error message
        call_args = str(mock_print.call_args_list)
        assert 'Test error message' in call_args

    @patch('requests.get')
    def test_certificate_transparency_search_empty_response(self, mock_get):
        """Test certificate transparency search with empty response"""
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = []
        mock_get.return_value = mock_response
        
        result = certificate_transparency_search('example.com')
        
        assert result['success'] == True
        assert result['domain'] == 'example.com'
        assert len(result['subdomains']) == 0

    @patch('os.makedirs')
    @patch('builtins.open', new_callable=mock_open)
    @patch('os.path.exists')
    def test_export_subdomains_to_file_error(self, mock_exists, mock_open, mock_makedirs):
        """Test exporting subdomains to file with error"""
        mock_exists.return_value = False
        mock_open.side_effect = Exception('Test error')
        
        results = {
            'domain': 'example.com',
            'subdomains': ['www.example.com']
        }
        
        result_path = export_subdomains_to_file(results)
        
        assert result_path is None

    @patch('network_toolkit.recon_tools.certificate_transparency_search')
    @patch('network_toolkit.recon_tools.dns_subdomain_enumeration')
    @patch('network_toolkit.recon_tools.passive_subdomain_enumeration')
    def test_comprehensive_subdomain_enumeration_ct_failure(self, mock_passive, mock_dns, mock_ct):
        """Test comprehensive subdomain enumeration with CT failure"""
        mock_ct.return_value = {
            'success': False,
            'error': 'CT failed'
        }
        mock_dns.return_value = {
            'found_subdomains': [('test.example.com', ['192.168.1.1'])]
        }
        mock_passive.return_value = {
            'found_subdomains': ['dev.example.com']
        }
        
        result = comprehensive_subdomain_enumeration('example.com')
        
        assert result['success'] == True  # Should still succeed overall
        assert len(result['subdomains']) == 2  # Only DNS and passive results

    @patch('builtins.print')
    def test_display_comprehensive_results_no_summary(self, mock_print):
        """Test displaying comprehensive results without summary"""
        results = {
            'success': True,
            'domain': 'example.com',
            'subdomains': ['www.example.com'],
            'total_found': 1
            # No summary field
        }
        
        display_comprehensive_results(results)
        
        # Should still display without crashing
        assert mock_print.call_count > 0