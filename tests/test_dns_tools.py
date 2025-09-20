import pytest
import dns.resolver
import dns.exception
from unittest.mock import MagicMock, patch, mock_open
from network_toolkit.dns_tools import (
    dns_lookup,
    comprehensive_dns_scan,
    batch_dns_lookup,
    reverse_dns_lookup,
    trace_dns_resolution,
    handle_trace_dns_option,
    _display_raw_output,
    _display_pentesting_output,
    _check_direct_dns_allowed
)

class TestDNSTools:
    """Test cases for dns_tools module"""

    @patch('network_toolkit.dns_tools.dns.resolver.Resolver')
    def test_dns_lookup_success(self, mock_resolver):
        """Test successful DNS lookup"""
        mock_instance = MagicMock()
        mock_resolver.return_value = mock_instance
        
        mock_answer = MagicMock()
        mock_answer.rrset = MagicMock()
        mock_answer.rrset.ttl = 300
        mock_answer.__iter__ = lambda self: iter([MagicMock()])
        mock_answer.__getitem__ = lambda self, index: MagicMock()
        
        mock_instance.resolve.return_value = mock_answer
        
        result = dns_lookup('example.com', 'A')
        
        assert isinstance(result, list)
        mock_instance.resolve.assert_called_once_with('example.com', 'A')

    @patch('network_toolkit.dns_tools.dns.resolver.Resolver')
    def test_dns_lookup_timeout(self, mock_resolver):
        """Test DNS lookup timeout"""
        mock_instance = MagicMock()
        mock_resolver.return_value = mock_instance
        mock_instance.resolve.side_effect = dns.resolver.Timeout()
        
        result = dns_lookup('example.com', 'A')
        assert isinstance(result, list)
        assert len(result) == 0

    @patch('network_toolkit.dns_tools.dns.resolver.Resolver')
    def test_dns_lookup_no_answer(self, mock_resolver):
        """Test DNS lookup with no answer"""
        mock_instance = MagicMock()
        mock_resolver.return_value = mock_instance
        mock_instance.resolve.side_effect = dns.resolver.NoAnswer()
        
        result = dns_lookup('example.com', 'A')
        assert isinstance(result, list)
        assert len(result) == 0

    @patch('network_toolkit.dns_tools.dns.resolver.Resolver')
    def test_dns_lookup_nxdomain(self, mock_resolver):
        """Test DNS lookup for non-existent domain"""
        mock_instance = MagicMock()
        mock_resolver.return_value = mock_instance
        mock_instance.resolve.side_effect = dns.resolver.NXDOMAIN()
        
        result = dns_lookup('nonexistent-domain.com', 'A')
        assert isinstance(result, list)
        assert len(result) == 0

    @patch('network_toolkit.dns_tools.dns_lookup')
    def test_comprehensive_dns_scan(self, mock_dns_lookup):
        """Test comprehensive DNS scan"""
        mock_dns_lookup.return_value = [{'type': 'A', 'data': '93.184.216.34'}]
        
        result = comprehensive_dns_scan('example.com')
        
        assert isinstance(result, dict)
        assert 'A' in result
        assert 'AAAA' in result
        assert 'NS' in result
        assert 'MX' in result
        assert 'TXT' in result
        assert 'CNAME' in result
        assert 'SOA' in result
        assert mock_dns_lookup.call_count == 7

    @patch('builtins.open', new_callable=mock_open, read_data='sub1.example.com\nsub2.example.com\n')
    @patch('network_toolkit.dns_tools.dns_lookup')
    def test_batch_dns_lookup_success(self, mock_dns_lookup, mock_file):
        """Test batch DNS lookup with valid file"""
        mock_dns_lookup.return_value = [{'type': 'A', 'data': '93.184.216.34'}]
        
        result = batch_dns_lookup('subdomains.txt', 'A')
        
        assert isinstance(result, dict)
        assert 'sub1.example.com' in result
        assert 'sub2.example.com' in result
        assert mock_dns_lookup.call_count == 2

    @patch('builtins.open')
    def test_batch_dns_lookup_file_not_found(self, mock_open):
        """Test batch DNS lookup with non-existent file"""
        mock_open.side_effect = FileNotFoundError()
        
        result = batch_dns_lookup('nonexistent.txt', 'A')
        assert result == {}

    @patch('network_toolkit.dns_tools.dns_lookup')
    def test_reverse_dns_lookup_ipv4(self, mock_dns_lookup):
        """Test reverse DNS lookup for IPv4"""
        mock_dns_lookup.return_value = [{'type': 'PTR', 'data': 'example.com.'}]
        
        result = reverse_dns_lookup('8.8.8.8')
        
        assert isinstance(result, list)
        mock_dns_lookup.assert_called_once()

    @patch('network_toolkit.dns_tools.dns_lookup')
    def test_reverse_dns_lookup_ipv6(self, mock_dns_lookup):
        """Test reverse DNS lookup for IPv6"""
        mock_dns_lookup.return_value = [{'type': 'PTR', 'data': 'example.com.'}]
        
        result = reverse_dns_lookup('2001:4860:4860::8888')
        
        assert isinstance(result, list)
        mock_dns_lookup.assert_called_once()

    @patch('network_toolkit.dns_tools._check_direct_dns_allowed')
    @patch('network_toolkit.dns_tools._trace_dns_direct')
    def test_trace_dns_resolution_direct_allowed(self, mock_trace_direct, mock_check_direct):
        """Test DNS trace resolution with direct queries allowed"""
        mock_check_direct.return_value = True
        mock_trace_direct.return_value = None
        
        result = trace_dns_resolution('example.com', 'A')
        
        mock_check_direct.assert_called_once()
        mock_trace_direct.assert_called_once_with('example.com', 'A', 5)

    @patch('network_toolkit.dns_tools._check_direct_dns_allowed')
    @patch('network_toolkit.dns_tools._trace_dns_recursive')
    def test_trace_dns_resolution_direct_blocked(self, mock_trace_recursive, mock_check_direct):
        """Test DNS trace resolution with direct queries blocked"""
        mock_check_direct.return_value = False
        mock_trace_recursive.return_value = None
        
        result = trace_dns_resolution('example.com', 'A')
        
        mock_check_direct.assert_called_once()
        mock_trace_recursive.assert_called_once_with('example.com', 'A', 5)

    @patch('network_toolkit.dns_tools.is_valid_domain')
    @patch('network_toolkit.dns_tools.trace_dns_resolution')
    def test_handle_trace_dns_option_valid_domain(self, mock_trace, mock_is_valid):
        """Test handle trace DNS option with valid domain"""
        mock_is_valid.return_value = True
        
        # Mock input calls
        with patch('builtins.input', side_effect=['example.com', 'A', '5']):
            handle_trace_dns_option()
        
        mock_trace.assert_called_once_with('example.com', 'A', 5)

    @patch('network_toolkit.dns_tools.is_valid_domain')
    def test_handle_trace_dns_option_invalid_domain(self, mock_is_valid):
        """Test handle trace DNS option with invalid domain"""
        mock_is_valid.return_value = False
        
        with patch('builtins.input', return_value='invalid-domain'):
            handle_trace_dns_option()
        
        # Should not call trace_dns_resolution

    @patch('network_toolkit.dns_tools.dns.query.udp')
    def test_check_direct_dns_allowed_true(self, mock_query_udp):
        """Test direct DNS allowed check returning True"""
        mock_query_udp.return_value = MagicMock()
        
        result = _check_direct_dns_allowed()
        assert result == True

    @patch('network_toolkit.dns_tools.dns.query.udp')
    def test_check_direct_dns_allowed_false(self, mock_query_udp):
        """Test direct DNS allowed check returning False"""
        mock_query_udp.side_effect = Exception('Connection failed')
        
        result = _check_direct_dns_allowed()
        assert result == False

    def test_display_raw_output(self):
        """Test raw output display"""
        import io
        from contextlib import redirect_stdout
        
        results = [
            {'type': 'A', 'data': '93.184.216.34', 'ttl': 300},
            {'type': 'A', 'data': '93.184.216.35', 'ttl': 300}
        ]
        
        f = io.StringIO()
        with redirect_stdout(f):
            _display_raw_output(results, 'example.com', 'A')
        
        output = f.getvalue()
        assert '93.184.216.34' in output
        assert '93.184.216.35' in output

    def test_display_pentesting_output_a_record(self):
        """Test pentesting output display for A records"""
        import io
        from contextlib import redirect_stdout
        
        results = [
            {'type': 'A', 'data': '93.184.216.34', 'ttl': 300, 'raw': MagicMock()}
        ]
        
        f = io.StringIO()
        with redirect_stdout(f):
            _display_pentesting_output(results, 'example.com', 'A')
        
        output = f.getvalue()
        assert '93.184.216.34' in output

    def test_display_pentesting_output_mx_record(self):
        """Test pentesting output display for MX records"""
        import io
        from contextlib import redirect_stdout
        
        # Create a mock MX record with preference attribute
        mock_raw = MagicMock()
        mock_raw.preference = 10
        
        results = [
            {'type': 'MX', 'data': 'mail.example.com', 'ttl': 300, 'raw': mock_raw}
        ]
        
        f = io.StringIO()
        with redirect_stdout(f):
            _display_pentesting_output(results, 'example.com', 'MX')
        
        output = f.getvalue()
        assert 'mail.example.com' in output

    def test_display_pentesting_output_txt_record_spf(self):
        """Test pentesting output display for TXT records with SPF"""
        import io
        from contextlib import redirect_stdout
        
        results = [
            {'type': 'TXT', 'data': '"v=spf1 include:_spf.example.com ~all"', 'ttl': 300, 'raw': MagicMock()}
        ]
        
        f = io.StringIO()
        with redirect_stdout(f):
            _display_pentesting_output(results, 'example.com', 'TXT')
        
        output = f.getvalue()
        assert 'SPF:' in output
        assert 'v=spf1' in output

    def test_display_pentesting_output_txt_record_dmarc(self):
        """Test pentesting output display for TXT records with DMARC"""
        import io
        from contextlib import redirect_stdout
        
        results = [
            {'type': 'TXT', 'data': '"v=DMARC1 p=none sp=quarantine rua=mailto:dmarc@example.com"', 'ttl': 300, 'raw': MagicMock()}
        ]
        
        f = io.StringIO()
        with redirect_stdout(f):
            _display_pentesting_output(results, 'example.com', 'TXT')
        
        output = f.getvalue()
        assert 'DMARC:' in output
        assert 'v=DMARC1' in output

    def test_display_pentesting_output_cname_record(self):
        """Test pentesting output display for CNAME records"""
        import io
        from contextlib import redirect_stdout
        
        results = [
            {'type': 'CNAME', 'data': 'cdn.example.com', 'ttl': 300, 'raw': MagicMock()}
        ]
        
        f = io.StringIO()
        with redirect_stdout(f):
            _display_pentesting_output(results, 'example.com', 'CNAME')
        
        output = f.getvalue()
        assert 'cdn.example.com' in output

    @patch('network_toolkit.dns_tools.dns.resolver.Resolver')
    def test_dns_lookup_with_nameserver(self, mock_resolver):
        """Test DNS lookup with custom nameserver"""
        mock_instance = MagicMock()
        mock_resolver.return_value = mock_instance
        
        mock_answer = MagicMock()
        mock_answer.rrset = MagicMock()
        mock_answer.rrset.ttl = 300
        mock_answer.__iter__ = lambda self: iter([MagicMock()])
        
        mock_instance.resolve.return_value = mock_answer
        
        result = dns_lookup('example.com', 'A', '1.1.1.1')
        
        assert mock_instance.nameservers == ['1.1.1.1']
        mock_instance.resolve.assert_called_once_with('example.com', 'A')

    @patch('network_toolkit.dns_tools.dns.resolver.Resolver')
    def test_dns_lookup_raw_mode(self, mock_resolver):
        """Test DNS lookup in raw mode"""
        mock_instance = MagicMock()
        mock_resolver.return_value = mock_instance
        
        mock_answer = MagicMock()
        mock_answer.rrset = MagicMock()
        mock_answer.rrset.ttl = 300
        mock_answer.__iter__ = lambda self: iter([MagicMock()])
        
        mock_instance.resolve.return_value = mock_answer
        
        result = dns_lookup('example.com', 'A', raw=True)
        
        # Should still return results
        assert isinstance(result, list)

    @patch('network_toolkit.dns_tools.time.sleep')
    @patch('network_toolkit.dns_tools.dns_lookup')
    def test_comprehensive_dns_scan_with_delay(self, mock_dns_lookup, mock_sleep):
        """Test comprehensive DNS scan includes delays between queries"""
        mock_dns_lookup.return_value = [{'type': 'A', 'data': '93.184.216.34'}]
        
        result = comprehensive_dns_scan('example.com')
        
        # Should call sleep between queries
        assert mock_sleep.call_count == 6  # 7 record types - 1

    @patch('network_toolkit.dns_tools.dns.reversename.from_address')
    @patch('network_toolkit.dns_tools.dns_lookup')
    def test_reverse_dns_lookup_exception_handling(self, mock_dns_lookup, mock_from_address):
        """Test reverse DNS lookup exception handling"""
        mock_from_address.side_effect = Exception('Test error')
        
        result = reverse_dns_lookup('8.8.8.8')
        
        assert isinstance(result, list)
        assert len(result) == 0