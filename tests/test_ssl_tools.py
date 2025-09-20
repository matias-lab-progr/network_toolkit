import pytest
import ssl
import socket
from unittest.mock import MagicMock, patch
from datetime import datetime, timedelta
from network_toolkit.ssl_tools import (
    get_ssl_certificate,
    analyze_ssl_certificate,
    check_ssl_security,
    get_ssl_grade,
    display_ssl_analysis
)

class TestSSLTools:
    """Test cases for ssl_tools module"""

    @patch('socket.create_connection')
    @patch('ssl.create_default_context')
    def test_get_ssl_certificate_success(self, mock_context, mock_connect):
        """Test successful SSL certificate retrieval"""
        # Mock SSL context and socket
        mock_ssl_context = MagicMock()
        mock_context.return_value = mock_ssl_context
        
        # Mock socket connection
        mock_sock = MagicMock()
        mock_connect.return_value = mock_sock
        
        # Mock SSL socket
        mock_ssl_sock = MagicMock()
        mock_ssl_sock.getpeercert.return_value = b'fake_cert_der'
        mock_ssl_sock.cipher.return_value = ('TLS_AES_256_GCM_SHA384', 'TLSv1.3', 256)
        mock_ssl_sock.version.return_value = 'TLSv1.3'
        mock_ssl_context.wrap_socket.return_value.__enter__.return_value = mock_ssl_sock
        
        # Mock OpenSSL certificate loading
        with patch('OpenSSL.crypto.load_certificate') as mock_load_cert:
            mock_cert = MagicMock()
            mock_load_cert.return_value = mock_cert
            
            result = get_ssl_certificate('example.com')
            
            assert result['success'] == True
            assert result['certificate'] == mock_cert
            assert result['cipher'] == ('TLS_AES_256_GCM_SHA384', 'TLSv1.3', 256)
            assert result['version'] == 'TLSv1.3'
            mock_connect.assert_called_once_with(('example.com', 443), timeout=10)

    @patch('socket.create_connection')
    def test_get_ssl_certificate_connection_error(self, mock_connect):
        """Test SSL certificate retrieval with connection error"""
        mock_connect.side_effect = socket.timeout("Connection timed out")
        
        result = get_ssl_certificate('example.com')
        
        assert result['success'] == False
        assert 'Error obteniendo certificado' in result['error']

    def test_analyze_ssl_certificate_success(self):
        """Test successful SSL certificate analysis"""
        # Mock OpenSSL certificate
        mock_cert = MagicMock()
        
        # Mock subject components
        mock_subject = MagicMock()
        mock_subject.get_components.return_value = [
            (b'CN', b'example.com'),
            (b'O', b'Example Organization')
        ]
        mock_cert.get_subject.return_value = mock_subject
        
        # Mock issuer components
        mock_issuer = MagicMock()
        mock_issuer.get_components.return_value = [
            (b'CN', b'Let\'s Encrypt'),
            (b'O', b'Let\'s Encrypt Authority X3')
        ]
        mock_cert.get_issuer.return_value = mock_issuer
        
        # Mock dates
        mock_cert.get_notBefore.return_value = b'20230101000000Z'
        mock_cert.get_notAfter.return_value = b'20240101000000Z'
        
        # Mock extensions
        mock_extension = MagicMock()
        mock_extension.get_short_name.return_value = b'subjectAltName'
        mock_extension.__str__.return_value = 'DNS:example.com, DNS:www.example.com'
        mock_cert.get_extension_count.return_value = 1
        mock_cert.get_extension.return_value = mock_extension
        
        # Mock other properties
        mock_cert.get_serial_number.return_value = 1234567890
        mock_cert.get_signature_algorithm.return_value = b'sha256WithRSAEncryption'
        mock_cert.get_version.return_value = 2  # X.509 v3
        
        result = analyze_ssl_certificate(mock_cert)
        
        assert result['subject']['CN'] == 'example.com'
        assert result['issuer']['CN'] == 'Let\'s Encrypt'
        assert result['serial_number'] == 1234567890
        assert result['signature_algorithm'] == 'sha256WithRSAEncryption'
        assert result['version'] == 2
        assert 'subjectAltName' in result['extensions']
        assert isinstance(result['not_before'], datetime)
        assert isinstance(result['not_after'], datetime)

    def test_analyze_ssl_certificate_expired(self):
        """Test SSL certificate analysis with expired certificate"""
        mock_cert = MagicMock()
        
        # Mock subject and issuer
        mock_subject = MagicMock()
        mock_subject.get_components.return_value = [(b'CN', b'example.com')]
        mock_cert.get_subject.return_value = mock_subject
        
        mock_issuer = MagicMock()
        mock_issuer.get_components.return_value = [(b'CN', b'Test CA')]
        mock_cert.get_issuer.return_value = mock_issuer
        
        # Set expired dates (1 year ago)
        past_date = (datetime.now() - timedelta(days=365)).strftime('%Y%m%d%H%M%SZ').encode()
        mock_cert.get_notBefore.return_value = b'20200101000000Z'
        mock_cert.get_notAfter.return_value = past_date
        
        # Mock extensions
        mock_cert.get_extension_count.return_value = 0
        
        # Mock other properties
        mock_cert.get_serial_number.return_value = 1234567890
        mock_cert.get_signature_algorithm.return_value = b'sha256WithRSAEncryption'
        mock_cert.get_version.return_value = 2
        
        result = analyze_ssl_certificate(mock_cert)
        
        assert result['has_expired'] == True
        assert result['days_until_expiry'] < 0

    def test_analyze_ssl_certificate_error(self):
        """Test SSL certificate analysis with error"""
        mock_cert = MagicMock()
        mock_cert.get_subject.side_effect = Exception('Test error')
        
        result = analyze_ssl_certificate(mock_cert)
        
        assert result['success'] == False
        assert 'Error analizando certificado' in result['error']

    def test_check_ssl_security_high_score(self):
        """Test SSL security check with high score"""
        ssl_info = {
            'days_until_expiry': 365,
            'has_expired': False,
            'extensions': {
                'subjectAltName': 'DNS:example.com',
                'OCSP': 'OCSP - URI:http://ocsp.example.com'
            }
        }
        cipher_info = ('TLS_AES_256_GCM_SHA384', 'TLSv1.3', 256)
        
        result = check_ssl_security(ssl_info, cipher_info)
        
        assert result['score'] >= 90
        assert result['grade'] == 'A+'
        assert len(result['security_issues']) == 0
        assert len(result['recommendations']) > 0

    def test_check_ssl_security_expired(self):
        """Test SSL security check with expired certificate"""
        ssl_info = {
            'days_until_expiry': -30,
            'has_expired': True,
            'extensions': {
                'subjectAltName': 'DNS:example.com'
            }
        }
        cipher_info = ('TLS_AES_256_GCM_SHA384', 'TLSv1.3', 256)
        
        result = check_ssl_security(ssl_info, cipher_info)
        
        assert result['score'] <= 50
        assert 'EXPIRADO' in str(result['security_issues'])
        assert result['grade'] in ['D', 'F']

    def test_check_ssl_security_weak_cipher(self):
        """Test SSL security check with weak cipher"""
        ssl_info = {
            'days_until_expiry': 365,
            'has_expired': False,
            'extensions': {
                'subjectAltName': 'DNS:example.com'
            }
        }
        cipher_info = ('RC4-MD5', 'TLSv1.0', 128)
        
        result = check_ssl_security(ssl_info, cipher_info)
        
        assert result['score'] < 80
        assert 'Cipher suite débil' in str(result['security_issues'])
        assert 'Actualizar a cipher suites modernos' in str(result['recommendations'])

    def test_check_ssl_security_no_san(self):
        """Test SSL security check without Subject Alternative Names"""
        ssl_info = {
            'days_until_expiry': 365,
            'has_expired': False,
            'extensions': {}  # No SAN extension
        }
        cipher_info = ('TLS_AES_256_GCM_SHA384', 'TLSv1.3', 256)
        
        result = check_ssl_security(ssl_info, cipher_info)
        
        assert result['score'] < 90
        assert 'Subject Alternative Names' in str(result['security_issues'])

    def test_get_ssl_grade_a_plus(self):
        """Test SSL grade calculation for A+"""
        assert get_ssl_grade(95) == 'A+'
        assert get_ssl_grade(100) == 'A+'

    def test_get_ssl_grade_a(self):
        """Test SSL grade calculation for A"""
        assert get_ssl_grade(85) == 'A'
        assert get_ssl_grade(89) == 'A'

    def test_get_ssl_grade_b(self):
        """Test SSL grade calculation for B"""
        assert get_ssl_grade(75) == 'B'
        assert get_ssl_grade(79) == 'B'

    def test_get_ssl_grade_c(self):
        """Test SSL grade calculation for C"""
        assert get_ssl_grade(65) == 'C'
        assert get_ssl_grade(69) == 'C'

    def test_get_ssl_grade_d(self):
        """Test SSL grade calculation for D"""
        assert get_ssl_grade(55) == 'D'
        assert get_ssl_grade(59) == 'D'

    def test_get_ssl_grade_f(self):
        """Test SSL grade calculation for F"""
        assert get_ssl_grade(45) == 'F'
        assert get_ssl_grade(0) == 'F'

    @patch('builtins.print')
    def test_display_ssl_analysis_success(self, mock_print):
        """Test SSL analysis display with successful results"""
        results = {
            'success': True,
            'ssl_info': {
                'subject': {'CN': 'example.com', 'O': 'Example Org'},
                'issuer': {'CN': 'Let\'s Encrypt', 'O': 'Let\'s Encrypt Authority X3'},
                'not_before': datetime(2023, 1, 1),
                'not_after': datetime(2024, 1, 1),
                'days_until_expiry': 365,
                'serial_number': 1234567890,
                'signature_algorithm': 'sha256WithRSAEncryption',
                'version': 2,
                'extensions': {
                    'subjectAltName': 'DNS:example.com',
                    'keyUsage': 'Digital Signature, Key Encipherment'
                }
            },
            'security': {
                'score': 95,
                'grade': 'A+',
                'security_issues': [],
                'recommendations': ['Mantener certificado actualizado']
            },
            'cipher': ('TLS_AES_256_GCM_SHA384', 'TLSv1.3', 256),
            'version': 'TLSv1.3'
        }
        
        display_ssl_analysis(results, 'example.com')
        
        # Verify that print was called multiple times (indicating successful display)
        assert mock_print.call_count > 10

    @patch('builtins.print')
    def test_display_ssl_analysis_failure(self, mock_print):
        """Test SSL analysis display with failed results"""
        results = {
            'success': False,
            'error': 'SSL handshake failed'
        }
        
        display_ssl_analysis(results, 'example.com')
        
        # Should print error message
        mock_print.assert_called()
        call_args = str(mock_print.call_args)
        assert 'SSL handshake failed' in call_args or 'Error' in call_args

    @patch('builtins.print')
    def test_display_ssl_analysis_with_issues(self, mock_print):
        """Test SSL analysis display with security issues"""
        results = {
            'success': True,
            'ssl_info': {
                'subject': {'CN': 'example.com'},
                'issuer': {'CN': 'Test CA'},
                'not_before': datetime(2023, 1, 1),
                'not_after': datetime(2023, 2, 1),  # Expires soon
                'days_until_expiry': 5,
                'serial_number': 1234567890,
                'signature_algorithm': 'sha1WithRSAEncryption',  # Weak algorithm
                'version': 2,
                'extensions': {}
            },
            'security': {
                'score': 65,
                'grade': 'C',
                'security_issues': [
                    'Certificado expira en 5 días',
                    'Algoritmo de firma débil'
                ],
                'recommendations': [
                    'Renovar certificado',
                    'Actualizar algoritmo de firma'
                ]
            },
            'cipher': ('RC4-MD5', 'TLSv1.0', 128),  # Weak cipher
            'version': 'TLSv1.0'
        }
        
        display_ssl_analysis(results, 'example.com')
        
        # Should display security issues
        assert mock_print.call_count > 10

    def test_check_ssl_security_short_key(self):
        """Test SSL security check with short key length"""
        ssl_info = {
            'days_until_expiry': 365,
            'has_expired': False,
            'extensions': {
                'subjectAltName': 'DNS:example.com'
            }
        }
        cipher_info = ('TLS_RSA_WITH_AES_128_CBC_SHA', 'TLSv1.2', 112)  # Short key
        
        result = check_ssl_security(ssl_info, cipher_info)
        
        assert result['score'] < 90
        assert 'Longitud de clave insuficiente' in str(result['security_issues'])

    def test_check_ssl_security_no_ocsp(self):
        """Test SSL security check without OCSP"""
        ssl_info = {
            'days_until_expiry': 365,
            'has_expired': False,
            'extensions': {
                'subjectAltName': 'DNS:example.com'
                # No OCSP extension
            }
        }
        cipher_info = ('TLS_AES_256_GCM_SHA384', 'TLSv1.3', 256)
        
        result = check_ssl_security(ssl_info, cipher_info)
        
        assert result['score'] < 100  # Should have minor deduction for no OCSP
        assert 'OCSP' in str(result['recommendations'])

    def test_analyze_ssl_certificate_no_extensions(self):
        """Test SSL certificate analysis with no extensions"""
        mock_cert = MagicMock()
        
        # Mock subject and issuer
        mock_subject = MagicMock()
        mock_subject.get_components.return_value = [(b'CN', b'example.com')]
        mock_cert.get_subject.return_value = mock_subject
        
        mock_issuer = MagicMock()
        mock_issuer.get_components.return_value = [(b'CN', b'Test CA')]
        mock_cert.get_issuer.return_value = mock_issuer
        
        # Mock dates
        mock_cert.get_notBefore.return_value = b'20230101000000Z'
        mock_cert.get_notAfter.return_value = b'20240101000000Z'
        
        # No extensions
        mock_cert.get_extension_count.return_value = 0
        
        # Mock other properties
        mock_cert.get_serial_number.return_value = 1234567890
        mock_cert.get_signature_algorithm.return_value = b'sha256WithRSAEncryption'
        mock_cert.get_version.return_value = 2
        
        result = analyze_ssl_certificate(mock_cert)
        
        assert result['extensions'] == {}
        assert result['days_until_expiry'] > 0
        assert not result['has_expired']