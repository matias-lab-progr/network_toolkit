import pytest
import re
from unittest.mock import MagicMock, patch
from network_toolkit.analysis_tools import (
    analyse_ping_output,
    analyze_traceroute_output,
    analyze_whois_output
)

class TestAnalysisTools:
    """Test cases for analysis_tools module"""

    def test_analyse_ping_output_linux_success(self):
        """Test ping analysis with Linux successful output"""
        output = """
PING google.com (142.251.42.78) 56(84) bytes of data.
64 bytes from 142.251.42.78: icmp_seq=1 ttl=118 time=10.5 ms
64 bytes from 142.251.42.78: icmp_seq=2 ttl=118 time=11.2 ms
64 bytes from 142.251.42.78: icmp_seq=3 ttl=118 time=9.8 ms
64 bytes from 142.251.42.78: icmp_seq=4 ttl=118 time=10.1 ms

--- google.com ping statistics ---
4 packets transmitted, 4 received, 0% packet loss, time 3005ms
rtt min/avg/max/mdev = 9.834/10.412/11.234/0.512 ms
"""
        
        result = analyse_ping_output(output, 'google.com')
        
        assert 'google.com' in result
        assert '0%' in result
        assert '10.41' in result  # avg time
        assert 'TTL' in result
        assert 'Recomendaciones' in result

    def test_analyse_ping_output_windows_success(self):
        """Test ping analysis with Windows successful output"""
        output = """
Haciendo ping a google.com [142.251.42.78] con 32 bytes de datos:
Respuesta desde 142.251.42.78: bytes=32 tiempo=10ms TTL=118
Respuesta desde 142.251.42.78: bytes=32 tiempo=11ms TTL=118
Respuesta desde 142.251.42.78: bytes=32 tiempo=9ms TTL=118
Respuesta desde 142.251.42.78: bytes=32 tiempo=10ms TTL=118

Estadísticas de ping para 142.251.42.78:
    Paquetes: enviados = 4, recibidos = 4, perdidos = 0
    (0% perdidos),
Tiempos aproximados de ida y vuelta en milisegundos:
    Mínimo = 9ms, Máximo = 11ms, Media = 10ms
"""
        
        result = analyse_ping_output(output, 'google.com')
        
        assert 'google.com' in result
        assert '0%' in result
        assert 'Media' in result
        assert 'TTL' in result

    def test_analyse_ping_output_with_loss(self):
        """Test ping analysis with packet loss"""
        output = """
4 packets transmitted, 2 received, 50% packet loss, time 3005ms
rtt min/avg/max/mdev = 9.834/10.412/11.234/0.512 ms
"""
        
        result = analyse_ping_output(output, 'example.com')
        assert '50%' in result
        assert 'pérdida significativa' in result or 'Problemática' in result

    def test_analyse_ping_output_timeout(self):
        """Test ping analysis with timeouts"""
        output = """
3 packets transmitted, 0 received, 100% packet loss
"""
        
        result = analyse_ping_output(output, 'example.com')
        assert '100%' in result

    def test_analyze_traceroute_output_basic(self):
        """Test traceroute analysis with basic output"""
        output = """
traceroute to google.com (142.251.42.78), 30 hops max, 60 byte packets
 1  192.168.1.1  1.234 ms  1.345 ms  1.456 ms
 2  10.0.0.1  2.345 ms  2.456 ms  2.567 ms
 3  142.251.42.78  10.123 ms  10.234 ms  10.345 ms
"""
        
        result = analyze_traceroute_output(output, 'google.com')
        
        assert 'Saltos totales: 3' in result
        assert '192.168.1.1' in result
        assert 'Privada' in result
        assert 'Recomendaciones' in result

    def test_analyze_traceroute_output_with_timeouts(self):
        """Test traceroute analysis with timeouts"""
        output = """
 1  192.168.1.1  1.234 ms  1.345 ms  1.456 ms
 2  * * *
 3  142.251.42.78  10.123 ms  10.234 ms  10.345 ms
"""
        
        result = analyze_traceroute_output(output, 'google.com')
        assert 'Timeouts' in result
        assert 'Saltos con timeouts: 1' in result

    def test_analyze_traceroute_output_high_latency(self):
        """Test traceroute analysis with high latency"""
        output = """
 1  192.168.1.1  1.234 ms
 2  10.0.0.1  150.456 ms
 3  142.251.42.78  200.123 ms
"""
        
        result = analyze_traceroute_output(output, 'google.com')
        assert '200' in result  # Should detect high latency
        assert 'lentos' in result or 'Latencia muy alta' in result

    def test_analyze_whois_output_basic(self):
        """Test WHOIS analysis with basic output"""
        output = """
Domain Name: EXAMPLE.COM
Registry Domain ID: 1234567890_DOMAIN_COM-VRSN
Registrar WHOIS Server: whois.example-registrar.com
Registrar URL: http://www.example-registrar.com
Updated Date: 2023-01-01T00:00:00Z
Creation Date: 2000-01-01T00:00:00Z
Registry Expiry Date: 2024-01-01T00:00:00Z
Registrar: Example Registrar, Inc.
Name Server: NS1.EXAMPLE.COM
Name Server: NS2.EXAMPLE.COM
"""
        
        result = analyze_whois_output(output, 'example.com')
        
        assert 'Creación: 2000-01-01' in result
        assert 'Expiración: 2024-01-01' in result
        assert 'Example Registrar' in result
        assert 'Servidores DNS' in result
        assert 'Recomendaciones' in result

    def test_analyze_whois_output_spanish(self):
        """Test WHOIS analysis with Spanish output"""
        output = """
Nombre de Dominio: EXAMPLE.COM
Fecha de creación: 2000-01-01
Fecha de expiración: 2024-01-01
Última actualización: 2023-01-01
Registrador: Ejemplo Registrador S.L.
Servidores de nombres:
- NS1.EXAMPLE.COM
- NS2.EXAMPLE.COM
"""
        
        result = analyze_whois_output(output, 'example.com')
        assert 'Creación: 2000-01-01' in result
        assert 'Expiración: 2024-01-01' in result

    def test_analyze_whois_output_expiring_soon(self):
        """Test WHOIS analysis with domain expiring soon"""
        from datetime import datetime, timedelta
        future_date = (datetime.now() + timedelta(days=15)).strftime('%Y-%m-%d')
        
        output = f"""
Creation Date: 2000-01-01
Registry Expiry Date: {future_date}
"""
        
        result = analyze_whois_output(output, 'example.com')
        assert 'expira pronto' in result or '¡El dominio expira pronto!' in result

    def test_analyze_dns_output_ipv4_only(self):
        """Test DNS analysis with IPv4 only"""
        output = """
Server:         8.8.8.8
Address:        8.8.8.8#53

Non-authoritative answer:
Name:   example.com
Address: 93.184.216.34
Name:   example.com
Address: 93.184.216.35
"""
        
        result = analyze_dns_output(output, 'example.com')
        assert 'Registros A (IPv4): 2 direcciones' in result
        assert '93.184.216.34' in result
        assert '93.184.216.35' in result
        assert 'No autoritativa' in result

    def test_analyze_dns_output_ipv6(self):
        """Test DNS analysis with IPv6"""
        output = """
example.com.    300 IN  AAAA    2606:2800:220:1:248:1893:25c8:1946
"""
        
        result = analyze_dns_output(output, 'example.com')
        assert 'IPv6' in result
        assert '2606:2800:220:1:248:1893:25c8:1946' in result
        assert 'Soporte para IPv6' in result

    def test_analyze_dns_output_authoritative(self):
        """Test DNS analysis with authoritative answer"""
        output = """
;; AUTHORITY SECTION:
example.com.    172800  IN  NS  a.iana-servers.net.
example.com.    172800  IN  NS  b.iana-servers.net.

;; ADDITIONAL SECTION:
a.iana-servers.net. 172800  IN  A   199.43.135.53
b.iana-servers.net. 172800  IN  A   199.43.133.53
"""
        
        result = analyze_dns_output(output, 'example.com')
        assert 'Autoritativa' in result

    def test_analyze_dns_output_multiple_ips(self):
        """Test DNS analysis with multiple IPs"""
        output = """
example.com.    300 IN  A   93.184.216.34
example.com.    300 IN  A   93.184.216.35
example.com.    300 IN  A   93.184.216.36
example.com.    300 IN  A   93.184.216.37
"""
        
        result = analyze_dns_output(output, 'example.com')
        assert 'Múltiples IPs' in result
        assert 'balanceo de carga' in result or 'geo-distribución' in result

    def test_analyze_dns_output_nslookup_format(self):
        """Test DNS analysis with nslookup format"""
        output = """
Nombre:   example.com
Addresses:  2606:2800:220:1:248:1893:25c8:1946
          93.184.216.34
"""
        
        result = analyze_dns_output(output, 'example.com')
        assert 'IPv4' in result
        assert 'IPv6' in result
        assert '93.184.216.34' in result
        assert '2606:2800:220:1:248:1893:25c8:1946' in result

    @patch('network_toolkit.analysis_tools.datetime')
    def test_analyze_whois_output_domain_age(self, mock_datetime):
        """Test WHOIS analysis with domain age calculation"""
        from datetime import datetime
        
        # Mock current date
        mock_now = datetime(2024, 1, 1)
        mock_datetime.now.return_value = mock_now
        mock_datetime.strptime.side_effect = lambda x, fmt: datetime.strptime(x, fmt)
        
        output = """
Creation Date: 2010-01-01
Registry Expiry Date: 2025-01-01
"""
        
        result = analyze_whois_output(output, 'example.com')
        assert '14 años' in result  # 2024 - 2010 = 14
        assert 'Dominio antiguo' in result

    def test_analyse_ping_output_no_metrics(self):
        """Test ping analysis with no detectable metrics"""
        output = "Some unrecognized ping output format"
        
        result = analyse_ping_output(output, 'example.com')
        # Should handle gracefully without crashing
        assert 'ANÁLISIS PING' in result
        assert 'example.com' in result

    def test_analyze_traceroute_output_empty(self):
        """Test traceroute analysis with empty output"""
        result = analyze_traceroute_output("", 'example.com')
        assert 'ANÁLISIS TRACEROUTE' in result
        assert 'Saltos totales: 0' in result

    def test_analyze_whois_output_empty(self):
        """Test WHOIS analysis with empty output"""
        result = analyze_whois_output("", 'example.com')
        assert 'ANÁLISIS WHOIS' in result
        assert 'Información del dominio' in result

    def test_analyze_dns_output_empty(self):
        """Test DNS analysis with empty output"""
        result = analyze_dns_output("", 'example.com')
        assert 'ANÁLISIS DNS' in result

    def test_analyse_ping_output_spanish_format(self):
        """Test ping analysis with Spanish format output"""
        output = """
Haciendo ping a google.com [142.251.42.78] con 32 bytes de datos:
Respuesta desde 142.251.42.78: bytes=32 tiempo=10ms TTL=118
Respuesta desde 142.251.42.78: bytes=32 tiempo=11ms TTL=118

Estadísticas de ping para 142.251.42.78:
    Paquetes: enviados = 4, recibidos = 4, perdidos = 0 (0% perdidos)
"""
        
        result = analyse_ping_output(output, 'google.com')
        assert 'google.com' in result
        assert '0%' in result
        assert 'TTL' in result

    def test_analyze_traceroute_output_complex(self):
        """Test traceroute analysis with complex output"""
        output = """
 1  192.168.1.1 (192.168.1.1)  1.234 ms  1.345 ms  1.456 ms
 2  10.0.0.1 (10.0.0.1)  2.345 ms  2.456 ms  2.567 ms
 3  100.64.0.1 (100.64.0.1)  5.678 ms  5.789 ms  5.890 ms
 4  203.0.113.1 (203.0.113.1)  15.678 ms  15.789 ms  15.890 ms
 5  198.51.100.1 (198.51.100.1)  25.678 ms  25.789 ms  25.890 ms
 6  142.251.42.78 (142.251.42.78)  35.678 ms  35.789 ms  35.890 ms
"""
        
        result = analyze_traceroute_output(output, 'google.com')
        assert 'Saltos totales: 6' in result
        assert '192.168.1.1' in result
        assert 'Privada' in result
        assert '203.0.113.1' in result