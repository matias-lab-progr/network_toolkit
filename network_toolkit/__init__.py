# network_toolkit/__init__.py
"""
Network Toolkit - Un conjunto de herramientas para diagnóstico de red y análisis DNS.
"""

__version__ = "1.0.0"
__author__ = "Matías"
__description__ = "Herramienta profesional para análisis de red, DNS y diagnóstico de conectividad"

from .dns_tools import (
    dns_lookup,
    comprehensive_dns_scan,
    batch_dns_lookup,
    reverse_dns_lookup,
    trace_dns_resolution
)

from .network_tools import (
    ping_target,
    traceroute_target,
    geolocate_ip,
    display_geolocation,
    get_detailed_asn_info,
    display_detailed_asn_info,
    scan_common_ports,
    display_port_scan_results,
    extended_reverse_dns,
    display_extended_dns_info
)

from .whois_tools import (
    get_whois_info,
    get_whois_info_enhanced
)

from .analysis_tools import (
    analyse_ping_output,
    analyze_traceroute_output,
    analyze_whois_output,
    analyze_dns_output
)

from .utils import (
    init_colorama,
    is_valid_ip,
    is_valid_domain,
    is_valid_target,
    check_optional_dependencies,
    is_dependency_available
)

from .ssl_tools import (
    get_ssl_certificate,
    analyze_ssl_certificate,
    check_ssl_security,
    display_ssl_analysis
)

# Lista de lo que se exporta al hacer 'from network_toolkit import *'
__all__ = [
    'dns_lookup',
    'comprehensive_dns_scan',
    'batch_dns_lookup',
    'reverse_dns_lookup',
    'trace_dns_resolution',
    'run_command',
    'run_command_realtime',
    'ping_target',
    'traceroute_target',
    'get_whois_info',
    'get_whois_info_enhanced',
    'analyse_ping_output',
    'analyze_traceroute_output',
    'analyze_whois_output',
    'analyze_dns_output',
    'init_colorama',
    'is_valid_ip',
    'is_valid_domain',
    'is_valid_target',
    'check_optional_dependencies',
    'is_dependency_available'
]



