# network_toolkit/__init__.py
"""
Network Toolkit - Un conjunto de herramientas para diagnóstico de red y análisis DNS.
"""

__version__ = "1.0.0"
__author__ = "Matías"
__description__ = "Herramienta profesional para análisis de red, DNS y diagnóstico de conectividad"

from .history_tools import NetworkHistoryManager, network_history
from .network_tools import ping_target, traceroute_target
from .analysis_tools import analyse_ping_output, analyze_traceroute_output
from .whois_tools import get_whois_info
from .network_tools import geolocate_ip, display_geolocation


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
    get_whois_info
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

from .recon_tools import (
    dns_subdomain_enumeration,
    passive_subdomain_enumeration,
    display_subdomain_results,
    display_passive_subdomain_results,
    load_subdomain_wordlist,
    certificate_transparency_search,
    display_ct_results,
    comprehensive_subdomain_enumeration,
    display_comprehensive_results,
    export_subdomains_to_file
)

from .threat_intel import (
    get_public_ip_report,
    display_threat_intel_results,
    check_abuseipdb_public,
    check_virustotal_public,
    get_ipinfo_public
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
    'is_dependency_available',
    'NetworkHistoryManager',
    'network_history',
    'ping_target',
    'traceroute_target',
    'analyse_ping_output',
    'analyze_traceroute_output',
    'geolocate_ip',
    'display_geolocation'
]



