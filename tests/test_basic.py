import pytest
import sys
import os

def test_module_imports():
    """Test that all modules can be imported successfully"""
    modules_to_test = [
        'network_toolkit.analysis_tools',
        'network_toolkit.dns_tools', 
        'network_toolkit.main',
        'network_toolkit.network_tools',
        'network_toolkit.recon_tools',
        'network_toolkit.ssl_tools',
        'network_toolkit.threat_intel',
        'network_toolkit.utils',
        'network_toolkit.whois_tools'
    ]
    
    for module_name in modules_to_test:
        try:
            __import__(module_name)
            print(f"✓ {module_name} imported successfully")
        except ImportError as e:
            pytest.fail(f"Failed to import {module_name}: {e}")

def test_network_tools_functions():
    """Test that network_tools functions can be imported"""
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
    assert True

def test_dns_tools_functions():
    """Test that dns_tools functions can be imported"""
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
    assert True

def test_main_functions():
    """Test that main functions can be imported"""
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
    assert True

def test_utils_functions():
    """Test that utils functions can be imported"""
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
    assert True

def test_analysis_tools_functions():
    """Test that analysis_tools functions can be imported"""
    from network_toolkit.analysis_tools import (
        analyse_ping_output,
        analyze_traceroute_output,
        analyze_whois_output,
        analyze_dns_output
    )
    assert True

def test_ssl_tools_functions():
    """Test that ssl_tools functions can be imported"""
    from network_toolkit.ssl_tools import (
        get_ssl_certificate,
        analyze_ssl_certificate,
        check_ssl_security,
        get_ssl_grade,
        display_ssl_analysis
    )
    assert True

def test_recon_tools_functions():
    """Test that recon_tools functions can be imported"""
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
    assert True

def test_threat_intel_functions():
    """Test that threat_intel functions can be imported"""
    from network_toolkit.threat_intel import (
        get_public_ip_report,
        check_abuseipdb_public,
        check_virustotal_public,
        get_ipinfo_public,
        generate_recommendations,
        display_threat_intel_results
    )
    assert True

def test_whois_tools_functions():
    """Test that whois_tools functions can be imported"""
    from network_toolkit.whois_tools import (
        get_whois_info,
        get_whois_info_enhanced
    )
    assert True

if __name__ == "__main__":
    test_module_imports()
    test_network_tools_functions()
    test_dns_tools_functions()
    test_main_functions()
    test_utils_functions()
    test_analysis_tools_functions()
    test_ssl_tools_functions()
    test_recon_tools_functions()
    test_threat_intel_functions()
    test_whois_tools_functions()
    print("All basic tests passed!")