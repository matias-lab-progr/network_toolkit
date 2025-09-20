import pytest
import sys
import os
from unittest.mock import MagicMock, patch

# Add the project root to Python path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

# Global fixtures and configuration

@pytest.fixture
def mock_socket():
    """Mock socket for network tests"""
    with patch('socket.socket') as mock_socket:
        mock_sock_instance = MagicMock()
        mock_socket.return_value = mock_sock_instance
        yield mock_sock_instance

@pytest.fixture
def mock_requests():
    """Mock requests for HTTP tests"""
    with patch('requests.get') as mock_get:
        yield mock_get

@pytest.fixture
def mock_dns_resolver():
    """Mock DNS resolver"""
    with patch('dns.resolver.Resolver') as mock_resolver:
        mock_instance = MagicMock()
        mock_resolver.return_value = mock_instance
        yield mock_instance

@pytest.fixture
def sample_network_data():
    """Sample network data for testing"""
    return {
        'ip': '8.8.8.8',
        'domain': 'example.com',
        'ports': [80, 443, 22, 53],
        'open_ports': [80, 443],
        'hostname': 'google-public-dns-a.google.com'
    }