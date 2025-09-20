import pytest
from unittest.mock import Mock, patch
import sys
import os

# Agregar el directorio root al path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

@pytest.fixture
def mock_colorama():
    """Fixture para mock de colorama"""
    with patch('network_toolkit.utils.colorama') as mock:
        mock.Fore = type('Fore', (), {'RED': '\033[91m', 'GREEN': '\033[92m', 'YELLOW': '\033[93m', 'BLUE': '\033[94m', 'CYAN': '\033[96m'})
        mock.Style = type('Style', (), {'RESET_ALL': '\033[0m'})
        yield mock

