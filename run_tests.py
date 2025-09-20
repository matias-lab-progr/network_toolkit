#!/usr/bin/env python3
"""
Test runner script for Network Toolkit - Complete test suite
"""

import subprocess
import sys

def run_tests():
    """Run all tests"""
    try:
        result = subprocess.run([
            'python', '-m', 'pytest',
            'tests/',
            '-v',
            '--cov=network_toolkit',
            '--cov-report=html',
            '--cov-report=term'
        ], check=True)
        
        return result.returncode == 0
        
    except subprocess.CalledProcessError as e:
        print(f"Tests failed with exit code {e.returncode}")
        return False
    except FileNotFoundError:
        print("pytest not found. Install it with: pip install pytest pytest-cov")
        return False

if __name__ == '__main__':
    success = run_tests()
    sys.exit(0 if success else 1)