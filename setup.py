#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Setup configuration for Network Toolkit
"""

import sys
import os

# Añadir esta verificación para evitar warnings
try:
    from setuptools import setup, find_packages
except ImportError:
    print("setuptools is required to install this package")
    print("Install it with: pip install setuptools")
    sys.exit(1)

# Leer el contenido del README para la descripción larga
def read_readme():
    try:
        with open('README.md', 'r', encoding='utf-8') as f:
            return f.read()
    except FileNotFoundError:
        return "Network Toolkit - A comprehensive network analysis and reconnaissance tool"

setup(
    name="network-toolkit",
    version="1.0.0",
    description="A comprehensive network analysis and reconnaissance tool",
    long_description=read_readme(),
    long_description_content_type="text/markdown",
    author="Matias Lab Progr",
    author_email="tu-email@example.com",
    url="https://github.com/matias-lab-progr/network_toolkit",
    packages=find_packages(),
    package_data={
        'network_toolkit': ['data/*.txt', 'data/*.json'],
    },
    install_requires=[
        "requests>=2.25.0",
        "beautifulsoup4>=4.9.0",
        "python-whois>=0.7.3",
        "dnspython>=2.1.0",
    ],
    entry_points={
        'console_scripts': [
            'network-toolkit=network_toolkit.main:main',
            'ntk=network_toolkit.main:main',  # Alias corto
        ],
    },
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Developers",
        "Intended Audience :: System Administrators",
        "Intended Audience :: Information Technology",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Operating System :: OS Independent",
        "Topic :: Security",
        "Topic :: Network",
        "Topic :: System :: Networking Monitoring",
    ],
    keywords="network, security, reconnaissance, dns, whois, ssl, scanning",
    python_requires=">=3.8",
    project_urls={
        "Documentation": "https://github.com/matias-lab-progr/network_toolkit/wiki",
        "Source": "https://github.com/matias-lab-progr/network_toolkit",
        "Tracker": "https://github.com/matias-lab-progr/network_toolkit/issues",
    },
    license="MIT",
    platforms=["any"],
)