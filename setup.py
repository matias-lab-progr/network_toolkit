from setuptools import setup, find_packages
import pathlib

# Leer el contenido del README.md para la descripción larga
here = pathlib.Path(__file__).parent.resolve()
long_description = (here / "README.md").read_text(encoding="utf-8")

setup(
    name="network-toolkit",
    version="0.1.0",
    description="A comprehensive network analysis and reconnaissance toolkit",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/matias-lab-progr/network_toolkit",
    author="Matias Lab",
    author_email="tu-email@ejemplo.com",
    classifiers=[
        "Development Status :: 3 - Alpha",
        "Intended Audience :: Information Technology",
        "Intended Audience :: System Administrators",
        "Topic :: Security",
        "Topic :: System :: Networking",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
    ],
    keywords="network, security, reconnaissance, dns, whois, ssl",
    package_dir={"": "."},
    packages=find_packages(where="."),
    python_requires=">=3.8, <4",
    install_requires=[
        "requests>=2.25.0",
        "dnspython>=2.1.0",
        "python-whois>=0.7.3",
        "beautifulsoup4>=4.9.0",
        "lxml>=4.6.0",
        "cryptography>=3.4.0",
        "pyOpenSSL>=20.0.0",
        "urllib3>=1.26.0",
        "colorama>=0.4.0",
        "tabulate>=0.8.0"
    ],
    extras_require={
        "dev": [
            "pytest>=6.0.0",
            "pytest-cov>=2.0.0",
            "black>=21.0.0",
            "flake8>=3.9.0"
        ],
        "full": [
            "scapy>=2.4.0",
            "paramiko>=2.7.0",
            "netaddr>=0.8.0"
        ]
    },
    entry_points={
        "console_scripts": [
            "ntk=network_toolkit.main:main",
            "network-toolkit=network_toolkit.main:main",
        ],
    },
    include_package_data=True,
    package_data={
        "network_toolkit": [
            "wordlists/*.txt",
            "config/*.json"
        ]
    },
    project_urls={
        "Bug Reports": "https://github.com/matias-lab-progr/network_toolkit/issues",
        "Source": "https://github.com/matias-lab-progr/network_toolkit",
    },
)