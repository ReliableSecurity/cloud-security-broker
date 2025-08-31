"""
Setup configuration for Cloud Security Broker (CASB)
Enterprise-grade Data Loss Prevention and Multi-Factor Authentication
"""

from setuptools import setup, find_packages
import os

# Read README for long description
with open("README_DETAILED.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

# Read requirements
with open("requirements.txt", "r", encoding="utf-8") as fh:
    requirements = [line.strip() for line in fh if line.strip() and not line.startswith("#")]

# Read version from __init__.py
def get_version():
    init_file = os.path.join(os.path.dirname(__file__), "casb", "__init__.py")
    if os.path.exists(init_file):
        with open(init_file, "r", encoding="utf-8") as f:
            for line in f:
                if line.startswith("__version__"):
                    return line.split("=")[1].strip().strip("\"'")
    return "2.0.0"

setup(
    name="cloud-security-broker",
    version=get_version(),
    author="CASB Security Team",
    author_email="support@casb-security.com",
    description="Enterprise-grade Cloud Access Security Broker with DLP and MFA",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/yourusername/cloud-security-broker",
    project_urls={
        "Bug Tracker": "https://github.com/yourusername/cloud-security-broker/issues",
        "Documentation": "https://casb-security.readthedocs.io/",
        "Source Code": "https://github.com/yourusername/cloud-security-broker",
        "Homepage": "https://casb-security.com",
    },
    packages=find_packages(exclude=["tests*", "docs*", "examples*"]),
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: System Administrators",
        "Intended Audience :: Information Technology",
        "Topic :: Security",
        "Topic :: Security :: Cryptography",
        "Topic :: System :: Systems Administration :: Authentication/Directory",
        "Topic :: Software Development :: Libraries :: Python Modules",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
        "Operating System :: OS Independent",
        "Environment :: Web Environment",
        "Framework :: Flask",
        "Framework :: FastAPI",
    ],
    python_requires=">=3.8",
    install_requires=requirements,
    extras_require={
        "dev": [
            "pytest>=7.4.0",
            "pytest-cov>=4.1.0",
            "pytest-mock>=3.11.0",
            "pytest-asyncio>=0.21.1",
            "black>=23.7.0",
            "isort>=5.12.0",
            "flake8>=6.0.0",
            "mypy>=1.5.0",
            "pre-commit>=3.3.0",
            "bandit>=1.7.5",
            "safety>=2.3.5",
        ],
        "ml": [
            "tensorflow>=2.13.0",
            "torch>=2.0.0",
            "transformers>=4.30.0",
            "spacy>=3.6.0",
            "nltk>=3.8.1",
        ],
        "blockchain": [
            "web3>=6.8.0",
            "eth-account>=0.9.0",
            "py-solc-x>=1.12.0",
        ],
        "cloud": [
            "boto3>=1.28.0",
            "azure-identity>=1.13.0",
            "azure-storage-blob>=12.17.0",
            "google-cloud-storage>=2.10.0",
        ],
        "monitoring": [
            "prometheus-client>=0.17.0",
            "sentry-sdk>=1.28.0",
            "opentelemetry-api>=1.18.0",
            "opentelemetry-sdk>=1.18.0",
            "jaeger-client>=4.8.0",
        ],
        "analytics": [
            "plotly>=5.15.0",
            "dash>=2.11.0",
            "streamlit>=1.25.0",
            "jupyter>=1.0.0",
        ],
        "all": [
            "tensorflow>=2.13.0",
            "torch>=2.0.0",
            "transformers>=4.30.0",
            "web3>=6.8.0",
            "boto3>=1.28.0",
            "prometheus-client>=0.17.0",
            "plotly>=5.15.0",
        ],
    },
    entry_points={
        "console_scripts": [
            "casb=casb.cli:main",
            "casb-dlp=dlp.cli:main",
            "casb-mfa=auth.cli:main",
            "casb-server=api.main:main",
            "casb-web=web.app:main",
        ],
    },
    include_package_data=True,
    package_data={
        "casb": [
            "config/*.json",
            "templates/*.html",
            "templates/*.txt",
            "static/css/*.css",
            "static/js/*.js",
        ],
        "dlp": [
            "models/*.json",
            "policies/*.json",
            "compliance/*.json",
        ],
        "auth": [
            "templates/*.html",
            "templates/*.txt",
        ],
    },
    data_files=[
        ("config", ["config/settings.json"]),
        ("docs", ["README.md", "README_DETAILED.md"]),
    ],
    zip_safe=False,
    keywords=[\n        "security", "dlp", "mfa", "casb", "cloud-security", \n        "data-loss-prevention", "multi-factor-authentication",\n        "access-control", "compliance", "audit", "encryption",\n        "biometric", "quantum-resistant", "blockchain", "zero-trust"\n    ],\n    platforms=["any"],\n    license="MIT",\n    \n    # Additional metadata for PyPI\n    maintainer="CASB Security Team",\n    maintainer_email="maintainers@casb-security.com",\n    \n    # Security and compliance information\n    download_url="https://github.com/yourusername/cloud-security-broker/archive/v2.0.0.tar.gz",\n    \n    # Documentation URLs\n    documentation_url="https://casb-security.readthedocs.io/",\n    \n    # Support information\n    support_url="https://github.com/yourusername/cloud-security-broker/issues",\n)", "search_start_line_number": 1}]
