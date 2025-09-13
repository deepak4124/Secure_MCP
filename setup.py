"""
Setup script for MCP Security Framework

A comprehensive security framework for Model Context Protocol (MCP) in Multi-Agent Systems (MAS).
"""

from setuptools import setup, find_packages
import os

# Read README file
def read_readme():
    with open("README.md", "r", encoding="utf-8") as fh:
        return fh.read()

# Read requirements
def read_requirements():
    with open("requirements.txt", "r", encoding="utf-8") as fh:
        return [line.strip() for line in fh if line.strip() and not line.startswith("#")]

setup(
    name="mcp-security-framework",
    version="0.1.0",
    author="Secure MCP Research Team",
    author_email="contact@mcp-security.org",
    description="A comprehensive security framework for Model Context Protocol (MCP) in Multi-Agent Systems (MAS)",
    long_description=read_readme(),
    long_description_content_type="text/markdown",
    url="https://github.com/mcp-security/framework",
    project_urls={
        "Bug Reports": "https://github.com/mcp-security/framework/issues",
        "Source": "https://github.com/mcp-security/framework",
        "Documentation": "https://mcp-security.readthedocs.io/",
    },
    packages=find_packages(),
    classifiers=[
        "Development Status :: 3 - Alpha",
        "Intended Audience :: Developers",
        "Intended Audience :: Science/Research",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Topic :: Scientific/Engineering :: Artificial Intelligence",
        "Topic :: Security",
        "Topic :: Software Development :: Libraries :: Python Modules",
    ],
    python_requires=">=3.8",
    install_requires=read_requirements(),
    extras_require={
        "dev": [
            "pytest>=6.0",
            "pytest-asyncio>=0.18.0",
            "pytest-cov>=2.10.0",
            "black>=21.0.0",
            "flake8>=3.8.0",
            "mypy>=0.800",
            "pre-commit>=2.10.0",
        ],
        "docs": [
            "sphinx>=4.0.0",
            "sphinx-rtd-theme>=0.5.0",
            "myst-parser>=0.15.0",
        ],
        "langgraph": [
            "langgraph>=0.0.20",
            "langchain>=0.1.0",
            "langchain-core>=0.1.0",
        ],
        "autogen": [
            "pyautogen>=0.2.0",
        ],
        "crewai": [
            "crewai>=0.1.0",
        ],
    },
    entry_points={
        "console_scripts": [
            "mcp-security=mcp_security_framework.cli:main",
        ],
    },
    include_package_data=True,
    package_data={
        "mcp_security_framework": [
            "config/*.yaml",
            "policies/*.yaml",
            "examples/*.py",
            "tests/*.py",
        ],
    },
    keywords=[
        "mcp", "model-context-protocol", "multi-agent-systems", "security",
        "trust", "identity", "authentication", "authorization", "mas",
        "langgraph", "autogen", "crewai", "semantic-kernel"
    ],
    zip_safe=False,
)
