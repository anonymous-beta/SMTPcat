#!/usr/bin/env python3
from setuptools import setup, find_packages

setup(
    name="smtpcat",
    version="2.0.0",
    author="Anonymous-beta",
    description="Advanced SMTP Security Assessment Tool",
    long_description=open("README.md").read(),
    long_description_content_type="text/markdown",
    url="https://github.com/Anonymous-beta/SMTPcat",
    packages=find_packages(),
    py_modules=["smtpcat"],
    entry_points={
        "console_scripts": [
            "smtpcat=smtpcat:main_cli",
        ],
    },
    install_requires=[
        "dnspython>=2.4.0",
        "requests>=2.28.0",
        "PySocks>=1.7.1",
    ],
    extras_require={
        "ml": ["numpy>=1.24.0", "scikit-learn>=1.2.0"],
        "plot": ["matplotlib>=3.6.0"],
        "full": ["numpy>=1.24.0", "scikit-learn>=1.2.0", "matplotlib>=3.6.0"],
    },
    classifiers=[
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "License :: Other/Proprietary License",
        "Operating System :: OS Independent",
        "Intended Audience :: Education",
        "Intended Audience :: Developers",
        "Intended Audience :: Information Technology",
        "Topic :: Security",
        "Topic :: Communications :: Email",
    ],
    python_requires=">=3.8",
)
