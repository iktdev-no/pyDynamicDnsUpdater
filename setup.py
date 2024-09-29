import os

from setuptools import setup
from DynamicDnsUpdater import version

def readme():
    with open('README.md', encoding='utf-8') as f:
        return f.read()

setup(
    name="pyDynamicDnsUpdater",
    long_description_content_type='text/markdown',
    long_description=readme(),
    packages=["DynamicDnsUpdater"],
    install_requires=[
        "netifaces>=0.11.0",
        "netaddr>=0.8.0",
        "dnspython>=2.4.0",
        "domeneshop>=0.4.3",
        "tldextract>=5.1.2"
    ],
    version=version.__version__,
    description="""
    A Python library to modify and alter the dns records in according to configuration passed
    """,
    python_requires=">=3.9.0",
    author="Brage Skjønborg",
    author_email="bskjon@outlook.com",
    url="https://github.com/iktdev-no/pyDynamicDnsUpdater",
    classifiers=[
        "Intended Audience :: Developers",
        "Operating System :: POSIX :: Linux",
        "Programming Language :: Python",
        "Programming Language :: Python :: 3",
        "Topic :: System :: Networking",
        "Topic :: Software Development :: Libraries :: Python Modules",
    ],
)
