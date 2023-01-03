# type: ignore
"""dns_exporter setup.py for setuptools.

Source code available at https://github.com/tykling/dns_exporter/
Can be installed from PyPi https://pypi.org/project/dns_exporter/
Read more at https://dns_exporter.readthedocs.io/en/latest/
"""
import setuptools

with open("README.md", "r") as fh:
    long_description = fh.read()

setuptools.setup(
    name="dns_exporter",
    version="0.1.0-dev",
    author="Thomas Steen Rasmussen",
    author_email="thomas@gibfest.dk",
    description="dns_exporter is a Blackbox style Prometheus exporter with a focus on DNS monitoring.",
    license="BSD License",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/tykling/dns_exporter",
    packages=["dns_exporter"],
    entry_points={"console_scripts": ["dns_exporter = dns_exporter.dns_exporter:main"]},
    classifiers=[
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "License :: OSI Approved :: BSD License",
        "Operating System :: OS Independent",
    ],
    python_requires=">=3.9",
    install_requires=["dnspython", "prometheus_client", "PyYAML"],
    include_package_data=True,
)
