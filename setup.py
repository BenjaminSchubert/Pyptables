#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Setup declaration to install Pyptables
"""

params = dict(
    name='pyptables',
    version='0.1',
    packages=['pyptables'],
    url='https://github.com/BenjaminSchubert/Pyptables',
    license='MIT',
    author='Benjamin Schubert',
    author_email='ben.c.schubert@gmail.com',
    description='A python wrapper around Iptables to simplify handling of not too complex rules',
    include_package_data=True,
    classifiers=[
        "Topic :: System :: Networking :: Firewalls",
        "Development Status :: 3 - Alpha",
        "Environment :: Console",
        "License :: OSI Approved :: MIT License",
        "Natural Language :: English",
        "Operating System :: Unix",
        "Programming Language :: Python :: 3.4",
        "Programming Language :: Python :: 3.5"
    ]
)

with open("README.md") as _desc:
    params["long_description"] = _desc.read()

try:
    from setuptools import setup
except ImportError:
    from distutils.core import setup

else:
    params['entry_points'] = {
        'console_scripts': [
            "pyptables = pyptables:run"
        ]
    }

setup(**params)
