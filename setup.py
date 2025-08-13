#!/usr/bin/env python

import setuptools

with open("README.rst", "r", encoding="utf-8") as fh:
    long_description = fh.read()

setuptools.setup(
    name="doipclient",
    version="1.1.7",
    description="A Diagnostic over IP (DoIP) client implementing ISO-13400-2.",
    long_description=long_description,
    long_description_content_type="text/x-rst",
    author="Jacob Schaer",
    url="https://github.com/jacobschaer/python-doipclient",
    packages=["doipclient"],
    package_data={"doipclient": ["py.typed"]},
    keywords=[
        "uds",
        "14229",
        "iso-14229",
        "diagnostic",
        "automotive",
        "13400",
        "iso-13400",
        "doip",
    ],
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
        "Topic :: Scientific/Engineering :: Interface Engine/Protocol Translator",
    ],
    python_requires=">=3.6",
)
