#!/usr/bin/env python

import setuptools

with open("README.rst", "r", encoding="utf-8") as fh:
    long_description = fh.read()

setuptools.setup(name='python_doip',
      version='0.0.7',
      description='Python DoIP Client',
      long_description=long_description,
      author='Jacob Schaer',
      url='https://github.com/jacobschaer/python_doip',
      packages=setuptools.find_packages(),
      keywords = ['uds', '14229', 'iso-14229', 'diagnostic', 'automotive', '13400', 'iso-13400', 'doip'], 
      classifiers=[
          "Programming Language :: Python :: 3",
          "License :: OSI Approved :: MIT License",
          "Operating System :: OS Independent",
          "Topic :: Scientific/Engineering :: Interface Engine/Protocol Translator",
      ],
      python_requires='>=3.6'
     )