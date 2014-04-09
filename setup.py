#!/usr/bin/env python
from setuptools import setup

setup(name='python-figo',
      version='1.1.1',
      description='Library to easily use the API of http://www.figo.me',
      author='Stefan Richter',
      author_email='stefan.richter@figo.me',
      url='http://www.figo.me',
      packages=['figo'],
      license='BSD License',
      classifiers=[
          'License :: OSI Approved :: BSD License',
          'Operating System :: OS Independent',
          'Programming Language :: Python',
          'Programming Language :: Python :: 2',
          'Programming Language :: Python :: 2.4',
          'Programming Language :: Python :: 2.5',
          'Programming Language :: Python :: 2.6',
          'Programming Language :: Python :: 2.7',
          'Programming Language :: Python :: 3',
          'Programming Language :: Python :: 3.1',
          'Programming Language :: Python :: 3.2',
          'Development Status :: 4 - Beta',
          'Intended Audience :: Developers',
          'Topic :: Office/Business :: Financial',
          'Topic :: Internet'
      ],
      requires=[
          'python-dateutil'
      ],
      test_suite="tests",
      )
