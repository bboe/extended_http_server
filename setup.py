import os
import re
from setuptools import setup

MODULE_NAME = 'ext_http_server'

README = open(os.path.join(os.path.dirname(__file__), 'README.md')).read()
VERSION = re.search("__version__ = '([^']+)'",
                    open('{0}.py'.format(MODULE_NAME)).read()).group(1)

setup(name=MODULE_NAME,
      author='Bryce Boe',
      author_email='bbzbryce@gmail.com',
      classifiers=['Intended Audience :: Developers',
                   'License :: OSI Approved :: BSD License',
                   'Operating System :: OS Independent',
                   'Programming Language :: Python',
                   #'Programming Language :: Python :: 3'
                   ],
      description=('An extended version of python\'s SimpleHTTPServer that '
                     'supports https, authentication, rate limiting, and '
                     'download resuming.'),
      entry_points={'console_scripts': ['{0} = {0}:main'.format(MODULE_NAME)]},
      install_requires=[],
      keywords=['http resume', 'http rate limit', 'http authentication'],
      license='Simplified BSD License',
      long_description=README,
      py_modules=[MODULE_NAME],
      url = 'https://github.com/bboe/extended_http_server',
      version=VERSION)
