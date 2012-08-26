import re
from setuptools import setup

version = re.search("__version__ = '([^']+)'",
                    open('ext_http_server.py').read()).group(1)

setup(name='ext_http_server',
      version=version,
      author='Bryce Boe',
      author_email='bbzbryce@gmail.com',
      url = 'https://github.com/bboe/extended_http_server',
      description = ('An extended version of python\'s SimpleHTTPServer that '
                     'supports https, authentication, rate limiting, and '
                     'download resuming.'),
      install_requires=[],
      keywords=['http resume', 'http rate limit', 'http authentication'],
      py_modules=['ext_http_server'],
      entry_points = {'console_scripts':
                          ['ext_http_server = ext_http_server:main']}
      )
