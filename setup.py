"""Packaging configuration for ext_http_server."""

import re
from pathlib import Path

from setuptools import setup

HERE = Path(__file__).parent

MODULE_NAME = "ext_http_server"
README = (HERE / "README.md").read_text(encoding="utf-8")
VERSION = re.search(
    r'__version__ = "([^"]+)"',
    (HERE / f"{MODULE_NAME}.py").read_text(encoding="utf-8"),
).group(1)

setup(
    author="Bryce Boe",
    author_email="bbzbryce@gmail.com",
    classifiers=[
        "Intended Audience :: Developers",
        "License :: OSI Approved :: BSD License",
        "Operating System :: OS Independent",
        "Programming Language :: Python",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
        "Programming Language :: Python :: 3.13",
        "Programming Language :: Python :: 3.14",
    ],
    description=(
        "An extended version of python's SimpleHTTPServer that supports https, "
        "authentication, rate limiting, and download resuming."
    ),
    entry_points={"console_scripts": [f"{MODULE_NAME} = {MODULE_NAME}:main"]},
    install_requires=[],
    keywords=["http resume", "http rate limit", "http authentication"],
    license="Simplified BSD License",
    long_description=README,
    name=MODULE_NAME,
    py_modules=[MODULE_NAME],
    python_requires=">=3.10",
    url="https://github.com/bboe/extended_http_server",
    version=VERSION,
)
