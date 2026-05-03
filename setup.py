"""Legacy setup.py for compatibility with older tooling.

The canonical package metadata lives in pyproject.toml. This shim exists so
that environments which still invoke `python setup.py install` continue to work.
"""

from setuptools import setup

if __name__ == "__main__":
    setup()
