#!/usr/bin/env python3

try:
    from importlib.metadata import version, PackageNotFoundError
except ModuleNotFoundError:
    from importlib_metadata import version, PackageNotFoundError

__version__ = ''
try:
    __version__ = version('sysflow-tools')
except PackageNotFoundError:
    pass
