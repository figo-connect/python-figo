from pkg_resources import DistributionNotFound
from pkg_resources import get_distribution
from setuptools_scm import get_version

try:
    __version__ = get_distribution('python_figo').version
except DistributionNotFound:
    __version__ = get_version()
