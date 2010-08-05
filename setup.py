"""Installer for foursquare"""

try:
        from setuptools import setup, find_packages
except ImportError:
        from ez_setup import use_setuptools
        use_setuptools()
        from setuptools import setup, find_packages
setup(
    name='Foursquare',
    description='Python module to interface with the foursquare API',
    version='0.1',
    author='John Wiseman',
    author_email='jjwiseman@gmail.com',
    url='http://github.com/wiseman/foursquare-python',
    packages=find_packages(exclude=('ez_setup', 'tests',)),
    license=open('LICENSE.txt').read(),
    setup_requires=(
        'oauth',
    )
)
