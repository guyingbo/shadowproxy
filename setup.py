try:
    from setuptools import setup
except ImportError:
    from distutils.core import setup
import os.path
import re
VERSION_RE = re.compile(r'''__version__ = ['"]([0-9.]+)['"]''')
BASE_PATH = os.path.dirname(__file__)


with open(os.path.join(BASE_PATH, 'shadowproxy.py')) as f:
    try:
        version = VERSION_RE.search(f.read()).group(1)
    except IndexError:
        raise RuntimeError('Unable to determine version.')


with open(os.path.join(BASE_PATH, 'README.md')) as readme:
    long_description = readme.read()


setup(
    name='shadowproxy',
    description='A proxy server that implements '
                'Socks5/Shadowsocks/Redirect/HTTP (tcp) '
                'and Shadowsocks/TProxy/Tunnel (udp) protocols.',
    long_description=long_description,
    long_description_content_type='text/markdown',
    license='MIT',
    version=version,
    author='Yingbo Gu',
    author_email='tensiongyb@gmail.com',
    maintainer='Yingbo Gu',
    maintainer_email='tensiongyb@gmail.com',
    url='https://github.com/guyingbo/shadowproxy',
    py_modules=['shadowproxy'],
    install_requires=[
        'pycryptodome>=3.4.3',
        'curio>=0.8',
        'pylru>=1.0.9',
        'httptools>=0.0.9',
        'microstats>=0.1.0',
    ],
    entry_points={
        'console_scripts': [
            'shadowproxy = shadowproxy:main',
        ],
    },
    classifiers=[
        'Programming Language :: Python :: 3.6',
    ],
    setup_requires=['pytest-runner'],
    tests_require=['pytest'],
)
