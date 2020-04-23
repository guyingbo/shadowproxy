import os.path
import re

from setuptools import find_namespace_packages, setup

VERSION_RE = re.compile(r"""__version__ = ['"]([0-9.]+)['"]""")
BASE_PATH = os.path.dirname(__file__)


with open(os.path.join(BASE_PATH, "shadowproxy", "__init__.py")) as f:
    try:
        version = VERSION_RE.search(f.read()).group(1)
    except IndexError:
        raise RuntimeError("Unable to determine version.")


with open(os.path.join(BASE_PATH, "README.md")) as readme:
    long_description = readme.read()


setup(
    name="shadowproxy",
    description="A proxy server that implements "
    "Socks5/Shadowsocks/Redirect/HTTP (tcp) "
    "and Shadowsocks/TProxy/Tunnel (udp) protocols.",
    long_description=long_description,
    long_description_content_type="text/markdown",
    license="MIT",
    version=version,
    author="Yingbo Gu",
    author_email="tensiongyb@gmail.com",
    maintainer="Yingbo Gu",
    maintainer_email="tensiongyb@gmail.com",
    url="https://github.com/guyingbo/shadowproxy",
    packages=find_namespace_packages(include=["shadowproxy*"]),
    install_requires=[
        "pycryptodome>=3.4.3",
        "curio==0.9",
        "pylru>=1.0.9",
        # "microstats>=0.1.0",
        "iofree>=0.2.4",
        "httptools",
        "hkdf",
    ],
    entry_points={"console_scripts": ["shadowproxy = shadowproxy.__main__:main"]},
    classifiers=[
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3.6",
        "Programming Language :: Python :: 3.7",
        "Programming Language :: Python :: 3.8",
    ],
    setup_requires=["pytest-runner"],
    tests_require=["pytest", "coverage", "pytest-cov"],
)
