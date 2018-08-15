#!/usr/bin/env python

from setuptools import setup

from unlocker import __version__


setup(name="unlocker",
    packages=[
        "unlocker",
        "unlocker.util",
    ],
    entry_points = {
        "console_scripts": [
            "unlocker = unlocker.bootstrap:main"
        ]
    },
    install_requires=[
        "ipaddress==1.0.17",
        "click==6.7"
    ],
    test_suite="tests",
    version=__version__,
    description="CLI credentials manager",
    author="Alexandru Catrina",
    author_email="alex@codeissues.net",
    license="MIT",
    url="https://github.com/lexndru/unlocker",
    download_url="https://github.com/lexndru/unlocker/archive/v{}.tar.gz".format(__version__),
    keywords=["credentials manager", "keychain", "remote connection"],
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Developers",
        "Intended Audience :: System Administrators",
        "Intended Audience :: Education",
        "Topic :: System :: Networking",
        "Topic :: System :: Shells",
        "Topic :: System :: Systems Administration",
        "Topic :: Terminals",
        "Topic :: Utilities",
        "Topic :: Internet",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 2.7",
        "Programming Language :: Unix Shell",
        "Operating System :: POSIX",
    ],
)
