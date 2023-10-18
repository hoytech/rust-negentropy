#!/usr/bin/env python

from setuptools import setup

from pathlib import Path
this_directory = Path(__file__).parent
long_description = (this_directory / "README.md").read_text()

setup(
    name='negentropy',
    version='0.0.1',
    description="Negentropy set-reconciliation protocol.",
    long_description=long_description,
    long_description_content_type='text/markdown',
    include_package_data = True,
    zip_safe=False,
    packages=['negentropy'],
    package_dir={'negentropy': './src/negentropy'},
    url="https://github.com/yukibtc/rust-negentropy",
    author="Yuki Kishimoto <yukikishimoto@protonmail.com>",
    license="MIT",
     # This is required to ensure the library name includes the python version, abi, and platform tags
    # See issue #350 for more information
    has_ext_modules=lambda: True,
)
