from setuptools import setup, find_packages

setup(
    name="mytool",                # name of your tool
    version="0.1.0",              # version number
    packages=find_packages(),     # include all code
    install_requires=[],          # add dependencies here
    entry_points={
        "console_scripts": [
            "mytool=mytool.main:main",  # run with 'mytool' command
        ],
    },
)
