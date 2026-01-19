from setuptools import setup, find_packages

setup(
    name="vuln",                # name of your tool
    version="0.1.0",              # version number
    packages=find_packages(),     # include all code
    install_requires=["requests"
],          # add dependencies here
    entry_points={
        "console_scripts": [
            "vuln=vuln.vuln:main",  # run with 'mytool' command
        ],
    },
    author="Avhishek",
    description="A simple vulnerability scanner too",
    lincense="MIT"
)


