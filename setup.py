from setuptools import setup, find_packages

setup(
    name="vuln",
    version="0.1.0",
    packages=find_packages(),
    install_requires=[
        "requests",
        "colorama",# add other libraries if needed
    ],
    entry_points={
        "console_scripts": [
            "vuln=vuln.vuln:main",  # lets users run 'vuln' from terminal
        ],
    },
    author="Avhishek",
    description="A simple vulnerability scanner created with AI and a touch of me 😋",
    license="MIT",
)
