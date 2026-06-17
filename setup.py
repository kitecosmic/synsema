from setuptools import setup, find_packages

setup(
    name="syntecnia",
    version="0.1.0",
    description="A programming language designed for AI agents",
    packages=find_packages(),
    python_requires=">=3.10",
    entry_points={
        "console_scripts": [
            "syntecnia=syntecnia.cli:main",
        ],
    },
)
