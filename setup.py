import pathlib
from setuptools import setup, find_packages

HERE = pathlib.Path(__file__).parent
README = (HERE / "README.md").read_text()

with open(f"{HERE}/requirements.txt") as file:
    requirements = file.read().splitlines()

setup(
    name="databases-casbin-adapter",
    version="0.0.1",
    description="This is an Adapter for PyCasbin that implemented using Databases connection to achieve async process",
    long_description=README,
    long_description_content_type="text/markdown",
    url="https://github.com/sampingantech/databases-casbin-adapter",
    author="Isa Setiawan Abdurrazaq",
    author_email="isasetiawan@protonmail.com",
    license="MIT",
    classifiers=[
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
    ],
    packages=find_packages(),
    include_package_data=True,
    install_requires=requirements,
)
