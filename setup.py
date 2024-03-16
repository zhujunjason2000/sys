# Jason
# 2024/3/16 22:12
# jasonchujun@sina.com
# setup.py

from setuptools import setup, find_packages

setup(
    name='sys_info',
    version='0.1.0',
    author='zhujun',
    author_email='zhujunjason2000@gmail.com',
    description='get local sys info',
    long_description=open('README.md').read(),
    long_description_content_type='text/markdown',
    url='https://github.com/zhujunjason2000/sys',
    packages=find_packages(),
    install_requires=[
        # List any dependencies here
        "json", "os", "platform", "re", "socket", "subprocess", "tzlocal "
    ],
    classifiers=[
        # classifiers list: https://pypi.org/pypi?%3Aaction=list_classifiers
    ],
    python_requires='>=3.6',
)
