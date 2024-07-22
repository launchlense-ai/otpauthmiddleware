# setup.py
from setuptools import setup, find_packages

setup(
    name='otpauthmiddleware',
    version='1.0.1',
    packages=find_packages(),
    install_requires=[
        'requests'
    ],
    readme="README.md",
    author='Launchlense',
    author_email='shashank@scaleknot.com',
    description='AuthMiddlewareService for handling authentication',
    url='https://github.com/launchlense-ai/otpauthmiddleware',
    classifiers=[
        'Programming Language :: Python :: 3',
        'License :: OSI Approved :: MIT License',
        'Operating System :: OS Independent',
    ],
    python_requires='>=3.6',
)
