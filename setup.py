from setuptools import find_packages, setup

setup(
    name='flask_project',
    version='1.0.0',
    packages=find_packages(),
    include_package_data=True,
    zip_safe=False,
    install_requires=[
        'flask',
        'flask_bootstrap',
        'flask_wtf',
        'flask_sqlalchemy',
        'flask_login',
        'wtforms',
        'email_validator',
    ],
)