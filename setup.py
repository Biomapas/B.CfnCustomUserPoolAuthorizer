from setuptools import setup, find_packages

with open('README.md') as readme_file:
    README = readme_file.read()

with open('HISTORY.md') as history_file:
    HISTORY = history_file.read()

with open('VERSION') as file:
    VERSION = file.read()
    VERSION = ''.join(VERSION.split())

setup(
    name='b_cfn_custom_userpool_authorizer',
    version=VERSION,
    license='Apache License 2.0',
    packages=find_packages(exclude=[
        # Exclude virtual environment.
        'venv',
        # Exclude test source files.
        'b_cfn_custom_userpool_authorizer_test'
    ]),
    description=(
        'Package that enables deployment of AWS CDK stacks in parallel.'
    ),
    long_description=README + '\n\n' + HISTORY,
    long_description_content_type='text/markdown',
    include_package_data=True,
    install_requires=[
        'python-jose>=3.3.0',
        'b-continuous-subprocess>=0.3.2,<1.0.0',
        'b-lambda-layer-common>=2.0.0,<3.0.0',
        'b-aws-cdk-parallel>=1.3.0,<2.0.0',
        'b-cfn-lambda-integration>=0.0.8,<1.0.0',
        'aws_cdk.aws_apigatewayv2>=1.90.0',
        'aws_cdk.aws_lambda>=1.90.0',
        'aws-cdk.assets>=1.90.0',
        'aws-cdk.aws-ec2>=1.90.0',
        'aws-cdk.core>=1.90.0',
        'aws-cdk.custom-resources>=1.90.0',
        'aws-cdk.cloud-assembly-schema>=1.90.0',
        'aws-cdk.region-info>=1.90.0',
        'aws-cdk.aws-cognito>=1.90.0',
    ],
    keywords='AWS Cognito UserPool Authorizer',
    url='https://github.com/biomapas/B.CfnCustomUserPoolAuthorizer.git',
    classifiers=[
        'Programming Language :: Python :: 3',
        'Operating System :: OS Independent',
    ],
)
