# B.CfnCustomUserPoolAuthorizer

![Pipeline](https://github.com/Biomapas/B.CfnCustomUserPoolAuthorizer/workflows/Pipeline/badge.svg?branch=master)

An AWS CDK resource that mimics original UserPoolAuthorizer resource.

### Description

This is a custom user pool authorizer used to protect API endpoints.
It has exactly the same functionality and purpose as the original 
[UserPoolAuthorizer](https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-apigatewayv2-authorizer.html).
The main reason why you would want to use this custom authorizer instead
of a default one - is that this custom authorizer can resolve user pool
region, id, and client id from SSM parameters (AWS Systems Manager Parameter Store).
This way your stacks no longer need a dependency to a stack containing user pool instance.

### Remarks

[Biomapas](https://www.biomapas.com/) aims to modernise life-science industry by sharing its IT knowledge with other companies and the community. 
This is an open source library intended to be used by anyone. 
Improvements and pull requests are welcome. 

### Related technology

- Python3
- AWS CDK
- AWS CloudFormation
- AWS Cognito
- AWS Cognito User Pool
- AWS API Gateway
- AWS API Gateway Authorizer


### Assumptions

This project assumes you are an expert in infrastructure-as-code via AWS CloudFormation and AWS CDK.
You must clearly understand how AWS API Gateway endpoints are protected with Authorizers / Custom Authorizers
and how it is managed via CloudFormation or CDK. You must also understand the pain-points
of stack dependencies and dependencies between microservices in general (which this package aims to solve). 

- Excellent knowledge in IaaC (Infrastructure as a Code) principles.
- Excellent knowledge in Cognito, User Pool, API Gateway, Authorizers.  
- Good experience in AWS CDK and AWS CloudFormation.
- Good Python skills and basis of OOP.

### Useful sources

- AWS CDK:<br>https://docs.aws.amazon.com/cdk/api/latest/docs/aws-construct-library.html
- AWS CloudFormation:<br>https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/Welcome.html
- API Gateway with CloudFormation:<br>https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-apigatewayv2-api.html
- AWS Cognito use pool:<br>https://docs.aws.amazon.com/cognito/latest/developerguide/cognito-user-identity-pools.html
- AWS Custom Authorizers:<br>https://docs.aws.amazon.com/apigateway/latest/developerguide/apigateway-use-lambda-authorizer.html

### Install

Before installing this library, ensure you have these tools setup:

- Python / Pip
- AWS CDK
- Docker

To install this project from source run:

```
pip install .
```


Or you can install it from a PyPi repository:

```
pip install b-cfn-custom-userpool-authorizer
```


### Usage & Examples

```python
from aws_cdk.core import Stack
from aws_cdk.aws_cognito import UserPool, UserPoolClient
from aws_cdk.aws_apigatewayv2 import CfnApi

from b_cfn_custom_userpool_authorizer.config.user_pool_config import UserPoolConfig
from b_cfn_custom_userpool_authorizer.user_pool_custom_authorizer import UserPoolCustomAuthorizer

# Create user pool and client.
pool = UserPool(...)
client = UserPoolClient(...)

# Create an API Gateway API.
api = CfnApi(...)

# Create custom authorizer and use it in your endpoints (CfnRoute).
authorizer = UserPoolCustomAuthorizer(
    scope=Stack(...),
    name='MyCustomAuthorizer',
    api=api,
    user_pool_config=UserPoolConfig(
        user_pool_id=pool.user_pool_id,
        user_pool_region=pool.stack.region,
        user_pool_client_id=client.user_pool_client_id
    )
)
```

### Testing

This package has integration tests based on **pytest**.
To run tests simply run:

```
pytest b_cfn_custom_userpool_authorizer_test/integration/tests
```

### Contribution

Found a bug? Want to add or suggest a new feature? 
Contributions of any kind are gladly welcome. 
You may contact us directly, create a pull-request or an issue in github platform. 
Lets modernize the world together.