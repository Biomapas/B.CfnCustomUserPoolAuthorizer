from typing import Union

from aws_cdk.aws_apigatewayv2 import CfnAuthorizer, CfnApi
from aws_cdk.core import Stack

from b_cfn_custom_userpool_authorizer.config.user_pool_config import UserPoolConfig
from b_cfn_custom_userpool_authorizer.config.user_pool_ssm_config import UserPoolSsmConfig
from b_cfn_custom_userpool_authorizer.user_pool_custom_authorizer_function import AuthorizerFunction


class UserPoolCustomAuthorizer(CfnAuthorizer):
    def __init__(
            self,
            scope: Stack,
            name: str,
            api: CfnApi,
            user_pool_config: Union[UserPoolConfig, UserPoolSsmConfig]
    ) -> None:
        """
        Constructor.

        :param scope: CloudFormation stack.
        :param name: Name of the custom authorizer e.g. "MyCoolAuthorizer".
        :param api: Parent API for which we are creating the authorizer.
        """
        lambda_function = AuthorizerFunction(
            scope=scope,
            name=f'{name}Function',
            user_pool_config=user_pool_config
        )

        # These environment variables are necessary for a lambda function to create
        # a policy document to allow/deny access. Read more here:
        # https://docs.aws.amazon.com/apigateway/latest/developerguide/api-gateway-lambda-authorizer-output.html
        lambda_function.add_environment('AWS_ACCOUNT', scope.account)
        lambda_function.add_environment('AWS_API_ID', api.ref)

        # Constructed by reading this documentation:
        # https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-apigatewayv2-authorizer.html
        super().__init__(
            scope=scope,
            id=name,
            name=name,
            api_id=api.ref,
            authorizer_payload_format_version='2.0',
            authorizer_result_ttl_in_seconds=0,
            authorizer_type='REQUEST',
            authorizer_uri=(
                f'arn:aws:apigateway:{scope.region}:'
                f'lambda:path/2015-03-31/functions/arn:'
                f'aws:lambda:{scope.region}:{scope.account}:'
                f'function:{lambda_function.function_name}/invocations'
            ),
            identity_source=[],
        )
