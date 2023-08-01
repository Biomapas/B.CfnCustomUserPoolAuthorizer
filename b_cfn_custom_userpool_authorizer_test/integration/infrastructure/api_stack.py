from aws_cdk import Stack
from aws_cdk.aws_apigatewayv2 import CfnApi, CfnStage
from b_aws_testing_framework.tools.cdk_testing.testing_stack import TestingStack
from constructs import Construct

from b_cfn_custom_userpool_authorizer.config.user_pool_ssm_config import UserPoolSsmConfig
from b_cfn_custom_userpool_authorizer.user_pool_custom_authorizer import UserPoolCustomAuthorizer
from b_cfn_custom_userpool_authorizer_test.integration.infrastructure.user_pool_stack import UserPoolStack


class ApiStack(Stack):
    def __init__(self, scope: Construct, user_pool_stack: UserPoolStack) -> None:
        super().__init__(scope=scope, id='ApiStack')

        prefix = TestingStack.global_prefix()

        self.api = CfnApi(
            scope=self,
            id='Api',
            name=f'{prefix}Api',
            description='Sample description.',
            protocol_type='HTTP',
            cors_configuration=CfnApi.CorsProperty(
                allow_methods=['GET', 'PUT', 'POST', 'OPTIONS', 'DELETE'],
                allow_origins=['*'],
                allow_headers=[
                    'Content-Type',
                    'Authorization'
                ],
                max_age=300
            )
        )

        self.authorizer = UserPoolCustomAuthorizer(
            scope=self,
            name=f'{prefix}UserPoolCustomAuthorizer',
            api=self.api,
            # Dynamically resolve.
            user_pool_config=UserPoolSsmConfig(
                user_pool_id_ssm_key=user_pool_stack.ssm_pool_id.parameter_name,
                user_pool_client_id_ssm_key=user_pool_stack.ssm_pool_client_id.parameter_name,
                user_pool_region_ssm_key=user_pool_stack.ssm_pool_region.parameter_name,
            )
        )

        self.stage: CfnStage = CfnStage(
            scope=self,
            id='Stage',
            stage_name='test',
            api_id=self.api.ref,
            auto_deploy=True,
        )
