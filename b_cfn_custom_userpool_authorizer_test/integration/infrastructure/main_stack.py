from aws_cdk.aws_apigatewayv2 import CfnApi, CfnStage
from aws_cdk.core import Construct
from b_aws_testing_framework.tools.cdk_testing.testing_stack import TestingStack

from b_cfn_custom_userpool_authorizer.config.user_pool_ssm_config import UserPoolSsmConfig
from b_cfn_custom_userpool_authorizer.user_pool_custom_authorizer import UserPoolCustomAuthorizer
from b_cfn_custom_userpool_authorizer_test.integration.infrastructure.authorized_endpoint_stack import AuthorizedEndpointStack
from b_cfn_custom_userpool_authorizer_test.integration.infrastructure.user_pool_stack import UserPoolStack


class MainStack(TestingStack):
    API_URL_KEY = 'ApiUrl'
    API_ENDPOINT_KEY = 'ApiEndpoint'
    USER_POOL_ID_KEY = 'UserPoolId'
    USER_POOL_CLIENT_ID_KEY = 'UserPoolClientId'

    def __init__(self, scope: Construct) -> None:
        super().__init__(scope=scope)

        prefix = TestingStack.global_prefix()

        self.user_pool_stack = UserPoolStack(self)

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
                user_pool_id_ssm_key=self.user_pool_stack.ssm_pool_id.parameter_name,
                user_pool_client_id_ssm_key=self.user_pool_stack.ssm_pool_client_id.parameter_name,
                user_pool_region_ssm_key=self.user_pool_stack.ssm_pool_region.parameter_name,
            )
        )

        self.stage: CfnStage = CfnStage(
            scope=self,
            id='Stage',
            stage_name='test',
            api_id=self.api.ref,
            auto_deploy=True,
        )

        self.endpoint_stack = AuthorizedEndpointStack(self, self.api, self.authorizer)

        self.add_output(self.API_URL_KEY, value=self.api.attr_api_endpoint)
        self.add_output(self.API_ENDPOINT_KEY, value=f'{self.api.attr_api_endpoint}/{self.stage.stage_name}/dummy')
        self.add_output(self.USER_POOL_ID_KEY, value=self.user_pool_stack.pool.user_pool_id)
        self.add_output(self.USER_POOL_CLIENT_ID_KEY, value=self.user_pool_stack.client.user_pool_client_id)
