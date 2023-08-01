from b_aws_testing_framework.tools.cdk_testing.testing_stack import TestingStack
from constructs import Construct

from b_cfn_custom_userpool_authorizer_test.integration.infrastructure.api_stack import ApiStack
from b_cfn_custom_userpool_authorizer_test.integration.infrastructure.authorized_endpoint_stack import AuthorizedEndpointStack
from b_cfn_custom_userpool_authorizer_test.integration.infrastructure.user_pool_stack import UserPoolStack


class MainStack(TestingStack):
    API_URL_KEY = 'ApiUrl'
    API_ENDPOINT_KEY = 'ApiEndpoint'
    USER_POOL_ID_KEY = 'UserPoolId'
    USER_POOL_CLIENT_ID_KEY = 'UserPoolClientId'

    def __init__(self, scope: Construct) -> None:
        super().__init__(scope=scope)

        self.user_pool_stack = UserPoolStack(self)
        self.api_stack = ApiStack(self, self.user_pool_stack)
        self.endpoint_stack = AuthorizedEndpointStack(self, self.api_stack.api, self.api_stack.authorizer)

        self.add_output(self.API_URL_KEY, value=self.api_stack.api.attr_api_endpoint)
        self.add_output(self.API_ENDPOINT_KEY, value=f'{self.api_stack.api.attr_api_endpoint}/{self.api_stack.stage.stage_name}/dummy')
        self.add_output(self.USER_POOL_ID_KEY, value=self.user_pool_stack.pool.user_pool_id)
        self.add_output(self.USER_POOL_CLIENT_ID_KEY, value=self.user_pool_stack.client.user_pool_client_id)
