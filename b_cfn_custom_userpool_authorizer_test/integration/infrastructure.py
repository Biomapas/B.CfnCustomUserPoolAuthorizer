from aws_cdk.aws_apigatewayv2 import CfnApi, CfnStage, CfnRoute
from aws_cdk.aws_cognito import *
from aws_cdk.aws_lambda import Function, Code, Runtime, CfnPermission
from aws_cdk.core import Construct, Duration
from b_aws_testing_framework.tools.cdk_testing.testing_stack import TestingStack

from b_cfn_custom_userpool_authorizer.config.user_pool_config import UserPoolConfig
from b_cfn_custom_userpool_authorizer.user_pool_custom_authorizer import UserPoolCustomAuthorizer
from b_cfn_lambda_integration.lambda_integration import LambdaIntegration


class Infrastructure(TestingStack):
    API_URL_KEY = 'ApiUrl'
    API_ENDPOINT_KEY = 'ApiEndpoint'
    USER_POOL_ID_KEY = 'UserPoolId'
    USER_POOL_CLIENT_ID_KEY = 'UserPoolClientId'

    def __init__(self, scope: Construct) -> None:
        super().__init__(scope=scope)

        prefix = TestingStack.global_prefix()

        self.pool = UserPool(
            scope=self,
            id='UserPool',
            user_pool_name=f'{prefix}UserPool',
            account_recovery=AccountRecovery.NONE,
            auto_verify=AutoVerifiedAttrs(email=True, phone=False),
            self_sign_up_enabled=False,
            sign_in_aliases=SignInAliases(email=False, phone=False, preferred_username=True, username=True),
            sign_in_case_sensitive=True,
            standard_attributes=StandardAttributes(
                email=StandardAttribute(required=False, mutable=True),
                preferred_username=StandardAttribute(required=True, mutable=True)
            )
        )

        self.client: UserPoolClient = self.pool.add_client(
            id=f'UserPoolClient',
            user_pool_client_name=f'{prefix}UserPoolClient',
            auth_flows=AuthFlow(
                admin_user_password=True,
                user_password=True,
                user_srp=True
            ),
            disable_o_auth=True,
        )

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
            user_pool_config=UserPoolConfig(
                user_pool_id=self.pool.user_pool_id,
                user_pool_client_id=self.client.user_pool_client_id,
                user_pool_region=self.region
            )
        )

        self.stage: CfnStage = CfnStage(
            scope=self,
            id='Stage',
            stage_name='test',
            api_id=self.api.ref,
            auto_deploy=True,
        )

        self.api_endpoint_function = Function(
            scope=self,
            id='ApiFunction',
            function_name=f'{prefix}ApiFunction',
            code=Code.from_inline(
                'def handler(event, context):\n'
                '    print(event)\n'
                '    return {\n'
                '        "statusCode": 200,\n'
                '        "headers": {},\n'
                '        "body": "Hello World!",\n'
                '        "isBase64Encoded": False'
                '    }'
            ),
            handler='index.handler',
            runtime=Runtime.PYTHON_3_7,
            memory_size=128,
            timeout=Duration.seconds(30),
        )

        CfnPermission(
            scope=self,
            id=f'{prefix}InvokePermission',
            action='lambda:InvokeFunction',
            function_name=self.api_endpoint_function.function_name,
            principal='apigateway.amazonaws.com',
        )

        self.integration = LambdaIntegration(
            scope=self,
            api=self.api,
            integration_name=f'{prefix}Integration',
            lambda_function=self.api_endpoint_function
        )

        self.route = CfnRoute(
            scope=self,
            id='DummyRoute',
            api_id=self.api.ref,
            route_key=f'GET /dummy',
            authorization_type='CUSTOM',
            target=f'integrations/{self.integration.ref}',
            authorizer_id=self.authorizer.ref
        )

        self.add_output(self.API_URL_KEY, value=self.api.attr_api_endpoint)
        self.add_output(self.API_ENDPOINT_KEY, value=f'{self.api.attr_api_endpoint}/{self.stage.stage_name}/dummy')
        self.add_output(self.USER_POOL_ID_KEY, value=self.pool.user_pool_id)
        self.add_output(self.USER_POOL_CLIENT_ID_KEY, value=self.client.user_pool_client_id)
