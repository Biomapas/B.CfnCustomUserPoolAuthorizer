from aws_cdk.aws_cognito import *
from aws_cdk.core import Construct
from b_aws_testing_framework.tools.cdk_testing.testing_stack import TestingStack


class Infrastructure(TestingStack):
    USER_POOL_ID_KEY = 'UserPoolId'
    USER_POOL_CLIENT_ID_KEY = 'UserPoolClientId'

    def __init__(self, scope: Construct) -> None:
        super().__init__(scope=scope)

        prefix = TestingStack.global_prefix()

        self.pool = UserPool(
            scope=scope,
            id='UserPool',
            user_pool_name=f'{prefix}UserPool',
            account_recovery=AccountRecovery.EMAIL_ONLY,
            auto_verify=AutoVerifiedAttrs(email=True, phone=False),
            self_sign_up_enabled=False,
            sign_in_aliases=SignInAliases(email=True, phone=False, preferred_username=True, username=True),
            sign_in_case_sensitive=True,
            standard_attributes=StandardAttributes(
                email=StandardAttribute(required=True, mutable=True),
                preferred_username=StandardAttribute(required=True, mutable=True)
            )
        )

        self.client: UserPoolClient = self.add_client(
            id=f'UserPoolClient',
            user_pool_client_name='',
            auth_flows=AuthFlow(
                admin_user_password=True,
                user_password=True,
                user_srp=True
            ),
            disable_o_auth=True,
        )
