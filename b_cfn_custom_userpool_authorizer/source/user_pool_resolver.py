import os

from b_lambda_layer_common.ssm.ssm_parameter import SSMParameter

USER_POOL_REGION_PARAMETER = SSMParameter(os.environ.get('USER_POOL_REGION_SSM_KEY'))
USER_POOL_ID_PARAMETER = SSMParameter(os.environ.get('USER_POOL_ID_SSM_KEY'))
USER_POOL_CLIENT_ID_PARAMETER = SSMParameter(os.environ.get('USER_POOL_CLIENT_ID_SSM_KEY'))


class UserPoolResolver:
    def __init__(self):
        self.user_pool_region = os.environ.get('USER_POOL_REGION') or USER_POOL_REGION_PARAMETER.value
        self.user_pool_id = os.environ.get('USER_POOL_ID') or USER_POOL_ID_PARAMETER.value
        self.user_pool_client_id = os.environ.get('USER_POOL_CLIENT_ID') or USER_POOL_CLIENT_ID_PARAMETER.value


# Expose the instance that is globally cached by a Lambda service.
Resolver = UserPoolResolver()
