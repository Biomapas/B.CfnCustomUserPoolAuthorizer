from aws_cdk.aws_iam import PolicyStatement
from aws_cdk.aws_lambda import Function, Code, Runtime, CfnPermission
from aws_cdk.aws_logs import RetentionDays
from aws_cdk.core import Duration, Stack
from b_lambda_layer_common.layer_v2 import LayerV2 as BLayer
from b_lambda_layer_common.package_version import PackageVersion

from b_cfn_custom_userpool_authorizer.user_pool_config import UserPoolConfig


class AuthorizerFunction(Function):
    def __init__(
            self,
            scope: Stack,
            name: str,
            user_pool_config: UserPoolConfig,
            *args,
            **kwargs
    ) -> None:
        super().__init__(
            scope=scope,
            id=name,
            function_name=name,
            code=self.code(),
            handler='index.handler',
            runtime=Runtime.PYTHON_3_8,
            environment=user_pool_config.to_dict(),
            layers=[
                BLayer(
                    scope=scope,
                    name=f'{name}BCommonLayer',
                    dependencies={
                        'python-jose': PackageVersion.from_string_version('3.3.0')
                    }
                )
            ],
            log_retention=RetentionDays.ONE_MONTH,
            memory_size=128,
            timeout=Duration.seconds(30),
            *args,
            **kwargs
        )

        CfnPermission(
            scope=scope,
            id=f'{name}InvokePermissionForApiGateway',
            action='lambda:InvokeFunction',
            function_name=self.function_name,
            principal='apigateway.amazonaws.com',
        )

        if user_pool_config.ssm_specified:
            self.add_to_role_policy(
                PolicyStatement(
                    actions=['ssm:GetParameters'],
                    resources=['*']
                )
            )

    @staticmethod
    def code() -> Code:
        from .source import root
        return Code.from_asset(root)
