from aws_cdk import App

from b_cfn_custom_userpool_authorizer_test.integration.infrastructure.main_stack import MainStack

app = App()
MainStack(app)
app.synth()
