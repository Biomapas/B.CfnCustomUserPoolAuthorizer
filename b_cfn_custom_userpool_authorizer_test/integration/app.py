from aws_cdk.core import App

from b_cfn_custom_userpool_authorizer_test.integration.infrastructure import Infrastructure

app = App()
Infrastructure(app)
app.synth()
