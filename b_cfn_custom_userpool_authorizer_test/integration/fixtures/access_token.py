import json

from b_aws_testing_framework.credentials import Credentials
from jose.utils import base64url_decode
from pytest import fixture

from b_cfn_custom_userpool_authorizer_test.integration.infrastructure.main_stack import MainStack


@fixture(scope='function')
def access_token():
    client = Credentials().boto_session.client('cognito-idp')
    user_pool_id = MainStack.get_output(MainStack.USER_POOL_ID_KEY)
    user_pool_client_id = MainStack.get_output(MainStack.USER_POOL_CLIENT_ID_KEY)

    username = 'TestSampleUsername123'

    # A random string to fit the requirements.
    temp_password = ')%2LU5nGNr-TEST'
    new_password = '34#$%ERTre!t3y'

    try:
        # Cleanup before creating user. There might be leftovers from previous runs.
        client.admin_delete_user(
            UserPoolId=user_pool_id,
            Username=username
        )
    except client.exceptions.UserNotFoundException:
        pass

    client.admin_create_user(
        UserPoolId=user_pool_id,
        Username=username,
        TemporaryPassword=temp_password,
        UserAttributes=[
            {'Name': 'preferred_username', 'Value': username},
        ],
    )

    session = client.admin_initiate_auth(
        UserPoolId=user_pool_id,
        ClientId=user_pool_client_id,
        AuthFlow='ADMIN_NO_SRP_AUTH',
        AuthParameters={'USERNAME': username, 'PASSWORD': temp_password},
    )['Session']

    access_token = client.admin_respond_to_auth_challenge(
        UserPoolId=user_pool_id,
        ClientId=user_pool_client_id,
        ChallengeName='NEW_PASSWORD_REQUIRED',
        ChallengeResponses={
            'NEW_PASSWORD': new_password,
            'USERNAME': username,
        },
        Session=session,
    )['AuthenticationResult']['AccessToken']

    # Debug.
    header, payload, signature = access_token.split('.')
    header = json.loads(base64url_decode(header.encode()).decode())
    payload = json.loads(base64url_decode(payload.encode()).decode())
    print(json.dumps(header, indent=4))
    print(json.dumps(payload, indent=4))

    return access_token
