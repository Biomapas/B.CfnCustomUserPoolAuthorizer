import urllib3
from b_aws_testing_framework.credentials import Credentials
from urllib3 import HTTPResponse

from b_cfn_custom_userpool_authorizer_test.integration.infrastructure import Infrastructure


def test_dummy():
    client = Credentials().boto_session.client('cognito-idp')
    user_pool_id = Infrastructure.get_output(Infrastructure.USER_POOL_ID_KEY)
    user_pool_client_id = Infrastructure.get_output(Infrastructure.USER_POOL_CLIENT_ID_KEY)
    endpoint = Infrastructure.get_output(Infrastructure.API_ENDPOINT_KEY)
    
    username = 'TestSampleUsername123'

    # A random string to fit the requirements.
    temp_password = ')%2LU5nGNr-TEST'
    new_password = '34#$%ERTre!t3y'

    try:
        # Cleanup before creating user. There might be leftovers from previous run.
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

    http = urllib3.PoolManager()

    response: HTTPResponse = http.request(
        method='GET',
        url=endpoint,
        headers={
            'Authorization': access_token
        },
    )

    try:
        assert response.status == 200

        data = response.data
        data = data.decode()
        assert data == 'Hello World!'
    except Exception:
        # Cleanup. Ensure no data is left.
        client.admin_delete_user(
            UserPoolId=user_pool_id,
            Username=username
        )

        raise
