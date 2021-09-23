import urllib3
from urllib3 import HTTPResponse

from b_cfn_custom_userpool_authorizer_test.integration.infrastructure.main_stack import MainStack


def test_authorizer_allow(access_token: str) -> None:
    """
    Tests whether the authorizer allows the request to pass through, if the
    access token is valid.

    :param access_token: (Fixture) valid access token.

    :return: No return.
    """
    endpoint = MainStack.get_output(MainStack.API_ENDPOINT_KEY)

    http = urllib3.PoolManager()

    response: HTTPResponse = http.request(
        method='GET',
        url=endpoint,
        headers={
            'Authorization': access_token
        },
    )

    assert response.status == 200

    data = response.data
    data = data.decode()
    # Response from a dummy lambda function defined in the infrastructure main stack.
    assert data == 'Hello World!'
