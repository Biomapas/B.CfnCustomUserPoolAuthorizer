import urllib3
from urllib3 import HTTPResponse

from b_cfn_custom_userpool_authorizer_test.integration.infrastructure.main_stack import MainStack
from b_cfn_custom_userpool_authorizer_test.integration.util.urlsafe_json import UrlSafeJson


def test_authorizer_with_invalid_kid_deny(access_token) -> None:
    """
    Tests whether the authorizer denys the request to pass through, if the
    access token is invalid (invalid kid).

    :param access_token: (Fixture) valid access token that will be modified to be invalid.

    :return: No return.
    """
    # Modify the kid so the whole jwt becomes invalid.
    header, payload, signature = access_token.split('.')
    header = UrlSafeJson.decode(header)
    header['kid'] = 'AutxFv/SsJHvxbk2C2w3AOyWp3P6Sg+bP92bUInAAeB='
    header = UrlSafeJson.encode(header)
    access_token = f'{header}.{payload}.{signature}'

    assert __make_call(access_token).status == 403


def test_authorizer_with_invalid_expiration_deny(access_token) -> None:
    """
    Tests whether the authorizer denys the request to pass through, if the
    access token is invalid (invalid expiration time).

    :param access_token: (Fixture) valid access token that will be modified to be invalid.

    :return: No return.
    """
    # Modify the expiration so the whole jwt becomes invalid.
    header, payload, signature = access_token.split('.')
    payload = UrlSafeJson.decode(payload)
    payload['exp'] = 1032393848
    payload = UrlSafeJson.encode(payload)
    access_token = f'{header}.{payload}.{signature}'

    assert __make_call(access_token).status == 403


def __make_call(access_token) -> HTTPResponse:
    endpoint = MainStack.get_output(MainStack.API_ENDPOINT_KEY)

    http = urllib3.PoolManager()

    return http.request(
        method='GET',
        url=endpoint,
        headers={
            'Authorization': access_token
        },
    )
