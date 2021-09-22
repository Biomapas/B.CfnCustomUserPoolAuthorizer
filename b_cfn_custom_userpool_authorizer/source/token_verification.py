import json
import os
import time

import urllib3
from jose import jwk, jwt
from jose.utils import base64url_decode

from auth_exception import AuthException

USER_POOL_REGION = os.environ['USER_POOL_REGION']
USER_POOL_ID = os.environ['USER_POOL_ID']
USER_POOL_CLIENT_ID = os.environ['USER_POOL_CLIENT_ID']
KEYS_URL = f'https://cognito-idp.{USER_POOL_REGION}.amazonaws.com/{USER_POOL_ID}/.well-known/jwks.json'

HTTP_MANGER = urllib3.PoolManager()
KEYS = json.loads(HTTP_MANGER.request('GET', KEYS_URL).data.decode())['keys']


class TokenVerification:
    """
    Class responsible for access token verification. The inspiration is taken from this example:
    https://github.com/awslabs/aws-support-tools/blob/master/Cognito/decode-verify-jwt/decode-verify-jwt.py
    """
    def __init__(self, access_token: str):
        self.__access_token = access_token

        if not access_token:
            raise AuthException('Access token not provided!')

    def verify(self) -> None:
        """
        Verifies the provided access token. If token is not valid
        an exception is thrown. If no exception is thrown - token is valid.

        :return: No return.
        """
        print(
            f'Verifying access token: {self.__access_token}. '
            f'{USER_POOL_REGION=}, {USER_POOL_ID=}, {USER_POOL_CLIENT_ID=}.'
        )

        # Get the kid from the headers prior to verification.
        headers = jwt.get_unverified_headers(self.__access_token)
        kid = headers['kid']
        # Search for the kid in the downloaded public keys.
        key_index = -1
        for i in range(len(KEYS)):
            if kid == KEYS[i]['kid']:
                key_index = i
                break
        if key_index == -1:
            raise AuthException('Public key not found in jwks.json!')

        # Construct the public key.
        public_key = jwk.construct(KEYS[key_index])
        # Get the last two sections of the token: message and signature (encoded in base64).
        message, encoded_signature = str(self.__access_token).rsplit('.', 1)
        # Decode the signature.
        decoded_signature = base64url_decode(encoded_signature.encode('utf-8'))

        # Verify the signature.
        if not public_key.verify(message.encode("utf8"), decoded_signature):
            raise AuthException('Signature verification failed!')

        # Since we passed the verification, we can now safely use the unverified claims.
        claims = jwt.get_unverified_claims(self.__access_token)
        print(f'Claims: {claims}.')

        # Additionally we can verify the token expiration.
        if time.time() > claims['exp']:
            raise AuthException('Token is expired!')

        # And the Audience (use claims['client_id'] if verifying an access token). Read more here:
        # https://stackoverflow.com/questions/53148711/why-doesnt-amazon-cognito-return-an-audience-field-in-its-access-tokens
        if (claims.get('aud') or claims.get('client_id')) != USER_POOL_CLIENT_ID:
            raise AuthException('Token was not issued for this audience')
