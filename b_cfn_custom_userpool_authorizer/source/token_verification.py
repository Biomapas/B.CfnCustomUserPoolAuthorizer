import json
import time
from typing import Any, Dict

import urllib3
from jose import jwk, jwt, JWTError
from jose.utils import base64url_decode

from auth_exception import AuthException
from user_pool_resolver import Resolver

KEYS_URL = f'https://cognito-idp.{Resolver.user_pool_region}.amazonaws.com/{Resolver.user_pool_id}/.well-known/jwks.json'
HTTP_MANAGER = urllib3.PoolManager()
KEYS = json.loads(HTTP_MANAGER.request('GET', KEYS_URL).data.decode())['keys']


class TokenVerification:
    """
    Class responsible for access token verification. The inspiration is taken from this example:
    https://github.com/awslabs/aws-support-tools/blob/master/Cognito/decode-verify-jwt/decode-verify-jwt.py
    """
    def __init__(self, access_token: str):
        # If there is a 'Bearer ' string at the beginning of the token (indicating that
        # this is a Bearer Token) it must be removed before token verification.
        self.__access_token = access_token.replace('Bearer ', '')

        if not access_token:
            raise AuthException('Access token not provided.')

    def verify(self) -> Dict[str, Any]:
        """
        Verifies the provided access token. If token is not valid
        an exception is thrown. If no exception is thrown - token is valid.

        :return: JWT claims.
        """
        print(
            f'Verifying access token: {self.__access_token}. '
            f'{Resolver.user_pool_region=}, {Resolver.user_pool_id=}, {Resolver.user_pool_client_id=}.'
        )

        try:
            headers = jwt.get_unverified_headers(self.__access_token)
        except JWTError:
            raise AuthException('Unable to retrieve unverified headers.')

        # Get the kid from the headers prior to verification.
        kid = headers['kid']
        # Search for the kid in the downloaded public keys.
        key_index = -1
        for i in range(len(KEYS)):
            if kid == KEYS[i]['kid']:
                key_index = i
                break
        if key_index == -1:
            raise AuthException('Public key not found in jwks.json.')

        # Construct the public key.
        public_key = jwk.construct(KEYS[key_index])
        # Get the last two sections of the token: message and signature (encoded in base64).
        message, encoded_signature = str(self.__access_token).rsplit('.', 1)
        # Decode the signature.
        decoded_signature = base64url_decode(encoded_signature.encode('utf-8'))

        # Verify the signature.
        if not public_key.verify(message.encode("utf8"), decoded_signature):
            raise AuthException('Signature verification failed.')

        # Since we passed the verification, we can now safely use the unverified claims.
        try:
            claims = jwt.get_unverified_claims(self.__access_token)
        except JWTError:
            raise AuthException('Unable to retrieve unverified claims.')
        print(f'Claims: {claims}.')

        # Additionally we can verify the token expiration.
        if time.time() > claims['exp']:
            raise AuthException('Token is expired.')

        # And the Audience (use claims['client_id'] if verifying an access token). Read more here:
        # https://stackoverflow.com/questions/53148711/why-doesnt-amazon-cognito-return-an-audience-field-in-its-access-tokens
        if (claims.get('aud') or claims.get('client_id')) != Resolver.user_pool_client_id:
            raise AuthException('Token was not issued for this audience.')

        return claims
