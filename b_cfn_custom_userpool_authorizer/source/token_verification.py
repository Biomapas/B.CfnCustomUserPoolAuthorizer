import json
import os
import time
from typing import Optional

import urllib3
from jose import jwk, jwt
from jose.utils import base64url_decode

from auth_exception import AuthException

USER_POOL_REGION = os.environ['USER_POOL_REGION']
USER_POOL_ID = os.environ['USER_POOL_ID']
USER_POOL_CLIENT_ID = os.environ['USER_POOL_CLIENT_ID']
KEYS_URL = f'https://cognito-idp.{USER_POOL_REGION}.amazonaws.com/{USER_POOL_ID}/.well-known/jwks.json'

with urllib3.PoolManager().request('GET', KEYS_URL) as f: response = f.read()
KEYS = json.loads(response.decode('utf-8'))['keys']


class TokenVerification:
    def __init__(self, access_token: str):
        self.__access_token = access_token

        if not access_token:
            raise AuthException('Access token not provided!')

    def verify(self) -> None:
        # Find kid.
        if kid := self.__find_kid() is None:
            raise AuthException('Public key not found in jwks.json.')

        # Verify signature.
        if not self.__verify_signature(kid):
            raise AuthException('Signature verification failed.')

        # Since we passed the verification, we can now safely use the unverified claims.
        if not self.__verify_claims():
            raise AuthException('Claims verification failed.')

    def __find_kid(self) -> Optional[str]:
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
            print('Public key not found in jwks.json')
            return None

        return KEYS[key_index]

    def __verify_signature(self, kid: str) -> bool:
        # construct the public key
        public_key = jwk.construct(kid)
        # get the last two sections of the token,
        # message and signature (encoded in base64)
        message, encoded_signature = str(self.__access_token).rsplit('.', 1)
        # decode the signature
        decoded_signature = base64url_decode(encoded_signature.encode('utf-8'))
        # verify the signature
        if not public_key.verify(message.encode("utf8"), decoded_signature):
            print('Signature verification failed')
            return False
        print('Signature successfully verified')
        return True

    def __verify_claims(self) -> bool:
        claims = jwt.get_unverified_claims(self.__access_token)
        # additionally we can verify the token expiration
        if time.time() > claims['exp']:
            print('Token is expired')
            return False
        # and the Audience  (use claims['client_id'] if verifying an access token)
        if claims['aud'] != USER_POOL_CLIENT_ID:
            print('Token was not issued for this audience')
            return False
        return True
