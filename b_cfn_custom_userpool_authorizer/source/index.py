import json
import os

from auth_exception import AuthException
from policy_document import PolicyDocument
from token_verification import TokenVerification


def handler(event, context):
    print(f'Received event:\n{json.dumps(event)}')

    document = PolicyDocument(
        region=os.environ['AWS_REGION'],
        account_id=os.environ['AWS_ACCOUNT'],
        api_id=os.environ['AWS_API_ID']
    )

    # Verify the authorization token.
    try:
        claims = TokenVerification(event.get('headers', {}).get('authorization')).verify()
        # Authorization was successful. Return "Allow".
        return document.create_policy_statement(allow=True, claims=claims)
    except AuthException as ex:
        # Log the error.
        print(ex)
        # Authorization has failed. Return "Deny".
        return document.create_policy_statement(allow=False)
