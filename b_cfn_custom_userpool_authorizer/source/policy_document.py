from typing import Any, Dict, Optional


class PolicyDocument:
    """
    Policy document that is constructed according to this documentation:
    https://docs.aws.amazon.com/apigateway/latest/developerguide/api-gateway-lambda-authorizer-output.html
    """
    def __init__(
            self,
            region: str,
            account_id: str,
            api_id: str
    ) -> None:
        self.region = region
        self.account_id = account_id
        self.api_id = api_id

    def create_policy_statement(
            self,
            allow: bool = False,
            claims: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        claims = claims or {}

        return {
            'principalId': 'user',
            'policyDocument': {
                'Version': '2012-10-17',
                'Statement': [
                    {
                        'Action': 'execute-api:Invoke',
                        'Resource': f'arn:aws:execute-api:{self.region}:{self.account_id}:{self.api_id}/*/*',
                        'Effect': 'Allow' if allow else 'Deny'
                    }
                ]
            },
            'context': {
                'auth_time': claims.get('auth_time'),
                'client_id': claims.get('client_id'),
                'event_id': claims.get('event_id'),
                'exp': claims.get('exp'),
                'iat': claims.get('iat'),
                'iss': claims.get('iss'),
                'jti': claims.get('jti'),
                'scope': claims.get('scope'),
                'sub': claims.get('sub'),
                'token_use': claims.get('token_use'),
                'username': claims.get('username')
            }
        }
