from typing import Dict, Any


class PolicyDocument:
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
            allow: bool = False
    ) -> Dict[str, Any]:
        return {
            'policyDocument': {
                'Version': '2012-10-17',
                'Statement': [
                    {
                        'Action': 'execute-api:Invoke',
                        'Resource': [
                            f'arn:aws:execute-api:{self.region}:{self.account_id}:{self.api_id}/*/*'
                        ],
                        'Effect': 'Allow' if allow else 'Deny'
                    }
                ]
            }
        }
