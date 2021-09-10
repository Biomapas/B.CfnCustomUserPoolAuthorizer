class PolicyDocument:
    def __init__(self):
        region = 'region'
        account_id = 'account'
        api_id = 'id'


        document = {
            "policyDocument": {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Action": "execute-api:Invoke",
                        "Resource": [
                            f"arn:aws:execute-api:{region}:{account_id}:{api_id}/*/*"
                        ],
                        "Effect": "Allow"
                    }
                ]
            }
        }
