from typing import Optional, Dict


class UserPoolConfig:
    def __init__(
            self,
            user_pool_id: Optional[str] = None,
            user_pool_client_id: Optional[str] = None,
            user_pool_id_ssm_key: Optional[str] = None,
            user_pool_client_id_ssm_key: Optional[str] = None
    ) -> None:
        self.user_pool_id = user_pool_id
        self.user_pool_client_id = user_pool_client_id
        self.id_specified = self.user_pool_id and self.user_pool_client_id

        self.user_pool_id_ssm_key = user_pool_id_ssm_key
        self.user_pool_client_id_ssm_key = user_pool_client_id_ssm_key
        self.ssm_specified = self.user_pool_id_ssm_key and self.user_pool_client_id_ssm_key

        if (not self.id_specified) and (not self.ssm_specified):
            raise ValueError('Specify either resource ids or ssm keys from which ids will be retrieved.')

        if self.id_specified and self.ssm_specified:
            raise ValueError('You can not specify both ids and ssm keys.')

    def to_dict(self) -> Dict[str, str]:
        if self.id_specified:
            return {
                'USER_POOL_ID': self.user_pool_id,
                'USER_POOL_CLIENT_ID': self.user_pool_client_id,
            }

        if self.ssm_specified:
            return {
                'USER_POOL_ID_SSM_KEY': self.user_pool_id_ssm_key,
                'USER_POOL_CLIENT_ID_SSM_KEY': self.user_pool_client_id_ssm_key,
            }

        raise Exception('Unexpected state.')
