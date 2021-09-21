from typing import Optional, Dict


class UserPoolSsmConfig:
    def __init__(
            self,
            user_pool_id_ssm_key: Optional[str] = None,
            user_pool_region_ssm_key: Optional[str] = None,
            user_pool_client_id_ssm_key: Optional[str] = None
    ) -> None:
        self.user_pool_id_ssm_key = user_pool_id_ssm_key
        self.user_pool_region_ssm_key = user_pool_region_ssm_key
        self.user_pool_client_id_ssm_key = user_pool_client_id_ssm_key

    def to_dict(self) -> Dict[str, str]:
        return {
            'USER_POOL_ID_SSM_KEY': self.user_pool_id_ssm_key,
            'USER_POOL_REGION_SSM_KEY': self.user_pool_region_ssm_key,
            'USER_POOL_CLIENT_ID_SSM_KEY': self.user_pool_client_id_ssm_key,
        }
