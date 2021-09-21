from typing import Optional, Dict


class UserPoolConfig:
    def __init__(
            self,
            user_pool_id: Optional[str] = None,
            user_pool_region: Optional[str] = None,
            user_pool_client_id: Optional[str] = None,
    ) -> None:
        self.user_pool_id = user_pool_id
        self.user_pool_region = user_pool_region
        self.user_pool_client_id = user_pool_client_id

    def to_dict(self) -> Dict[str, str]:
        return {
            'USER_POOL_ID': self.user_pool_id,
            'USER_POOL_REGION': self.user_pool_region,
            'USER_POOL_CLIENT_ID': self.user_pool_client_id,
        }
