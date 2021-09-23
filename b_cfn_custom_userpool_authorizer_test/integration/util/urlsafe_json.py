import json
from typing import Any, Dict

from jose.utils import base64url_decode, base64url_encode


class UrlSafeJson:
    @staticmethod
    def decode(data: str) -> Dict[str, Any]:
        data = base64url_decode(data.encode())
        return json.loads(data)

    @staticmethod
    def encode(data: Dict[str, Any]) -> str:
        data = json.dumps(data).replace(' ', '').replace('/', '\\/').encode()
        return base64url_encode(data).decode()
