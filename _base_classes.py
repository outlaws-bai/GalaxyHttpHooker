import base64
import typing as t
from pydantic import BaseModel

__all__ = ["RequestModel", "ResponseModel", "parse_sm2_pri", "parse_sm2_pub"]


class RequestModel(BaseModel):
    secure: bool
    host: str
    port: int
    version: str
    method: str
    path: str
    query: t.Dict[str, t.List[str]]
    headers: t.Dict[str, t.List[str]]
    contentBase64: str

    @property
    def content(self) -> bytes:
        return base64.b64decode(self.contentBase64)

    @content.setter
    def content(self, content: bytes):
        self.contentBase64 = base64.b64encode(content).decode()


class ResponseModel(BaseModel):
    version: str
    statusCode: int
    reason: str
    headers: t.Dict[str, t.List[str]]
    contentBase64: str

    @property
    def content(self) -> bytes:
        return base64.b64decode(self.contentBase64)

    @content.setter
    def content(self, content: bytes):
        self.contentBase64 = base64.b64encode(content).decode()


def parse_sm2_pri(pri):
    pri_hex = pri.hex()
    return pri_hex[72 : 72 + 64]


def parse_sm2_pub(pub):
    pub_hex = pub.hex()
    return pub_hex[-128:]
