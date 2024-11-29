import base64
import typing as t
from pydantic import BaseModel

__all__ = ["RequestModel", "ResponseModel"]


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


class UploadFile: ...


class Form(t.Dict[str, t.List[str]]): ...


class FormData(t.Dict[str, t.List[t.Union[str, UploadFile]]]): ...
