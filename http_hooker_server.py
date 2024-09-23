# coding: utf-8
# @author: outlaws-bai
# @date: 2024/09/22 16:55:53
# @description: 对应示例中的 AesCbc
import json
import base64
from fastapi import FastAPI
from typing import Dict, List
from Crypto.Cipher import AES
from pydantic import BaseModel
from Crypto.Util.Padding import pad, unpad

get_encrypt_text = lambda x: json.loads(x)["data"]
to_encrypt_body = lambda x: json.dumps({"data": x.decode()}).encode()

KEY = b"32byteslongsecretkeyforaes256!aa"
IV = b"16byteslongiv456"


# AES加密函数
def aes_encrypt(data: bytes) -> bytes:
    cipher = AES.new(KEY, AES.MODE_CBC, IV)
    ct_bytes = cipher.encrypt(pad(data, AES.block_size))
    return base64.b64encode(ct_bytes)


# AES解密函数
def aes_decrypt(data: bytes) -> bytes:
    data1 = base64.b64decode(data)
    cipher = AES.new(KEY, AES.MODE_CBC, IV)
    pt = unpad(cipher.decrypt(data1), AES.block_size)
    return pt


class RequestModel(BaseModel):
    secure: bool
    host: str
    port: int
    version: str
    method: str
    path: str
    query: Dict[str, List[str]]
    headers: Dict[str, List[str]]
    contentBase64: str

    def get_content(self) -> bytes:
        return base64.b64decode(self.contentBase64)

    def set_content(self, content: bytes):
        self.contentBase64 = base64.b64encode(content).decode()


class ResponseModel(BaseModel):
    version: str
    statusCode: int
    reason: str
    headers: Dict[str, List[str]]
    contentBase64: str

    def get_content(self) -> bytes:
        return base64.b64decode(self.contentBase64)

    def set_content(self, content: bytes):
        self.contentBase64 = base64.b64encode(content).decode()


app = FastAPI()


@app.post("/hookRequestToBurp", response_model=RequestModel)
def hookRequestToBurp(request: RequestModel):
    request.set_content(aes_decrypt(get_encrypt_text(request.get_content())))
    return request


@app.post("/hookRequestToServer", response_model=RequestModel)
def hookRequestToServer(request: RequestModel):
    request.set_content(to_encrypt_body(aes_encrypt(request.get_content())))
    return request


@app.post("/hookResponseToBurp", response_model=ResponseModel)
def hookResponseToBurp(response: ResponseModel):
    response.set_content(aes_decrypt(get_encrypt_text(response.get_content())))
    return response


@app.post("/hookResponseToClient", response_model=ResponseModel)
def hookResponseToClient(response: ResponseModel):
    response.set_content(to_encrypt_body(aes_encrypt(response.get_content())))
    return response


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host="0.0.0.0", port=5000)
