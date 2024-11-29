import json
import base64
import typing as t
from fastapi import FastAPI
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from _base_classes import *


KEY = b"32byteslongsecretkeyforaes256!aa"
IV = b"16byteslongiv456"
JSON_KEY = "data"
app = FastAPI()


@app.post("/hookRequestToBurp", response_model=RequestModel)
async def hook_request_to_burp(request: RequestModel):
    """HTTP请求从数据客户端到达Burp时被调用。在此处完成请求解密的代码就可以在Burp中看到明文的请求报文。"""
    # 获取需要解密的数据
    encrypted_data: bytes = base64.b64decode(request.query["username"][0].encode())
    # 调用函数解密
    data: bytes = decrypt(encrypted_data)
    # 更新query
    request.query["username"] = [data.decode()]
    return request


@app.post("/hookRequestToServer", response_model=RequestModel)
async def hook_request_to_server(request: RequestModel):
    """HTTP请求从Burp将要发送到Server时被调用。在此处完成请求加密的代码就可以将加密后的请求报文发送到Server。"""
    # 获取被解密的数据
    data: bytes = request.query["username"][0].encode()
    # 调用函数加密回去
    encryptedData: bytes = encrypt(data)
    # 更新query
    request.query["username"] = [base64.b64encode(encryptedData).decode()]
    return request


@app.post("/hookResponseToBurp", response_model=ResponseModel)
async def hook_response_to_burp(response: ResponseModel):
    """HTTP响应从Server到达Burp时被调用。在此处完成响应解密的代码就可以在Burp中看到明文的响应报文。"""
    # 获取需要解密的数据
    encryptedData: bytes = get_data(response.content)
    # 调用函数解密
    data: bytes = decrypt(encryptedData)
    # 更新body
    response.content = data
    return response


@app.post("/hookResponseToClient", response_model=ResponseModel)
async def hook_response_to_client(response: ResponseModel):
    """HTTP响应从Burp将要发送到Client时被调用。在此处完成响应加密的代码就可以将加密后的响应报文返回给Client。"""
    # 获取被解密的数据
    data: bytes = response.content
    # 调用函数加密回去
    encryptedData: bytes = encrypt(data)
    # 将已加密的数据转换为Server可识别的格式
    body: bytes = to_data(encryptedData)
    # 更新body
    response.content = body
    return response


def decrypt(content: bytes) -> bytes:
    cipher = AES.new(KEY, AES.MODE_CBC, IV)
    return unpad(cipher.decrypt(content), AES.block_size)


def encrypt(content: bytes) -> bytes:
    cipher = AES.new(KEY, AES.MODE_CBC, IV)
    return cipher.encrypt(pad(content, AES.block_size))


def get_data(content: bytes) -> bytes:
    body_json: t.Dict = json.loads(content)
    return base64.b64decode(body_json[JSON_KEY])


def to_data(contnet: bytes) -> bytes:
    body_json = {}
    body_json[JSON_KEY] = base64.b64encode(contnet).decode()
    return json.dumps(body_json).encode()


if __name__ == "__main__":
    # 多进程启动
    # uvicorn aes_cbc_query:app --host 0.0.0.0 --port 5000 --workers 4
    import uvicorn

    uvicorn.run(app, host="0.0.0.0", port=5000)
