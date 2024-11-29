import json
import base64
import typing as t
from fastapi import FastAPI
from gmssl import sm2
from _base_classes import *


publicKey1Base64 = "MFkwEwYHKoZIzj0CAQYIKoEcz1UBgi0DQgAEBv9Z+xbmSOH3W/V9UEpU1yUiJKNGh/I8EiENTPYxX3GujsZyKhuEUzxloKCATcNaKWi7w/yK3PxGONM4xvMlIQ=="
privateKey1Base64 = "MIGTAgEAMBMGByqGSM49AgEGCCqBHM9VAYItBHkwdwIBAQQgWmIprZ5a6TsqRUgy32J+F22AYIKl+14P4qlw/LPPCcagCgYIKoEcz1UBgi2hRANCAAQG/1n7FuZI4fdb9X1QSlTXJSIko0aH8jwSIQ1M9jFfca6OxnIqG4RTPGWgoIBNw1opaLvD/Irc/EY40zjG8yUh"
publicKey2Base64 = "MFkwEwYHKoZIzj0CAQYIKoEcz1UBgi0DQgAE/1kmIjlOfsqG9hN4b/O3hiSI91ErgVDeqB9YOgCFiUiFyPo32pCHh691zGnoAj0l/P132CyLgBeH6TUa/TrLUg=="
privateKey2Base64 = "MIGTAgEAMBMGByqGSM49AgEGCCqBHM9VAYItBHkwdwIBAQQgP8vW9tEh0dMP5gJNsol5Gyc6jvvgK1NRqOVg8VaLYVygCgYIKoEcz1UBgi2hRANCAAT/WSYiOU5+yob2E3hv87eGJIj3USuBUN6oH1g6AIWJSIXI+jfakIeHr3XMaegCPSX8/XfYLIuAF4fpNRr9OstS"
pub_key1 = base64.b64decode(publicKey1Base64)
pri_key1 = base64.b64decode(privateKey1Base64)
pub_key2 = base64.b64decode(publicKey2Base64)
pri_key2 = base64.b64decode(privateKey2Base64)
JSON_KEY = "data"
app = FastAPI()


@app.post("/hookRequestToBurp", response_model=RequestModel)
async def hook_request_to_burp(request: RequestModel):
    """HTTP请求从客户端到达Burp时被调用。在此处完成请求解密的代码就可以在Burp中看到明文的请求报文。"""
    # 获取需要解密的数据
    encrypted_data: bytes = get_data(request.content)
    # 调用函数解密
    data: bytes = decrypt(encrypted_data, pri_key1)
    # 更新body为已解密的数据
    request.content = data
    return request


@app.post("/hookRequestToServer", response_model=RequestModel)
async def hook_request_to_server(request: RequestModel):
    """HTTP请求从Burp将要发送到Server时被调用。在此处完成请求加密的代码就可以将加密后的请求报文发送到Server。"""
    # 获取被解密的数据
    data: bytes = request.content
    # 调用函数加密回去
    encryptedData: bytes = encrypt(data, pub_key1)
    # 将已加密的数据转换为Server可识别的格式
    body: bytes = to_data(encryptedData)
    # 更新body
    request.content = body
    return request


@app.post("/hookResponseToBurp", response_model=ResponseModel)
async def hook_response_to_burp(response: ResponseModel):
    """HTTP响应从Server到达Burp时被调用。在此处完成响应解密的代码就可以在Burp中看到明文的响应报文。"""
    # 获取需要解密的数据
    encryptedData: bytes = get_data(response.content)
    # 调用函数解密
    data: bytes = decrypt(encryptedData, pri_key2)
    # 更新body
    response.content = data
    return response


@app.post("/hookResponseToClient", response_model=ResponseModel)
async def hook_response_to_client(response: ResponseModel):
    """HTTP响应从Burp将要发送到Client时被调用。在此处完成响应加密的代码就可以将加密后的响应报文返回给Client。"""
    # 获取被解密的数据
    data: bytes = response.content
    # 调用函数加密回去
    encryptedData: bytes = encrypt(data, pub_key2)
    # 将已加密的数据转换为Server可识别的格式
    body: bytes = to_data(encryptedData)
    # 更新body
    response.content = body
    return response


def decrypt(content: bytes, secret: bytes) -> bytes:
    cipher = sm2.CryptSM2(
        parse_sm2_pri(secret),
        "",
        asn1=False,
    )
    decrypted_data = cipher.decrypt(content[1:])
    assert decrypted_data
    return decrypted_data


def encrypt(content: bytes, secret: bytes) -> bytes:
    cipher = sm2.CryptSM2(
        "",
        parse_sm2_pub(secret),
        asn1=False,
    )
    encrypted_data = cipher.encrypt(content)
    assert encrypted_data
    return b"\x04" + encrypted_data


def get_data(content: bytes) -> bytes:
    body_json: t.Dict = json.loads(content)
    return base64.b64decode(body_json[JSON_KEY])


def to_data(contnet: bytes) -> bytes:
    body_json = {}
    body_json[JSON_KEY] = base64.b64encode(contnet).decode()
    return json.dumps(body_json).encode()


if __name__ == "__main__":
    # 多进程启动
    # uvicorn sm2:app --host 0.0.0.0 --port 5000 --workers 4
    import uvicorn

    uvicorn.run(app, host="0.0.0.0", port=5000)
