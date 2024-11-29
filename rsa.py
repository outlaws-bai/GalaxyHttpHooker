import json
import base64
import typing as t
from fastapi import FastAPI
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_v1_5
from _base_classes import *


publicKey1Base64 = "MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQC7JoQAWLsovzHjaUMZg2lwO4LCuP97mitUc4chqRlQD3NgyCWLqEnYyM+OJ7i6cyMuWLwGtMi29DoKLjpE/xRZR0OUk46PDCAtyDgIyejK7c7KlZTbiqb4PtiJNLZgg0UP62kLMycnpY/wg/R2G9g+7MiJWUV5SR+Lhryv8CWezQIDAQAB"
privateKey1Base64 = "MIICdQIBADANBgkqhkiG9w0BAQEFAASCAl8wggJbAgEAAoGBALsmhABYuyi/MeNpQxmDaXA7gsK4/3uaK1RzhyGpGVAPc2DIJYuoSdjIz44nuLpzIy5YvAa0yLb0OgouOkT/FFlHQ5STjo8MIC3IOAjJ6MrtzsqVlNuKpvg+2Ik0tmCDRQ/raQszJyelj/CD9HYb2D7syIlZRXlJH4uGvK/wJZ7NAgMBAAECgYAhgbhRbZF4rp6Kdh6e00HN58G2BjQrl4MZeCOh+aoABPwlwD/EnMk36GAMtfzjWNjcI+PqGXT0GI7JotQo5ThpoweXX/uoeGOW+UkYLA6a67lmxfoZsDtY2+jnaWIs2c7Itz3ClRxo4tYwCoPNjtaBpMfPgZaYg2QN8/wLQPI66wJBAM0xpjb2OlLDs75lVxbm6v6Dx3YBS20GSqJqvf+14a/k7mrZ3PmAHOfqTqKOwbVQJmLbeOpU+sUBpeLpILKOCLcCQQDpfSsDhdosC6qTL9XnF2jS49iws2RBKw5YjDkClwA6VMNj5uzL1Rl7/AimLRMnB4BwrD95ksuOJsqNXW6wRGibAkAkk28PaQCodB38GFBX0r2ctJy/Wie5vV9caC6KAD/EfMhK357WEpIUfN2beFrrGOhewsRg8NjqeQq60dd0PIEtAkBYAm03O7n8Bj26kzpejA1gCLBCEqyEf/U9XUWT+1UDp7Wqr32sa1vaxyp/cNgaSxKX5eVbLwD5SRfqZ0B0wqRnAkATpUNiCqjQVS+OI5dwjoI1Rx3oI8pyKWOg3+QIHIRgL3pc8HLdZ2BkX4Vf6ANb4+noQnD/di1Mj+0pUL8RhIJE"
publicKey2Base64 = "MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCrfqYv278oDvreohZeR+UMiNSJC2FG4u8dSNC/hj88lw7eULQOiuUnsZ4eineeFOquXckjhkh1AJsd87+Nz1ZQB61dY3NmVR5Tk+2wH/kNdiVCoRrbULs29Tms17IyrZZU9WQFQbBxC/g6n5zwp6ST/siGRfHAwVVbq+iccQfdpwIDAQAB"
privateKey2Base64 = "MIICdgIBADANBgkqhkiG9w0BAQEFAASCAmAwggJcAgEAAoGBAKt+pi/bvygO+t6iFl5H5QyI1IkLYUbi7x1I0L+GPzyXDt5QtA6K5Sexnh6Kd54U6q5dySOGSHUAmx3zv43PVlAHrV1jc2ZVHlOT7bAf+Q12JUKhGttQuzb1OazXsjKtllT1ZAVBsHEL+DqfnPCnpJP+yIZF8cDBVVur6JxxB92nAgMBAAECgYAghb2lcNKBGcooo2uDiLXe2SoZLT/O7iVzk8YGtEJUzr7imUJ0SZHoo639U7wYjhXtaFrHMmWWTr2cAggvMAVJi5fZYYJLbYdc8O5QCKi6PzV2J2NxYyuABL5yarvy4Ji0twnDjlqBYqrjOsxJbeMv58CHLKqduIZuxppGGOoRQQJBANTV3JEg6xJdPXsF9ztOf03BNkvpibuUSNbTssTdzEtLMQW7zd5y1qTCwUbf+e2UsRIYPn5DwOlTu8SaE97Zz8ECQQDORm7szA0WL1OTYob0U1NSSFDn8Jg7FyX5md6ndL3KNTKBDBfe3hNpauLi01lTMbO3MoriOWsFiN++6dZAdwdnAkEAq6PcwN1/Ncwj7Lae7yEa4SXUF9w6yx+GrlkDbmhAfOginLEcES0jlLPLEtFFySeEtUb//uu9A24XmzF2nN2jAQJABgL7fJ89ymW6s9LtR/WdugotgXT7ms1D6BBZ8ttuJJSEUkp975rdSfc5gY7TTZ9nM3GfppQx0El66994xQwzBQJAct1HPeCVROxyEHNwsiRH9wqR5P4B59Mo1714R7ozsdTpVx8FWmqi+OQIJt+IizYgRyQ09qORAFei9AHeQtxKiw=="
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
    print(encrypted_data, data)
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
    rsa_key = RSA.import_key(secret)
    cipher = PKCS1_v1_5.new(rsa_key)
    decrypted_data = cipher.decrypt(content, 0)
    assert isinstance(decrypted_data, bytes)
    return decrypted_data


def encrypt(content: bytes, secret: bytes) -> bytes:
    rsa_key = RSA.import_key(secret)
    cipher = PKCS1_v1_5.new(rsa_key)
    return cipher.encrypt(content)


def get_data(content: bytes) -> bytes:
    body_json: t.Dict = json.loads(content)
    return base64.b64decode(body_json[JSON_KEY])


def to_data(contnet: bytes) -> bytes:
    body_json = {}
    body_json[JSON_KEY] = base64.b64encode(contnet).decode()
    return json.dumps(body_json).encode()


if __name__ == "__main__":
    # 多进程启动
    # uvicorn rsa:app --host 0.0.0.0 --port 5000 --workers 4
    import uvicorn

    uvicorn.run(app, host="0.0.0.0", port=5000)
