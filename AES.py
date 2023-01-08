from Crypto.Cipher import AES
from Crypto import Random


def aes_en(key: bytes, data: bytes) -> bytes:
    cipher = AES.new(key, AES.MODE_OFB, b'1234567887654321')
    return cipher.encrypt(data)


def aes_de(key: bytes, data: bytes) -> bytes:
    decoder = AES.new(key, AES.MODE_OFB, b'1234567887654321')
    return decoder.decrypt(data)


def get_key() -> bytes:
    return Random.new().read(16)
