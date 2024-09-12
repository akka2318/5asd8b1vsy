import json
import re

from Crypto.Cipher import AES
import base64

from Crypto.Util.Padding import pad


def base64_encrypt(text):
    return base64.b64encode(text).decode('utf-8')


def AES_Cipher(url=None):
    key_data = {"words": [825307441, 825307441, 825307441, 825307441], "sigBytes": 16}

    if not url:
        url = input('输入URL：')
    index = url.find('bookDetail?')
    base64_str = url[index+len('bookdetail?')::]
    base64_str = base64.b64decode(base64_str).decode('utf-8')
    base64_str = json.loads(base64_str)
    ciphertext_b64 = base64_str['encrypt']
    iv_data = base64_str['iv']

    def convert_words_to_bytes(words, sigBytes):
        byte_array = []
        for word in words:
            byte_array.append((word >> 24) & 0xFF)
            byte_array.append((word >> 16) & 0xFF)
            byte_array.append((word >> 8) & 0xFF)
            byte_array.append(word & 0xFF)
        # 截取有效字节
        return bytes(byte_array[:sigBytes])

    key = convert_words_to_bytes(key_data["words"], key_data["sigBytes"])
    iv = convert_words_to_bytes(iv_data["words"], iv_data["sigBytes"])

    # 解码 base64
    ciphertext = base64.b64decode(ciphertext_b64)

    # 解密
    cipher = AES.new(key, AES.MODE_CBC, iv)
    decrypted_padded = cipher.decrypt(ciphertext)

    # 无填充模式
    try:
        cipher = AES.new(key, AES.MODE_CBC, iv)
        decrypted = cipher.decrypt(ciphertext)
        de = decrypted.rstrip(b'\x00').decode('utf-8', errors='ignore')

        numbers = re.findall(r'\d+', de)
        book_id = numbers[0]
        eisbn = numbers[1]

        return book_id, eisbn
    except ValueError:
        print("填充错误，可能是密钥、IV 或加密模式不正确。")


def AES_encrypt(plaintext):
    # AES对象
    key = b'1111111111111111'
    iv = b'1234567890123456'
    cipher = AES.new(key, AES.MODE_CBC, iv)
    padded_data = pad(plaintext, AES.block_size)
    # 加密
    ct_bytes = cipher.encrypt(padded_data)
    base64_str = base64_encrypt(ct_bytes)
    return base64_str