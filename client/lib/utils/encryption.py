import json
import zlib
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP, AES
import requests
# base64 encoding
from base64 import b64encode, b64decode
from Crypto.Util.Padding import pad

class Encryption:
    """
    This class is used to encrypt data using RSA public key
    """
    PUBLIC_KEY_PATH = "/api/public-key"

    def __init__(self, server_url: str):
        self._keys = self.generate_rsa_key_pair(2048)
        self.__decryptor = PKCS1_OAEP.new(self._keys[0])
        
        # get AES key from server
        self.__aes_key = self.get_aes_key(server_url + self.PUBLIC_KEY_PATH)

        # create AES encryptor
        self.__encryptor = AES.new(self.__aes_key, AES.MODE_CBC)

    @classmethod
    def generate_rsa_key_pair(cls, key_size):
        # Generate a new RSA key pair
        key = RSA.generate(key_size)
        private_key = key
        public_key = key.publickey()
        
        return (private_key, public_key)

    def get_aes_key(self, public_key_url: str):
        response = requests.get(public_key_url, {
            "pem": b64encode(self._keys[1].export_key()),
        }, headers={
            "Content-Type": "application/json",
        })
        if response.status_code != 200:
            raise Exception("Error getting AES key from server")

        response = b64decode(response.json()["aes_key"])
        return self.decrypt(response)
    
    def encrypt(self, data: bytes):
        return self.__encryptor.encrypt(data)
    
    def decrypt(self, data: bytes):
        return self.__decryptor.decrypt(data)

    def aes_encrypt_msg(self, data: bytes):
        padded_data = pad(data, AES.block_size)
        return self.encrypt(padded_data)



if __name__ == "__main__":
    # Generate a new RSA key pair
    e = Encryption("http://localhost:5000")
