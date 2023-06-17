import base64, json
from socketio import Client
import requests
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
import zlib

class OnlineClient(Client):
    PROTOCOL = "http"

    def __init__(self, ip, port, encrypted=False):
        super().__init__()
        self._remote_url = f"{self.PROTOCOL}://{ip}:{port}"
        try:
            if encrypted:
                # request public key from server
                rsa_public_key = requests.get(f"{self._remote_url}/public-key").text
                rsa_public_key = RSA.importKey(rsa_public_key)
                rsa_public_key = PKCS1_OAEP.new(rsa_public_key)
                self._encryption_key = rsa_public_key
            else:
                self._encryption_key = None

        except Exception as e:
            raise e

    def connect(self):
        super().connect(self._remote_url)


    def send(self, data):
        try:
            if self._encryption_key:
                data = self._encryption_key.encrypt(data)
            else:
                pass
                # data = base64.b64encode(data)

            super().emit('event', data)
        except Exception as e:
            print("Failed to send data: ", e)

