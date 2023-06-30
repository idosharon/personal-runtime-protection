"""
    File: client.py
    Description: This file contains the client class.
    Author: Ido Sharon
"""
from base64 import b64encode
import json
from socketio import Client
from .utils.encryption import Encryption
from .utils.logger import Logger

class OnlineClient(Client):
    """
        This class represents the online client, and it inherits from the socketio client.
        It is used to send data to the server, and it can be encrypted.    
    """
    PROTOCOL = "http"

    def __init__(self, ip, port):
        # init socketio client
        super().__init__(reconnection=False)
        # set ip, port and remote url
        self._ip, self._port, self._remote_url = ip, port, f"{self.PROTOCOL}://{ip}:{port}"
        try:
            self._encryptor = Encryption(self._remote_url)
        except Exception as e:
            raise ValueError(f"Failed to create encryptor - {e}") from e

    def connect(self):
        """
            Connect to the server using the socketio client connect method
        """
        try:
            # connect to the server
            super().connect(self._remote_url)
        except Exception as e:
            raise ConnectionError(f"Failed to connect to {self._remote_url} - {e}") from e

    def send(self, data: bytes):
        try:
            encrypted_data = self._encryptor.aes_encrypt_msg(data)
            super().emit('event', b64encode(encrypted_data).decode('utf-8'))
        except Exception as e:
            raise Exception(f"Failed to send data to {self._remote_url} - {e}") from e

