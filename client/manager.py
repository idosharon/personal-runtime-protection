from queue import Queue
import threading
from pathlib import Path
import base64
import json

from .client import OnlineClient
from .ebpf import EBPFLoader
import socket
from threading import Thread


class Manager:
    """
    Manager is a client that listens to events from the kernel and sends them to the server.
    """
    def __init__(self, server_ip: str, server_port: int, programs_folder: str = None, config_file: str = None):
        self._socket = socket.socket(family=socket.AF_INET, type=socket.SOCK_DGRAM)
        self._socket.bind(("127.0.0.1", 0))

        self._host, self._port = self._socket.getsockname()
        print(f"Manager started listen: {self._host}:{self._port}")
        threading.Thread(target=self._listen).start()

        self._client = OnlineClient(server_ip, server_port)
        self._client.connect()

        # start sending thread
        self._sending_queue = Queue()
        self._sending_thread = threading.Thread(target=self._sending_thread)
        self._sending_thread.start()

        self.EBPFLoader = EBPFLoader(folder=Path(programs_folder), host=self._host, port=self._port)
        self.EBPFLoader.attach_programs()

    def _sending_thread(self):
        print("Starting queue thread...")
        while True:
            if event := self._sending_queue.get():
                self._client.send(event)

    def _listen(self):
        while True:
            event, addr = self._socket.recvfrom(1024)
            self._sending_queue.put(event)

    def getPort(self):
        return self._socket.getsockname()[1]
