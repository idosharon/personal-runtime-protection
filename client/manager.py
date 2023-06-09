import threading
from pathlib import Path

from .remote import Remote
from .ebpf import EBPFProgram, EBPFLoader
import socket
from threading import Thread


class Manager:
    def __init__(self, server_ip: str, server_port: int, programs_folder: str = None, config_file: str = None):
        self._socket = socket.socket(family=socket.AF_INET, type=socket.SOCK_DGRAM)
        self._socket.bind(("127.0.0.1", 0))

        self._host, self._port = self._socket.getsockname()
        print(f"Listening on {self._host}:{self._port}")
        threading.Thread(target=self._listen).start()

        self._remote = Remote(server_ip, server_port)

        self.EBPFLoader = EBPFLoader(folder=Path(programs_folder), host=self._host, port=self._port)
        self.EBPFLoader.attach_programs()

        # TODO: separate to functions

    def _listen(self):
        while True:
            data, addr = self._socket.recvfrom(1024)
            print(f"Received {data} from {addr}")

    def getPort(self):
        return self._socket.getsockname()[1]

    # def add_program(self, ppath):
    #     program = EBPFProgram(ppath)
    #     self._programs.append(program)

    # def begin(self):
    #     for program in self._programs:
    #         program.attach()
