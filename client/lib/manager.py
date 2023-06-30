from queue import Queue
from pathlib import Path
from .client import OnlineClient
from .ebpf import EBPFLoader
import socket
from threading import Thread
from .utils.logger import Logger
from time import sleep

class Manager:
    """
    Manager is a client that listens to events from the kernel and sends them to the server.
    """
    def __init__(self, server_ip: str, server_port: int, programs_folder: str, config_file: str = None):
        # save programs folder & config file
        self._programs_folder, self._config_file = Path(programs_folder), Path(config_file) if config_file else None
        if self._programs_folder and (not self._programs_folder.exists() or not self._programs_folder.is_dir()):
            raise FileNotFoundError(f"Folder {self._programs_folder} does not exist")
        if self._config_file and (not self._config_file.exists() or not self._config_file.is_file()):
            raise FileNotFoundError(f"File {self._config_file} does not exist")
        
        # start listening socket for eBPF programs events, using UDP protocol
        self._socket = socket.socket(family=socket.AF_INET, type=socket.SOCK_DGRAM)
        self._socket.bind(("127.0.0.1", 0))
        self._host, self._port = self._socket.getsockname()
        Logger.info(f"Manager socket started listen: {self._host}:{self._port}")

        # start listening thread
        Thread(target=self._listen, daemon=True).start()

        # connect to remote server using OnlineClient
        self._client = OnlineClient(server_ip, server_port)
        self._client.connect()

        # start sending queue thread
        self._sending_queue = Queue()
        self._sending_thread = Thread(target=self._sending_thread, daemon=True)
        self._sending_thread.start()

        self._is_running = True
    
    def start(self):
        """
        Start the manager - load eBPF programs and attach them, and start sending events to the server.
        """
        self.EBPFLoader = EBPFLoader(folder=self._programs_folder, config_path=self._config_file, host=self._host, port=self._port)
        self.EBPFLoader.attach_programs()
    
    def wait(self):
        """
        Wait for the manager to stop.
        """
        while self._is_running:
            sleep(1)
            
    def _sending_thread(self):
        """
        Sending thread - sends events to the server from the sending queue.
        """
        Logger.info("Starting queue thread...")
        while True:
            if event := self._sending_queue.get():
                try:
                    self._client.send(event)
                except Exception as e:
                    # check if server is still connected
                    if not self._client.connected:
                        self._client.disconnect()
                        Logger.error("Server is not connected, exiting...")
                        self._is_running = False
                        return
                    Logger.error(f"Error sending event {event} to server: {e}")

    def _listen(self):
        """
        Listen to events from the kernel over UDP socket and put them in the sending queue
        """
        while True:
            # receive event from kernel
            event, addr = self._socket.recvfrom(1024)
            self._sending_queue.put(event)
            Logger.debug(f"Received {event} from {addr}")
