import enum
import json
import logging
import base64
import socket
import threading
import time
from pathlib import Path
import psutil
import queue

from bcc import BPF

from .logger import Logger
from .config import Config


class EBPFProgram:
    CHUNK_SIZE = 10

    # TODO: generate header file from this
    class EventType:
        EVENT_ARG = 0
        EVENT_RET = 1

    def __init__(self, src_file: Path, ebpf_config: dict, host: str = "localhost", port: int = 1234):
        try:
            # connect to socket of manager
            Logger.info(f"Connecting to {host}:{port}...")
            self._client = socket.socket(family=socket.AF_INET, type=socket.SOCK_DGRAM)
            self._client.connect((host, port))

            print("compiling ebpf program...")

            self.src_file = src_file
            self.header_file = ebpf_config.get("header", "")
            if self.header_file:
                self.header_file = (src_file.parent / self.header_file)
                if not self.header_file.is_file():
                    Logger.warning(f"Header file not found: {self.header_file}")
                else:
                    self._generate_header()

            self._bpf = BPF(src_file=str(self.src_file),
                            hdr_file=str(self.header_file),
                            cflags=["-Wno-everything"])

            # threading.Thread(target=self._pull_events_thread).start()

            self._sending_queue = queue.Queue()
            self._sending_thread = threading.Thread(target=self._sending_thread)
            self._sending_thread.start()

            self._events = {}
            self.start_ts = time.time()

            for fn in ebpf_config.get("functions", [{}]):
                try:
                    Logger.info(f"Attaching {fn['type']}: {self._bpf.get_syscall_fnname(fn['syscall'])} {fn['name']}")

                    function_name, event_name = fn["name"], self._bpf.get_syscall_fnname(fn["syscall"])

                    if fn['type'] == "kprobe":
                        self._bpf.attach_kprobe(event=event_name, fn_name=function_name)
                    elif fn['type'] == "kretprobe":
                        self._bpf.attach_kretprobe(event=event_name, fn_name=function_name)
                    else:
                        raise Exception(f"Unknown type: {fn['type']}")

                    self._events[fn["syscall"]] = {}
                    self.attach_callback(fn["syscall"])
                except Exception as e:
                    Logger.warning(e)
                    continue

            print("🐙 Loaded eBPF program from file: ", src_file)

        except Exception as e:
            print(f"Failed to compile ebpf program: {e}")

    # function that sends a given data chunk to server using a socket
    def _send(self, data: bytes):
        try:
            self._client.send(data)
        except Exception as e:
            Logger.error(e)

    def _sending_thread(self):
        print("Starting queue thread...")
        while True:
            data = self._sending_queue.get()
            if data:
                print("sending data: {}".format(data))
                self._send(data)

    def _generate_callback(self, syscall):
        def callback(cpu, data, size):
            try:
                event = self._bpf[f"{syscall}"].event(data)

                print("event: ", event.type)

                if event.type == self.EventType.EVENT_ARG:
                    pid = event.pid

                    if pid in self._events[syscall].keys():
                        self._events[syscall][pid]["args"].append(event.argv.decode("utf-8"))
                    else:
                        self._events[syscall][pid] = {
                            "ts": event.ts,
                            "since": time.time() - self.start_ts,
                            "ppid": event.ppid,
                            "uid": event.uid,
                            "comm": event.comm,
                            "path": event.path.decode("utf-8"),
                            "args": [event.argv.decode("utf-8")] if event.argv else [],

                            # TODO: maybe in future
                            #  "cpu": cpu,
                            # "size": size,
                        }

                elif event.type == self.EventType.EVENT_RET:
                    self._sending_queue.put(
                        json.dumps({
                            "type": syscall,
                            "ret": event.return_value,
                            "data": json.dumps(self._events[syscall])
                        }).encode("utf-8"))

                    self._events[syscall] = {}


            except Exception as e:
                Logger.error(e)
                return

        return callback

    def attach_callback(self, syscall: str):
        self._bpf[f"{syscall}"].open_perf_buffer(self._generate_callback(syscall))
        while True:
            try:
                self._bpf.perf_buffer_poll()
            except KeyboardInterrupt:
                exit()

    def clean(self):
        self._bpf.cleanup()

    def _generate_header(self):
        # wrtie header file
        header = """
        enum event_type {
            EVENT_ARG = 0,
            EVENT_RET = 1,
        };"""

        with open(self.header_file, "w") as f:
            f.write(header)
            f.close()


class EBPFLoader:
    def __init__(self, folder: Path, config_path: Path = None, host: str = "localhost", port: int = 1234):
        self._programs = []
        self._folder = folder
        if not self._folder.exists():
            raise FileNotFoundError(f"Programs folder not found: {self._folder}")

        config_file = (self._folder / Config.CONFIG_FILE_NAME)
        if config_path is not None and config_path.exists():
            config_file = config_path

        self.config = Config(config_file=config_file)

        self._host = host
        self._port = port

    def attach_programs(self):
        for src_file, ebpf_config in self.config.programs_config.items():
            if not self.config.verify_file(src_file):
                raise ValueError(f"File {src_file} is not verified")
            Logger.info(f"🥳 {src_file} is verified!")
            self._programs.append(EBPFProgram(src_file=src_file, ebpf_config=ebpf_config,
                                              host=self._host, port=self._port))
