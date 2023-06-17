import enum
import json
import logging
import socket
import threading
import time
from pathlib import Path
import psutil
import queue

from bcc import BPF

from .logger import Logger
from .config import Config


# each ebpf program is for a specific syscall
class EBPFProgram:
    # TODO: generate header file from this
    class EventType:
        EVENT_ARG = 0
        EVENT_RET = 1

    def __init__(self, src_file: Path, ebpf_config: dict, host: str = "localhost", port: int = 1234):
        # sourcery skip: raise-specific-error
        try:
            # connect to socket of manager
            Logger.info(f"Connecting to {host}:{port}...")
            self._client = socket.socket(family=socket.AF_INET, type=socket.SOCK_DGRAM)
            self._client.connect((host, port))

            self._syscall = ebpf_config.get("syscall", src_file.stem)
            self._attach_types = ebpf_config.get("types", [])

            self.src_file = src_file
            self.header_file = ebpf_config.get("header", "")
            if self.header_file:
                self.header_file = (src_file.parent / self.header_file)
                if not self.header_file.exists() or not self.header_file.is_file():
                    Logger.warning(f"Header file not found: {self.header_file}")
                # else:
                #     self._generate_header()

            Logger.info(f"Compiling {src_file}...")
            self._bpf = BPF(src_file=str(self.src_file),
                            cflags=["-Wno-everything"])
            
            self._sending_queue = queue.Queue()
            self._sending_thread = threading.Thread(target=self._sending_thread)
            self._sending_thread.start()

            self._poll_loop_thread = threading.Thread(target=self.buffer_poll_loop)

            self._events = {}
            self.start_ts = time.time()

            try:
                event_name = self._bpf.get_syscall_fnname(self._syscall)
                print(f"Attaching to {self._attach_types} {event_name}...")

                for attach_type in self._attach_types:
                    if attach_type == "kprobe":
                        self._bpf.attach_kprobe(event=event_name, fn_name=f"syscall__kprobe_{self._syscall}")
                    elif attach_type == "kretprobe":
                        self._bpf.attach_kretprobe(event=event_name, fn_name=f"syscall__kretprobe_{self._syscall}")
                    elif attach_type == "tracepoint":
                        self._bpf.attach_tracepoint(tp=f"syscalls:{self._syscall}", fn_name=f"syscall__tracepoint_{self._syscall}")
                    else: 
                        raise Exception(f"Invalid attach type: {attach_type}")

                # self._bpf.trace_print()
                self.attach_callback()

                print("🐙 Loaded eBPF program from file: ", src_file)

            except Exception as e:
                Logger.error(e)

        except Exception as e:
            print(f"Failed to compile ebpf program: {e}")

    def _send(self, event):
        try:
            self._client.send(event)
        except Exception as e:
            Logger.error(e)

    def _sending_thread(self):
        print("Starting queue thread...")
        while True:
            if event := self._sending_queue.get():
                self._send(event)

    def _event_to_dict(self, event) -> dict:
        return {
            "ts": event.ts,
            "since": time.time() - self.start_ts,
            "ppid": event.ppid,
            "uid": event.uid,
            "comm": event.comm.decode("utf-8"),
            "value": event.value.decode("utf-8"),
            "args": [event.argv.decode("utf-8")] if event.argv else [],
        }

    def callback(self, cpu, data, size):
        try:
            event = self._bpf[self._syscall].event(data)
            pid = event.pid

            if event.type == self.EventType.EVENT_ARG:
                if pid in self._events.keys():
                    if event.argv:
                        self._events[pid]["args"].append(event.argv.decode("utf-8"))
                else:
                    self._events[pid] = self._event_to_dict(event)
            elif event.type == self.EventType.EVENT_RET:
                if pid not in self._events.keys():
                    # Logger.warning(f"Missing event for pid {pid}")
                    self._events[pid] = self._event_to_dict(event)

                self._sending_queue.put(
                    json.dumps({
                        "syscall": self._syscall,
                        "pid": pid,
                        "ret": event.return_value,
                        "data": self._events[pid]
                    }).encode("utf-8"))

                del(self._events[pid])

        except Exception as e:
            Logger.error(e)
            print("Failed to parse event data: ", self._events)
            return

    def buffer_poll_loop(self):
        while True:
            try:
                self._bpf.perf_buffer_poll()
            except KeyboardInterrupt:
                break

    def attach_callback(self):
        self._bpf[self._syscall].open_perf_buffer(self.callback)
        self._poll_loop_thread.start()

    def clean(self):
        self._bpf.cleanup()

    def _generate_header(self):
        pass


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
