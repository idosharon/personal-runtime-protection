"""
    File: lib/ebpf.py
    Description: This file contains the eBPF program wrapper.
    Author: Ido Sharon
"""
from .utils.logger import Logger
from .utils.config import Config
import json
import re
import socket
from socket import inet_ntop, AF_INET
from threading import Thread
import time
from pathlib import Path
import queue
from struct import pack
import bcc
from .utils.consts import Consts

class EBPFProgram:
    """
    EBPFProgram is a wrapper for an eBPF program.
    """
    BOOT_TIME = time.time() - time.clock_gettime(time.CLOCK_BOOTTIME)

    def __init__(self, src_file: Path, ebpf_config: dict, host: str = "localhost", port: int = 1234):
        """
        src_file: Path to the eBPF source file
        ebpf_config: Configuration for the eBPF program
        host: Host to send the events to
        port: Port to send the events to
        """
        try:
            # connect to server
            Logger.info(f"Connecting to {host}:{port}...")
            self._client = socket.socket(family=socket.AF_INET, type=socket.SOCK_DGRAM)
            self._client.connect((host, port))

            # load config
            self._syscall = ebpf_config.get("syscall", src_file.stem)
            self._attach_types = ebpf_config.get("types", [])

            # set source file
            self.src_file = src_file

            # set filters
            filters = ebpf_config.get("filters", {})
            self._ignored_values = filters.get("ignored_values", [])
            self._ignored_processes = filters.get("ignored_processes", [])
            self._only_uids = filters.get("only_uids", [1000])

            # set value type
            self._value_type = ebpf_config.get("value_type", "string")

            # load eBPF program
            self._bpf = bcc.BPF(src_file=self.src_file.as_posix(),
                            cflags=["-Wno-everything"])

            # start sending thread
            self._sending_queue = queue.Queue()
            self._sending_thread = Thread(target=self._sending_thread, daemon=True)
            self._sending_thread.start()

            # start polling thread
            self._poll_loop_thread = Thread(target=self._buffer_poll_loop, daemon=True)

            if not ebpf_config.get("auto_attach", False):
                # attach manually, if auto_attach is False in the config
                # get event name from syscall
                event_name = self._bpf.get_syscall_fnname(self._syscall)
                Logger.info(f"Attaching to {self._attach_types} {event_name}...")

                # attach to event
                for attach_type in self._attach_types:
                    if attach_type == "kprobe":
                        self._bpf.attach_kprobe(event=event_name, fn_name=f"syscall__kprobe_{self._syscall}")
                    elif attach_type == "kretprobe":
                        self._bpf.attach_kretprobe(event=event_name, fn_name=f"syscall__kretprobe_{self._syscall}")
                    else: 
                        raise Exception(f"Invalid attach type: {attach_type}")

            # start callback 
            self.attach_callback()
            Logger.info("🐙 Loaded eBPF program from file")
        except Exception as e:
            Logger.error(f"Failed to load eBPF program from file: {src_file} - {e}")
            
    def _send(self, event):
        """
        Send an event to the Manager
        """
        try:
            self._client.send(event)
        except Exception as e:
            Logger.error(f"Failed to send event: {e}")

    def _sending_thread(self):
        """
        Sending thread
        """
        Logger.info("Starting queue thread...")
        while True:
            if event := self._sending_queue.get():
                try:
                    event = self._event_to_dict(event)
                    # filter events
                    if not self._filter_event(event):
                        self._send(json.dumps({
                                    "syscall": self._syscall,
                                    "data": event
                                }).encode("utf-8"))
                except Exception as e:
                    Logger.error(f"Failed to parse event data: {e}")

    def _parse_value(self, value: bytes) -> str:
        """
        Parse the value according to the value type
        """
        try:
            if self._value_type == "string":
                return value.decode("utf-8")
            elif self._value_type == "ipv4":
                return inet_ntop(AF_INET, pack("I", value))
            else:
                Logger.error(f"Invalid value type: {self._value_type}")
        except Exception:
            return "[Unknown]"

    def _parse_process_name(self, value: bytes) -> str:
        try:
            return value.decode("utf-8").strip()
        except Exception:
            return "[Unknown]"

    def _event_to_dict(self, event) -> dict:
        """
        Translate eBPF event to dict
        """
        return {
            "ts": self.BOOT_TIME + event.ts / 1e9,
            "pid": event.pid,
            "ppid": event.ppid,
            "uid": event.uid,
            "process": self._parse_process_name(event.process),
            "value": self._parse_value(event.value),
        }
    
    def _filter_event(self, event: dict) -> bool:
        """
        Filter events by filter rules from config
        """
        if event["process"] in self._ignored_processes:
            return True
        if event["uid"] not in self._only_uids:
            return True
        return any(re.match(value, event["value"]) for value in self._ignored_values)

    def callback(self, cpu, data, size):
        """
        Callback function called for each event received from the eBPF program 
        """
        try:
            self._sending_queue.put(self._bpf[self._syscall].event(data))
        except Exception as e:
            Logger.error(f"Failed to get event from ebpf: {e}")

    def _buffer_poll_loop(self):
        """
        Polling loop for perf buffer
        """
        while True:
            try:
                # poll perf buffer
                self._bpf.perf_buffer_poll()
            except KeyboardInterrupt:
                break

    def attach_callback(self):
        """
        Attach callback to eBPF program and start polling loop
        """
        self._bpf[self._syscall].open_perf_buffer(self.callback)
        self._poll_loop_thread.start()
    
class EBPFLoader:
    """
        eBPF loader class for loading eBPF programs from folder & config, and attaching them to the kernel
    """
    def __init__(self, folder: Path, config_path: Path = None, host: str = "localhost", port: int = 1234):
        # init variables
        self._host = host
        self._port = port

        self._programs = []
        self._folder = folder
        if not self._folder.exists():
            raise FileNotFoundError(f"Programs folder not found: {self._folder}")
        
        # load config using Config class
        config_file = (self._folder / Consts.CONFIG_FILE_NAME)
        if config_path is not None and config_path.exists():
            config_file = config_path
        self.config = Config(config_file=config_file)

    def attach_programs(self):
        """
        Attach all loaded programs
        """
        # for each program, attach it to the kernel
        for src_file, ebpf_config in self.config.programs_config.items():
            # check if file is verified
            if not self.config.verify_file(src_file):
                raise ValueError(f"File {src_file} is not verified")
            Logger.info(f"🥳 {src_file} is verified!")

            # attach program by creating EBPFProgram object
            self._programs.append(EBPFProgram(src_file=src_file, ebpf_config=ebpf_config,
                                              host=self._host, port=self._port))
