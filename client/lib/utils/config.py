"""
    File: utils/config.py
    Description: This file contains the config class.
    Author: Ido Sharon
"""
from .logger import Logger
from .consts import Consts
from pathlib import Path
import hashlib
import json

class Config:
    """
    Config is a wrapper for the config file, used to read the config file and verify the eBPF programs.
    """
    ALLOWED_EXTENSIONS = [".c"]
    _encryption = hashlib.sha256
    _encoding = "utf-8"

    def __init__(self, config_file: Path):
        """
        Create a new config object from a config file.
        """
        if not config_file.exists():
            raise FileNotFoundError(f"Config file not found: {config_file}")
        try:
            # Create a new empty programs config
            self.programs_config = {}
            self.allowed_signatures = {}
            # Parse the config file to a json object
            parsed_config = json.load(config_file.open("r"))
            # Get the eBPF config from the json object
            ebpfs_config = parsed_config.get(Consts.EBPF_CONFIG_KEY, None)
            if ebpfs_config is None:
                raise FileNotFoundError(f"No eBPF config in {config_file}")
            
            # Get the config folder
            config_folder = config_file.parent
            # Get the programs folder from the eBPF config and create it if it doesn't exist
            self.programs_folder = (config_folder / ebpfs_config.get(Consts.CONFIG_FOLDER_KEY, "ebpfs"))
            self.programs_folder.mkdir(parents=True, exist_ok=True)

            # Iterate over the files in the eBPF config
            for filename, program_config in ebpfs_config.get("files", {}).items():
                # Get the current file path
                current_file = (self.programs_folder / filename)
                # Check if the file is allowed
                if self.allowed_file(current_file):
                    # Add the current file to the programs config
                    self.programs_config[current_file] = program_config
                    self.allowed_signatures[current_file.name] = program_config.get("signature", None)
                else:
                    Logger.warning(f"File {current_file} not found")
        except Exception as e:
            raise Exception(
                f"Config file is not valid: {e}"
            ) from e

    @classmethod
    def get_file_hash(cls, file_path: Path) -> str:
        """
        get_file_hash is a static method that returns the hash of a file.
        """
        if not file_path.exists():
            raise FileNotFoundError(f"File not found: {file_path}")
        return cls._encryption(file_path.read_text().encode(cls._encoding)).hexdigest()

    @classmethod
    def allowed_file(cls, file_path: Path) -> bool:
        """
        allowed_file is a static method that returns true if the file name is allowed.
        """
        return file_path.exists() and file_path.suffix in cls.ALLOWED_EXTENSIONS

    def verify_file(self, file_path: Path) -> bool:
        """
        verify_file is a method that returns true if the file is verified.
        """
        if file_path.exists():
            sig = self.allowed_signatures.get(str(file_path.name), None)
            if sig is not None:
                return sig == self.get_file_hash(file_path)
        return False
