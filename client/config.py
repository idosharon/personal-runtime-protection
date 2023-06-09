import hashlib
import json
from pathlib import Path
from .logger import Logger


class Config:
    ALLOWED_EXTENSIONS = [".c"]
    CONFIG_FILE_NAME = "config.json"
    _encryption = hashlib.sha256
    _encoding = "utf-8"

    def __init__(self, config_file: Path):
        if not config_file.exists():
            raise FileNotFoundError(f"Config file not found: {config_file}")
        try:
            self.programs_config = {}
            config_folder = config_file.parent
            parsed_config = json.load(config_file.open("r"))
            # TODO: Move consts to another consts file
            ebpfs_config = parsed_config.get("ebpf_config", None)
            if ebpfs_config is None:
                raise Exception(f"No eBPF parsed_config in {config_file}")
            else:
                self.programs_folder = (config_folder / ebpfs_config.get("folder", "ebpfs"))
                self.programs_folder.mkdir(parents=True, exist_ok=True)

                for filename, program_config in ebpfs_config.get("files", {}).items():
                    current_file = (self.programs_folder / filename)
                    if self.allowed_file(current_file):
                        self.programs_config[current_file] = program_config
                    else:
                        # warning file is skipped
                        Logger.warning(f"File {current_file} not found")
        except json.JSONDecodeError:
            raise ValueError(f"Signatures file is not a valid json file: {config_file}")

    @classmethod
    def _get_file_hash(cls, file_path: Path) -> str:
        if not file_path.exists():
            raise FileNotFoundError(f"File not found: {file_path}")
        return cls._encryption(file_path.read_text().encode(cls._encoding)).hexdigest()

    @classmethod
    def allowed_file(cls, file_path: Path) -> bool:
        return file_path.exists() and file_path.suffix in cls.ALLOWED_EXTENSIONS

    def verify_file(self, file_path: Path) -> bool:
        # TODO: create signatures and fix function when done
        return True
        if file_path.exists():
            sig = self.allowed_signatures.get(str(file_path.name), None)
            if sig is not None:
                return sig == self._get_file_hash(file_path)
        return False


if __name__ == "__main__":
    p = Path("src/helloworld.c")
    print(p.read_text("utf-8"))
