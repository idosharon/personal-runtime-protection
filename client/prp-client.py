"""
    PRP (Personal Runtime Protection) client - a tool for monitoring and protecting your system.
"""
from lib import Manager, Logger
import argparse
from os import geteuid

# parse all arguments
argparser = argparse.ArgumentParser(description=
                                    """
                                    PRP (Personal Runtime Protection) client - a tool for monitoring and protecting your system.
                                    """)

argparser.add_argument("--programs-folder", type=str, default="./", help="Folder with eBPF programs")
argparser.add_argument("--config-file", type=str, default=None, help="Config file path")
argparser.add_argument("--server-ip", type=str, default="127.0.0.1", help="Server IP address")
argparser.add_argument("--server-port", type=int, default=3000, help="Server port")
argparser.add_argument("--debug", action="store_true", help="Enable debug mode")

args = argparser.parse_args()

# set logger level to debug if debug mode is enabled
if args.debug:
    Logger.set_level(Logger.Levels.DEBUG)

# check if program is run as root
if geteuid() != 0:
    Logger.error("Program must be run as root")
else:
    # start manager
    Logger.info("Starting PRP client...\n press Ctrl+C to stop")
    Logger.info(f"Server IP: {args.server_ip} Port: {args.server_port}")

    try:
        manager = Manager(server_ip=args.server_ip, server_port=args.server_port, 
                        programs_folder=args.programs_folder, config_file=args.config_file)
        manager.start()
        # wait for Ctrl+C
        manager.wait()
    except KeyboardInterrupt:
        pass
    except Exception as e:
        Logger.error(f"{e}")
    
    Logger.info("Stopping PRP client...")
    exit(1)
    
