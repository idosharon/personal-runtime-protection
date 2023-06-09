class Logger:
    @staticmethod
    def debug(msg):
        print("DEBUG:", msg)

    @staticmethod
    def info(msg):
        print("INFO:", msg)

    @staticmethod
    def warning(msg):
        print(f"\033[33mWarning: {msg}\033[0m")

    @staticmethod
    def error(msg):
        print(f"\033[91mERROR: {msg}\033[39m")