"""
    File: utils/logger.py
    Description: This file contains the logger class.
    Author: Ido Sharon
"""

class Logger:
    """
        This class is used to log messages to the console, with different levels and colors.
    """
    # current level
    LEVEL = 0
    
    # colors
    COLORS = {
        "white": "\033[0m",
        "red": "\033[91m",
        "yellow": "\033[33m",
        "blue": "\033[94m",
    }

    # levels
    class Levels:
        INFO = 0
        DEBUG = 1
        WARNING = 0
        ERROR = 0

    @staticmethod
    def set_level(level):
        Logger.LEVEL = level

    @staticmethod
    def colorize(msg, color):
        return Logger.COLORS[color] + msg + Logger.COLORS["white"]

    @staticmethod
    def log(msg, level, color="white"):
        if level <= Logger.LEVEL:
            print(Logger.colorize(msg, color))

    @staticmethod
    def info(msg):
        Logger.log(msg, Logger.Levels.INFO, "blue")

    @staticmethod
    def debug(msg):
        Logger.log(msg, Logger.Levels.DEBUG, "blue")

    @staticmethod
    def warning(msg):
        Logger.log(msg, Logger.Levels.WARNING, "yellow")

    @staticmethod
    def error(msg):
        Logger.log(msg, Logger.Levels.ERROR, "red")
        