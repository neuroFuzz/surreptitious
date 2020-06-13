'''
    Taken from:

        https://github.com/realgam3/pymultitor

    and modified for our purposes here
'''
import logging
import socket
from os import path
from shutil import rmtree
from tempfile import mkdtemp
from stem.control import Controller, Signal
from stem.process import launch_tor_with_config


logging.getLogger("stem").disabled = True


class Tor(object):
    def __init__(self, cmd='tor', log_file=''):
        self.logger = logging.getLogger(log_file)
        self.tor_cmd = cmd
        self.socks_port = self.free_port()
        self.control_port = self.free_port()
        self.data_directory = mkdtemp()
        self.id = self.socks_port
        self.process = None
        self.controller = None
        self.__is_shutdown = False

    def __del__(self):
        self.shutdown()

    def __enter__(self):
        return self.run()

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.shutdown()

    def run(self):
        self.logger.debug("[%05d] Executing Tor Process" % self.id)
        self.process = launch_tor_with_config(
            config={
                "ControlPort": str(self.control_port),
                "SocksPort": "127.0.0.1:{}".format(str(self.socks_port)),
                "DataDirectory": self.data_directory,
                "AllowSingleHopCircuits": "1",
                "ExcludeSingleHopRelays": "0",
            },
            tor_cmd=self.tor_cmd,
            init_msg_handler=self.print_bootstrapped_line
        )

        self.logger.debug("[%05d] Creating Tor Controller" % self.id)
        self.controller = Controller.from_port(port=self.control_port)
        self.controller.authenticate()

        return self

    def shutdown(self):
        if self.__is_shutdown:
            return

        self.__is_shutdown = True
        self.logger.debug("[%05d] Destroying Tor" % self.id)
        self.controller.close()
        self.process.terminate()
        self.process.wait()

        # If Not Closed Properly
        if path.exists(self.data_directory):
            rmtree(self.data_directory)

    def newnym_available(self):
        return self.controller.is_newnym_available()

    def newnym(self):
        if not self.newnym_available():
            self.logger.warning("[%05d] Cant Change Tor Identity (Need More Tor Processes)" % self.id)
            return False

        self.logger.debug("[%05d] Changing Tor Identity" % self.id)
        self.controller.signal(Signal.NEWNYM)
        return True

    def print_bootstrapped_line(self, line):
        if "Bootstrapped" in line:
            self.logger.debug("[%05d] Tor Bootstrapped Line: %s" % (self.id, line))

            if "100%" in line:
                self.logger.debug("[%05d] Tor Process Executed Successfully" % self.id)

    @staticmethod
    def free_port():
        """
        Determines a free port using sockets.
        Taken from selenium python.
        """
        free_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        free_socket.bind(('0.0.0.0', 0))
        free_socket.listen(5)
        port = free_socket.getsockname()[1]
        free_socket.close()
        return port
