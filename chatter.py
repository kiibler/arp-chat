#!/usr/bin/env python3

from enum import Enum
from scapy.all import ARP, AsyncSniffer, conf, Ether, srploop
from threading import Thread


class Kind(Enum):
    HELLO = "02"


class Addr(Enum):
    ANY = "00:00:00:00:00:00"
    BROADCAST = "ff:ff:ff:ff:ff:ff"


descriptions = {
    "exit": "Exit from this program.",
    "help": "Get info about a command",
    "show": "Show status of parts of the program",
    "start": "Start parts of the program",
    "stop": "Stop parts of the program",
}


class Chatter:
    def __init__(self):
        self.ip = conf.iface.ip
        self.mac = conf.iface.mac
        self.iface = conf.iface.network_name

        self.hello_broadcast = Thread(target=self.start_hello, daemon=True)

        self.sniffer = AsyncSniffer(
            filter="arp",
            iface=self.iface,
            store=False,
            quiet=True,
            prn=self.check_for_data,
        )
        self.peers = []

        self.cmds = {
            "exit": self.exit,
            "help": self.help,
            "show": self.not_implemented,
            "start": {
                "sniffer": self.start_sniffer,
                "broadcast": self.not_implemented,
            },
            "stop": {
                "sniffer": self.stop_sniffer,
                "broadcast": self.not_implemented,
            },
        }
        self.cmd_descs = descriptions
        self.is_running = True

    def parse_cmd(self, command):
        cmd = command.split()
        main, args = cmd[0], cmd[1:]

        if main in self.cmds.keys():
            self.run_cmd(main, *args)
        else:
            print(f"Unknown command: {main}.")

    def run_cmd(self, main, *args):
        if len(args):
            pass
        else:
            pass

        # try:
        #     if isinstance(self.cmds[main], dict):
        #         self.cmds[main][args[0]](*args[1:])
        #     else:
        #         self.cmds[main](*args)
        # except TypeError:
        #     print(f"Wrong amount of arguments to '{main}'.")
        # except KeyError:
        #     print(f"Unknown argument '{args[0]}' to '{main}'.")

    def not_implemented(self):
        print("NOT IMPLEMENTED.")

    def exit(self):
        self.is_running = False

    def help(self, *args):
        if len(args) == 1:
            print(f"\t{args[0]}: {self.cmd_descs[args[0]]}")
        elif len(args) == 0:
            print("Available commands:")
            for cmd in self.cmds.keys():
                print(f"\t{cmd}")

            print("Use help to get information about a specific command:")
            print("For example: start help")

    def start_hello(self, interval=3):
        packet = Ether(src=self.mac, dst=Addr.BROADCAST.value) / ARP(
            hwsrc="02:00:00:00:00:00",
            hwdst=Addr.BROADCAST.value,
            psrc=self.ip,
            pdst="0.0.0.0",
        )

        srploop(
            pkts=packet,
            store=False,
            timeout=interval,
            verbose=0,
            iface=self.iface,
            stop_filter=lambda p: "STOP" in str(p),
        )

    def start_sniffer(self):
        self.sniffer.start()
        print("Started packet sniffer.")

    def stop_sniffer(self):
        self.sniffer.stop()
        print("Stopped packet sniffer.")

    def check_for_data(self, p):
        eth, arp = p[Ether], p[ARP]

        if eth.src != self.mac:
            match arp.hwsrc[:2]:
                case Kind.HELLO.value:
                    self.add_to_peers(eth.src)

                case _:
                    pass

    def add_to_peers(self, hwsrc):
        if hwsrc not in self.peers:
            self.peers.append(hwsrc)
            print(f"{hwsrc} added to peers.")

    def run(self):
        print("Starting.")

        while c.is_running:
            try:
                c.parse_cmd(input(">>> "))
            except KeyboardInterrupt:
                self.exit()

        print("Quitting.")


if __name__ == "__main__":
    c = Chatter()
    c.run()
