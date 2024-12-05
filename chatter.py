#!/usr/bin/env python3

from enum import Enum
from scapy.all import ARP, conf, Ether


class Kind(Enum):
    START = "06"


class Addr(Enum):
    ANY = "00:00:00:00:00:00"
    BROADCAST = "ff:ff:ff:ff:ff:ff"


descriptions = {
    "exit": "Exit from this program.",
    "help": "Get info about a command",
    "send": "Send message",
}


class Chatter:
    def __init__(self):
        self.ip = conf.iface.ip
        self.mac = conf.iface.mac
        self.iface = conf.iface.network_name

        self.cmds = {
            "exit": self.exit,
            "help": self.help,
            "send": self.send,
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
        try:
            self.cmds[main](*args)
        except KeyError:
            print(f"Unknown argument '{args[0]}' to '{main}'.")

    def exit(self):
        self.is_running = False

    def help(self, *args):
        if len(args) == 0:
            print("Available commands:")
            for cmd in self.cmds.keys():
                print(f"\t{cmd}")

            print("Use help to get information about a specific command:")
            print("For example: help exit")
        else:
            try:
                print(f"\t{args[0]}: {self.cmd_descs[args[0]]}")
            except KeyError:
                print(f"Unknown command '{args[0]}'.")

    def msg_to_hex_arr(self, message):
        return [hex(ord(c))[2:] for c in message.strip()]

    def int_to_hex_padded(self, len_hex_msg):
        return f"{len_hex_msg:#0{4}x}"[2:]

    def build_arp(self, payload):
        if len(payload) != 6:
            for i in range(6 - len(payload)):
                payload.append("ff")

        eth = Ether(src=self.mac, dst=Addr.BROADCAST.value)
        arp = ARP(
            hwsrc=":".join(payload),
            hwdst=Addr.BROADCAST.value,
            psrc=self.ip,
            pdst=Addr.ANY.value,
        )

        return eth / arp

    def send(self):
        message = input("Enter a message: ")

        hex_msg = self.msg_to_hex_arr(message)
        len_hex_msg = self.int_to_hex_padded(len(hex_msg))

        self.build_arp([Kind.START.value, len_hex_msg, "ff", "ff", "ff", "ff"]).show()
        for i in range(0, len(hex_msg), 6):
            self.build_arp(hex_msg[i : i + 6]).show()

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
