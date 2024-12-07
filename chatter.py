#!/usr/bin/env python3

from enum import Enum
from os import getuid
from scapy.all import ARP, AsyncSniffer, conf, Ether, sendp


class Flag(Enum):
    HEADER = "06"
    MSG = "0a"


class Addr(Enum):
    IPANY = "0.0.0.0"
    HWBROADCAST = "ff:ff:ff:ff:ff:ff"


class Chatter:
    def __init__(self):
        self.ip = conf.iface.ip
        self.mac = conf.iface.mac
        self.iface = conf.iface.network_name

        self.sniffer = AsyncSniffer(
            store=False,
            prn=self.check_packet,
            filter="arp",
            iface=self.iface,
            quiet=True,
        )
        self.msg_table = {}

        self.cmds = {
            "exit": self.exit,
            "help": self.help,
        }
        self.cmd_descs = {
            "exit": "Exit from this program.",
            "help": "Get info about a command",
        }
        self.is_running = True

    def parse_cmd(self, command):
        cmd = command.split()

        if not cmd:
            return

        main, args = cmd[0], cmd[1:]

        if main in self.cmds.keys():
            self.cmds[main](*args)
        else:
            self.broadcast(command)

    def exit(self):
        self.is_running = False

    def help(self, *args):
        if not args:
            print("Available commands:")
            for cmd in self.cmds.keys():
                print(f"\t{cmd}")
        else:
            try:
                print(f"\t{args[0]}: {self.cmd_descs[args[0]]}")
            except KeyError:
                print(f"Unknown command '{args[0]}'.")

    def add_to_msg_table(self, sender, hex_len):
        self.msg_table[sender] = {
            "len": int(hex_len, 16),
            "msg": "",
        }

    def decode_msg(self, sender, hex_msg):
        msg = []
        for c in range(0, len(hex_msg), 3):
            if hex_msg[c : c + 2] != "00":
                msg.append(chr(int(hex_msg[c : c + 2], 16)))

        return msg

    def read_into_msg_table(self, sender, hex_msg):
        msg = self.decode_msg(sender, hex_msg)

        self.msg_table[sender]["len"] -= len(msg)
        self.msg_table[sender]["msg"] += "".join(msg)

        if self.msg_table[sender]["len"] == 0:
            data = self.msg_table.pop(sender)
            print(f"{sender}: {data['msg']}")

    def check_packet(self, p):
        eth, arp = p[Ether], p[ARP]

        if eth.src == self.mac:
            return

        match arp.hwsrc[:2]:
            case Flag.HEADER.value:
                self.add_to_msg_table(eth.src, arp.hwsrc[3:5])

            case Flag.MSG.value:
                self.read_into_msg_table(eth.src, arp.hwsrc[3:])

    def msg_to_hex_arr(self, message):
        return [hex(ord(c))[2:] for c in message.strip()]

    def int_to_hex_padded(self, len_hex_msg):
        return "{:02x}".format(len_hex_msg)

    def build_arp(self, data):
        data_len = len(data)

        if data_len != 6:
            for i in range(6 - data_len):
                data.append("00")

        eth = Ether(src=self.mac, dst=Addr.HWBROADCAST.value)
        arp = ARP(
            hwsrc=":".join(data),
            hwdst=Addr.HWBROADCAST.value,
            psrc=self.ip,
            pdst=Addr.IPANY.value,
        )

        return eth / arp

    def send(self, data):
        sendp(
            x=self.build_arp(data),
            verbose=0,
            iface=self.iface,
        )

    def broadcast(self, message):
        message = message[:255]

        hex_msg = self.msg_to_hex_arr(message)
        msg_bytes = len(hex_msg)
        len_hex_msg = self.int_to_hex_padded(msg_bytes)

        self.send([Flag.HEADER.value, len_hex_msg, "00", "00", "00", "00"])
        for i in range(0, msg_bytes, 5):
            self.send([Flag.MSG.value] + hex_msg[i : i + 5])

        print(f"{msg_bytes} bytes sent.")

    def run(self):
        print("Starting.")
        self.sniffer.start()

        while self.is_running:
            try:
                self.parse_cmd(input(">>> "))
            except KeyboardInterrupt:
                self.exit()

        print("Quitting.")
        self.sniffer.stop()


def is_sudo():
    return getuid() == 0


if __name__ == "__main__":
    if not is_sudo():
        print("Use sudo to run this program.")
        exit(1)

    c = Chatter()
    c.run()
