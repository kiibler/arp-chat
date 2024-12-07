#!/usr/bin/env python3

from enum import Enum
from os import getuid
from scapy.all import ARP, AsyncSniffer, conf, Ether, sendp


class Flag(Enum):
    START = "06"
    DATA = "0a"


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

    def exit(self):
        self.is_running = False

    def parse_cmd(self, command):
        cmd = command.split()

        if not cmd:
            return

        main, args = cmd[0], cmd[1:]

        if main in self.cmds.keys():
            self.cmds[main](*args)
        else:
            self.broadcast(command)

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

    def check_packet(self, p):
        eth, arp = p[Ether], p[ARP]

        if eth.src != self.mac:
            match arp.hwsrc[:2]:
                case Flag.START.value:
                    self.msg_table[eth.src] = {
                        "len": int(arp.hwsrc[3:5], 16),
                        "msg": "",
                    }

                case Flag.DATA.value:
                    if eth.src in self.msg_table.keys():
                        self.decode_msg(eth.src, arp.hwsrc[3:])

    def decode_msg(self, sender, hex_msg):
        msg = []
        for c in range(0, len(hex_msg), 3):
            if hex_msg[c : c + 2] != "ff":
                msg.append(chr(int(hex_msg[c : c + 2], 16)))

        self.msg_table[sender]["len"] -= len(msg)
        self.msg_table[sender]["msg"] += "".join(msg)

        if self.msg_table[sender]["len"] == 0:
            data = self.msg_table.pop(sender)
            print(f"{sender}: {data['msg']}")

    def msg_to_hex_arr(self, message):
        return [hex(ord(c))[2:] for c in message.strip()]

    def int_to_hex_padded(self, len_hex_msg):
        return "{:02x}".format(len_hex_msg)

    def build_arp(self, payload):
        p_len = len(payload)

        if p_len != 6:
            for i in range(6 - p_len):
                payload.append("ff")

        eth = Ether(src=self.mac, dst=Addr.HWBROADCAST.value)
        arp = ARP(
            hwsrc=":".join(payload),
            hwdst=Addr.HWBROADCAST.value,
            psrc=self.ip,
            pdst=Addr.IPANY.value,
        )

        return eth / arp

    def send(self, payload):
        sendp(
            x=self.build_arp(payload),
            verbose=0,
            realtime=True,
            iface=self.iface,
        )

    def broadcast(self, message):
        message = message[:256]

        hex_msg = self.msg_to_hex_arr(message)
        msg_bytes = len(hex_msg)
        len_hex_msg = self.int_to_hex_padded(msg_bytes)

        self.send([Flag.START.value, len_hex_msg, "ff", "ff", "ff", "ff"])
        for i in range(0, msg_bytes, 5):
            self.send([Flag.DATA.value] + hex_msg[i : i + 5])

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
