#!/usr/bin/env python3

from enum import Enum
from scapy.all import ARP, AsyncSniffer, conf, Ether, sendp


class Kind(Enum):
    START = "06"
    DATA = "0A"


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
            "broadcast": self.broadcast,
        }
        self.cmd_descs = {
            "exit": "Exit from this program.",
            "help": "Get info about a command",
            "broadcast": "Broadcast a message to lan",
        }
        self.is_running = True

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

    def parse_cmd(self, command):
        cmd = command.split()

        if cmd:
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

    def check_packet(self, p):
        eth, arp = p[Ether], p[ARP]

        if eth.src != self.mac:
            match arp.hwsrc[:2]:
                case Kind.START.value:
                    self.msg_table[eth.src] = ""

                case Kind.DATA.value:
                    try:
                        self.msg_table[eth.src] += self.decode_msg(arp.hwsrc)
                    except KeyError:
                        pass

    def decode_msg(self, hex_msg):
        # length is important
        # where to store it
        pass

    def msg_to_hex_arr(self, message):
        return [hex(ord(c))[2:] for c in message.strip()]

    def int_to_hex_padded(self, len_hex_msg):
        return f"{len_hex_msg:#0{4}x}"[2:]

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

    def broadcast(self):
        message = input("Enter a message: ")

        hex_msg = self.msg_to_hex_arr(message)
        msg_bytes = len(hex_msg)
        len_hex_msg = self.int_to_hex_padded(msg_bytes)

        self.send([Kind.START.value, len_hex_msg, "ff", "ff", "ff", "ff"])
        for i in range(0, msg_bytes, 5):
            self.send([Kind.DATA.value] + hex_msg[i : i + 5])

        print(f"{msg_bytes} bytes sent.")

    def run(self):
        print("Starting.")
        self.sniffer.start()

        while c.is_running:
            try:
                c.parse_cmd(input(">>> "))
            except KeyboardInterrupt:
                self.exit()

        print("Quitting.")
        self.sniffer.stop()


if __name__ == "__main__":
    c = Chatter()
    c.run()
