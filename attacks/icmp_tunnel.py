import random, time
from scapy.all import Ether, IP, ICMP, sendp, get_if_hwaddr, get_if_addr
from attacks.base import BaseAttack


class IcmpTunnel(BaseAttack):
    def run(self):
        target_ip = self.params.get("target_ip", "")
        message   = self.params.get("message", "SOC-LAB-COVERT-CHANNEL-TEST")
        repeat    = int(self.params.get("repeat", 5))

        if not target_ip:
            self.log("ICMP Tunnel: no target IP", "error"); return

        dst_mac = self.resolve_mac(target_ip)
        src_mac = get_if_hwaddr(self.iface)
        src_ip  = get_if_addr(self.iface)
        writer  = self.open_pcap()

        chunks = [message[i:i+32] for i in range(0, len(message), 32)]
        self.log(f"ICMP Covert Channel → {target_ip} | {len(message)} bytes in {len(chunks)} frame(s)", "warn")

        for tx in range(repeat):
            if self._stop.is_set(): break
            sid = random.randint(0, 0xFFFF)
            for idx, chunk in enumerate(chunks):
                if self._stop.is_set(): break
                payload = chunk.encode().ljust(32, b"\x00")
                pkt = (
                    Ether(src=src_mac, dst=dst_mac)
                    / IP(src=src_ip, dst=target_ip, ttl=64)
                    / ICMP(type=8, code=0, id=sid, seq=idx)
                    / payload
                )
                sendp(pkt, iface=self.iface, verbose=False)
                self.write(pkt)
                self.log(f"TX {tx+1}/{repeat} chunk {idx+1}/{len(chunks)}: {chunk[:24]!r}", "info")
                time.sleep(0.05)
            time.sleep(1)

        writer.close()
        self.log("ICMP Covert Channel: transmission complete", "success")
