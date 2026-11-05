"""
hping3 ICMP Customization  — hping3 --icmp --icmp-type N --icmp-code N
Crafts ICMP packets with fully customizable type, code, payload size,
TTL, and ID. Simulates a wide variety of ICMP-based probe and flood patterns
that SOC analysts need to recognise in captures.
"""
import time, random
from scapy.all import Ether, IP, ICMP, ARP, srp, sendp, get_if_hwaddr
from attacks.base import BaseAttack


ICMP_TYPE_NAMES = {
    0:  "Echo Reply",
    3:  "Destination Unreachable",
    5:  "Redirect",
    8:  "Echo Request",
    11: "Time Exceeded",
    13: "Timestamp Request",
    14: "Timestamp Reply",
    17: "Address Mask Request",
}


class Hping3Icmp(BaseAttack):
    def run(self):
        target_ip    = self.params.get("target_ip", "")
        icmp_type    = int(self.params.get("icmp_type", 8))
        icmp_code    = int(self.params.get("icmp_code", 0))
        payload_size = int(self.params.get("payload_size", 64))
        ttl          = int(self.params.get("ttl", 64))
        count        = int(self.params.get("count", 100))
        interval     = float(self.params.get("interval", 0.1))

        if not target_ip:
            self.log("hping3 ICMP: no target IP", "error"); return

        arp_pkt = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=target_ip)
        ans, _  = srp(arp_pkt, iface=self.iface, timeout=2, verbose=False)
        dst_mac = ans[0][1][ARP].hwsrc if ans else "ff:ff:ff:ff:ff:ff"
        src_mac = get_if_hwaddr(self.iface)
        writer  = self.open_pcap()

        type_name = ICMP_TYPE_NAMES.get(icmp_type, f"type{icmp_type}")
        self.log(
            f"hping3 ICMP → {target_ip}  type={icmp_type} ({type_name})  "
            f"code={icmp_code}  size={payload_size}B  ttl={ttl}  count={count}",
            "warn"
        )

        sent = 0
        while not self._stop.is_set():
            if count and sent >= count:
                break
            payload = bytes(random.getrandbits(8) for _ in range(payload_size))
            pkt = (
                Ether(src=src_mac, dst=dst_mac)
                / IP(dst=target_ip, ttl=ttl, id=random.randint(0, 0xFFFF))
                / ICMP(type=icmp_type, code=icmp_code,
                       id=random.randint(0, 0xFFFF), seq=sent)
                / payload
            )
            try:
                sendp(pkt, iface=self.iface, verbose=False)
                self.write(pkt)
                sent += 1
                if sent % 25 == 0:
                    self.log(f"  ICMP {type_name}: {sent}/{count} sent", "info")
            except Exception as e:
                self.log(f"hping3 ICMP error: {e}", "error"); break
            time.sleep(interval)

        writer.close()
        self.log(f"hping3 ICMP done — {sent} packets sent", "success")
