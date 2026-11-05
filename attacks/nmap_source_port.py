"""
Nmap Source Port Scan  — --source-port / -g <port>
Sends SYN probes from a fixed source port (e.g. 53, 80, 443).
Exploits firewalls that trust traffic FROM well-known ports.
Generates traffic that is trivially bypassing simple ACLs.
"""
import threading
from queue import Queue, Empty
from scapy.all import Ether, IP, TCP, ARP, srp, get_if_hwaddr
from attacks.base import BaseAttack


class NmapSourcePort(BaseAttack):
    def run(self):
        target_ip   = self.params.get("target_ip", "")
        port_range  = self.params.get("port_range", "1-1024")
        source_port = int(self.params.get("source_port", 53))

        if not target_ip:
            self.log("Source-Port Scan: no target IP", "error"); return

        self.log(f"Source-Port Scan → {target_ip}  fixed src_port={source_port}", "warn")
        self.log(f"  Firewalls trusting src={source_port} may allow these probes through", "info")

        try:
            p_start, p_end = (int(x) for x in port_range.split("-"))
        except ValueError:
            self.log("Invalid port range", "error"); return

        arp_pkt = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=target_ip)
        ans, _  = srp(arp_pkt, iface=self.iface, timeout=2, verbose=False)
        dst_mac = ans[0][1][ARP].hwsrc if ans else "ff:ff:ff:ff:ff:ff"
        src_mac = get_if_hwaddr(self.iface)
        writer  = self.open_pcap()
        open_ports = []
        q = Queue()
        for p in range(p_start, p_end + 1): q.put(p)

        def worker():
            while not self._stop.is_set():
                try: port = q.get_nowait()
                except Empty: break
                pkt = (Ether(src=src_mac, dst=dst_mac)
                       / IP(dst=target_ip)
                       / TCP(dport=port, sport=source_port, flags="S"))
                self.write(pkt)
                ans2, _ = srp(pkt, iface=self.iface, timeout=0.5, verbose=False)
                for _, rcv in ans2:
                    if rcv.haslayer(TCP) and (rcv[TCP].flags & 0x12):
                        open_ports.append(port)
                        self.log(f"  OPEN  {target_ip}:{port}  (via src={source_port})", "success")
                q.task_done()

        threads = [threading.Thread(target=worker, daemon=True) for _ in range(50)]
        for t in threads: t.start()
        for t in threads: t.join()
        writer.close()
        self.log(
            f"Source-Port scan done — src={source_port} — {len(open_ports)} open port(s): {sorted(open_ports)}",
            "success"
        )
