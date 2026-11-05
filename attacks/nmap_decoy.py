"""
Nmap Decoy Scan  — -D decoy1,decoy2,ME
Sends SYN probes from multiple spoofed IPs simultaneously with the
real source, making it harder for the defender to identify the true scanner.
Simulated here via scapy parallel SYN streams from decoy IPs + real IP.
"""
import threading, time, random
from scapy.all import Ether, IP, TCP, ARP, srp, sendp, get_if_hwaddr, get_if_addr, RandShort
from attacks.base import BaseAttack


class NmapDecoyScan(BaseAttack):
    def run(self):
        target_ip  = self.params.get("target_ip", "")
        port_range = self.params.get("port_range", "1-1024")
        decoys_raw = self.params.get("decoys", "RND:5")  # "RND:N" or "ip1,ip2,ip3"

        if not target_ip:
            self.log("Decoy Scan: no target IP", "error"); return

        # Build decoy IP list
        real_ip = get_if_addr(self.iface)
        if decoys_raw.upper().startswith("RND:"):
            try:
                n = int(decoys_raw.split(":")[1])
            except Exception:
                n = 5
            decoy_ips = [
                f"{random.randint(1,223)}.{random.randint(0,254)}."
                f"{random.randint(0,254)}.{random.randint(1,254)}"
                for _ in range(n)
            ]
        else:
            decoy_ips = [d.strip() for d in decoys_raw.split(",") if d.strip()]

        # Insert real IP at random position (ME)
        me_pos = random.randint(0, len(decoy_ips))
        decoy_ips.insert(me_pos, real_ip)

        self.log(f"Decoy Scan → {target_ip}", "warn")
        self.log(f"  Scan order: {' | '.join(decoy_ips)}", "info")
        self.log(f"  Real scanner at position {me_pos + 1} ({real_ip})", "info")

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
        lock = threading.Lock()

        from queue import Queue, Empty
        q = Queue()
        for p in range(p_start, p_end + 1): q.put(p)

        self.log(f"Sending from {len(decoy_ips)} sources across ports {p_start}-{p_end}", "info")

        def worker():
            while not self._stop.is_set():
                try: port = q.get_nowait()
                except Empty: break
                # Blast SYN from each decoy, then from real IP
                for src_ip in decoy_ips:
                    pkt = (Ether(src=src_mac, dst=dst_mac)
                           / IP(src=src_ip, dst=target_ip)
                           / TCP(dport=port, flags="S", sport=RandShort()))
                    sendp(pkt, iface=self.iface, verbose=False)
                    self.write(pkt)
                # Only use real-IP response to judge port state
                real_pkt = (Ether(src=src_mac, dst=dst_mac)
                            / IP(src=real_ip, dst=target_ip)
                            / TCP(dport=port, flags="S", sport=RandShort()))
                ans2, _ = srp(real_pkt, iface=self.iface, timeout=0.5, verbose=False)
                for _, rcv in ans2:
                    if rcv.haslayer(TCP) and (rcv[TCP].flags & 0x12):
                        with lock:
                            open_ports.append(port)
                        self.log(f"  OPEN  {target_ip}:{port}", "success")
                q.task_done()

        threads = [threading.Thread(target=worker, daemon=True) for _ in range(30)]
        for t in threads: t.start()
        for t in threads: t.join()
        writer.close()
        self.log(f"Decoy scan done — {len(open_ports)} open port(s)", "success")
