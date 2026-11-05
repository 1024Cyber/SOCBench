import threading
from queue import Queue, Empty
from scapy.all import Ether, IP, TCP, ARP, sendp, send, srp, get_if_hwaddr, RandShort
from attacks.base import BaseAttack


class SynScan(BaseAttack):
    def run(self):
        target_ip = self.params.get("target_ip", "")
        p_range   = self.params.get("port_range", "1-1024")

        if not target_ip:
            self.log("SYN Scan: no target IP", "error"); return

        try:
            p_start, p_end = (int(x) for x in p_range.split("-"))
        except ValueError:
            self.log("SYN Scan: invalid port range — use start-end (e.g. 1-1024)", "error"); return

        # Resolve MAC once
        arp_pkt = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=target_ip)
        ans, _  = srp(arp_pkt, iface=self.iface, timeout=2, verbose=False)
        dst_mac = ans[0][1][ARP].hwsrc if ans else "ff:ff:ff:ff:ff:ff"
        src_mac = get_if_hwaddr(self.iface)

        ports      = list(range(p_start, p_end + 1))
        open_ports = []
        writer     = self.open_pcap()
        queue      = Queue()
        for p in ports: queue.put(p)

        self.log(f"SYN Scan → {target_ip}  ports {p_start}–{p_end} ({len(ports)} ports)", "warn")

        def worker():
            while not self._stop.is_set():
                try:
                    port = queue.get_nowait()
                except Empty:
                    break
                pkt = (
                    Ether(src=src_mac, dst=dst_mac)
                    / IP(dst=target_ip)
                    / TCP(dport=port, flags="S", sport=RandShort())
                )
                try:
                    self.write(pkt)
                    ans2, _ = srp(pkt, iface=self.iface, timeout=0.5, verbose=False)
                    for _, rcv in ans2:
                        if rcv.haslayer(TCP) and (rcv[TCP].flags & 0x12):
                            open_ports.append(port)
                            self.log(f"  OPEN  {target_ip}:{port}", "success")
                            rst = (
                                Ether(src=src_mac, dst=dst_mac)
                                / IP(dst=target_ip)
                                / TCP(dport=port, sport=rcv[TCP].dport,
                                      flags="R", seq=rcv[TCP].ack)
                            )
                            sendp(rst, iface=self.iface, verbose=False)
                except Exception:
                    pass
                finally:
                    queue.task_done()

        threads = [threading.Thread(target=worker, daemon=True) for _ in range(50)]
        for t in threads: t.start()
        for t in threads: t.join()

        writer.close()
        self.log(f"SYN Scan done — {len(open_ports)} open port(s): {sorted(open_ports)}", "success")
