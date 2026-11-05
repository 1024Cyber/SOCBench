"""
Nmap FIN Scan  — -sF
Sends TCP FIN packets. Closed ports reply RST; open ports silent.
Similar evasion profile to NULL and Xmas. Bypasses non-stateful ACLs.
"""
import subprocess, shutil, threading
from queue import Queue, Empty
from scapy.all import Ether, IP, TCP, ARP, srp, get_if_hwaddr, RandShort
from attacks.base import BaseAttack


class NmapFinScan(BaseAttack):
    def run(self):
        target_ip  = self.params.get("target_ip", "")
        port_range = self.params.get("port_range", "1-1024")
        if not target_ip:
            self.log("FIN Scan: no target IP", "error"); return

        if shutil.which("nmap"):
            self._run_nmap(target_ip, port_range)
        else:
            self.log("nmap not found — using scapy FIN implementation", "warn")
            self._run_scapy(target_ip, port_range)

    def _run_nmap(self, target_ip, port_range):
        cmd = ["nmap", "-sF", "-p", port_range, "--open", "-oN", "-", target_ip]
        self.log(f"nmap FIN: {' '.join(cmd)}", "info")
        writer = self.open_pcap()
        proc = subprocess.Popen(cmd, stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE, text=True)
        for line in proc.stdout:
            line = line.rstrip()
            if line:
                self.log(f"  {line}", "success" if "open" in line else "info")
        proc.wait()
        writer.close()
        self.log("nmap FIN scan complete", "success")

    def _run_scapy(self, target_ip, port_range):
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

        self.log(f"Scapy FIN scan → {target_ip} ports {p_start}-{p_end}", "warn")

        def worker():
            while not self._stop.is_set():
                try: port = q.get_nowait()
                except Empty: break
                pkt = (Ether(src=src_mac, dst=dst_mac)
                       / IP(dst=target_ip)
                       / TCP(dport=port, flags="F", sport=RandShort()))
                self.write(pkt)
                ans2, _ = srp(pkt, iface=self.iface, timeout=0.5, verbose=False)
                if not ans2:
                    open_ports.append(port)
                    self.log(f"  OPEN|FILTERED  {target_ip}:{port}", "success")
                q.task_done()

        threads = [threading.Thread(target=worker, daemon=True) for _ in range(50)]
        for t in threads: t.start()
        for t in threads: t.join()
        writer.close()
        self.log(f"FIN scan done — {len(open_ports)} open|filtered port(s)", "success")
