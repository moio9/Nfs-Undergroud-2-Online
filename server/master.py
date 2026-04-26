"""
master.py — Master/Slave replication system.
Matches DLL strings:
  'Master server startup / shutdown / reconfig'
  'Master connect from slave %08x'
  'Master completing reconfig for slave %08x'
  'Master is down with message: %s'
  'Master got extension server update (type=%s, seqn=%ld, addr=%08x, port=%d)'
"""

import socket
import threading
import time
import logging
import json
from typing import Dict, List, Optional, Callable

log = logging.getLogger("master")

SLAVE_STATE_CONNECTING  = "CONNECTING"
SLAVE_STATE_ACTIVE      = "ACTIVE"
SLAVE_STATE_RECONFIG    = "RECONFIG"
SLAVE_STATE_DOWN        = "DOWN"


# ======================================================================= #
# Slave connection (master-side view)                                      #
# ======================================================================= #

class SlaveConn:
    def __init__(self, conn: socket.socket, addr: tuple):
        self.conn       = conn
        self.ip         = addr[0]
        self.port       = addr[1]
        self.ident      = int(addr[0].replace(".", "")) & 0xFFFFFFFF
        self.state      = SLAVE_STATE_CONNECTING
        self.connected  = True
        self.last_seen  = time.time()
        self.seq        = 0
        self._lock      = threading.Lock()

    def send(self, msg: str):
        try:
            with self._lock:
                self.conn.sendall(msg.encode())
            self.last_seen = time.time()
        except Exception as e:
            log.warning("Slave %08x send error: %s", self.ident, e)
            self.connected = False

    def recv_line(self) -> Optional[str]:
        buf = b""
        try:
            while True:
                ch = self.conn.recv(1)
                if not ch:
                    return None
                buf += ch
                if ch == b"\n":
                    return buf.decode("utf-8", errors="replace").strip()
        except Exception:
            return None

    def connection_info(self) -> str:
        return (f"state={self.state}, "
                f"inpbuf=0, outbuf=0")


# ======================================================================= #
# Master Server                                                            #
# ======================================================================= #

class MasterServer:
    """
    Runs a TCP listener that slave servers connect to.
    Distributes config updates and collects stats.
    """

    def __init__(self, cfg, get_server_state: Callable):
        self.cfg              = cfg
        self.get_state        = get_server_state
        self._lock            = threading.Lock()
        self._slaves: Dict[int, SlaveConn] = {}
        self._running         = False
        self._thread          = None
        self._seq             = 0

        self.host = cfg.get("HOST", "0.0.0.0")
        self.port = cfg.get("MASTER_PORT", 11200)

    # ------------------------------------------------------------------ #

    def start(self):
        self._running = True
        self._thread  = threading.Thread(target=self._listen,
                                         name="MasterListener", daemon=True)
        self._thread.start()
        log.info("Master server startup (listening on %s:%d)", self.host, self.port)

    def stop(self):
        self._running = False
        log.info("Master server shutdown")

    # ------------------------------------------------------------------ #

    def _listen(self):
        try:
            srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            srv.bind((self.host, self.port))
            srv.listen(16)
            srv.settimeout(1.0)
            log.info("Master server is setup")
            while self._running:
                try:
                    conn, addr = srv.accept()
                    t = threading.Thread(target=self._handle_slave,
                                         args=(conn, addr), daemon=True)
                    t.start()
                except socket.timeout:
                    pass
        except Exception as e:
            log.error("Master listener error: %s", e)

    def _handle_slave(self, conn: socket.socket, addr: tuple):
        slave = SlaveConn(conn, addr)
        with self._lock:
            self._slaves[slave.ident] = slave

        log.info("Master connect from slave %08x: %s", slave.ident, addr[0])
        slave.state = SLAVE_STATE_ACTIVE

        # Send current config snapshot to new slave
        self._send_config(slave)

        try:
            while self._running and slave.connected:
                line = slave.recv_line()
                if line is None:
                    break
                self._handle_slave_msg(slave, line)
                slave.last_seen = time.time()
        finally:
            slave.connected = False
            log.info("Master connection: %s", slave.connection_info())
            with self._lock:
                self._slaves.pop(slave.ident, None)

    def _handle_slave_msg(self, slave: SlaveConn, line: str):
        if line.startswith("STAT"):
            # Slave reporting its stats
            log.debug("Slave %08x stat: %s", slave.ident, line)
        elif line.startswith("SHUTDOWN"):
            log.info("Master got extension server shutdown from %08x", slave.ident)
            slave.connected = False
        else:
            log.debug("Slave %08x: %s", slave.ident, line)

    def _send_config(self, slave: SlaveConn):
        """Push current config to slave."""
        state = self.get_state()
        msg   = json.dumps({"type": "CONFIG", "data": state}) + "\n"
        slave.send(msg)

    # ------------------------------------------------------------------ #
    # Reconfig broadcast                                                   #
    # ------------------------------------------------------------------ #

    def reconfig(self, update: dict):
        """
        Broadcast a config update to all slaves.
        Matches: 'Master server reconfig' / 'Master starting reconfig for slave %08x'
        """
        log.info("Master server reconfig")
        self._seq += 1
        with self._lock:
            slaves = list(self._slaves.values())

        for slave in slaves:
            log.info("Master starting reconfig for slave %08x", slave.ident)
            slave.state = SLAVE_STATE_RECONFIG
            msg = json.dumps({
                "type": "UPDATE",
                "seqn": self._seq,
                "addr": slave.ip,
                "port": slave.port,
                "data": update,
            }) + "\n"
            slave.send(msg)
            log.info("Master completing reconfig for slave %08x", slave.ident)
            slave.state = SLAVE_STATE_ACTIVE
            log.info("Master got extension server update (type=%s, seqn=%ld, addr=%s, port=%d): ok",
                     update.get("type", "GENERIC"), self._seq, slave.ip, slave.port)

    def broadcast(self, msg: str):
        with self._lock:
            for slave in self._slaves.values():
                slave.send(msg)

    # ------------------------------------------------------------------ #
    # Periodic health check                                                #
    # ------------------------------------------------------------------ #

    def check_slaves(self, timeout: float = 30.0):
        """Mark unresponsive slaves as down."""
        now = time.time()
        with self._lock:
            for slave in list(self._slaves.values()):
                if now - slave.last_seen > timeout:
                    log.warning("Master is down with message: slave %08x timeout", slave.ident)
                    slave.state = SLAVE_STATE_DOWN

    def master_info(self) -> List[dict]:
        """Master #%d (%s): %d.%d.%d.%d"""
        with self._lock:
            result = []
            for i, slave in enumerate(self._slaves.values()):
                parts = slave.ip.split(".")
                result.append({
                    "index": i + 1,
                    "ip":    slave.ip,
                    "state": slave.state,
                    "seq":   slave.seq,
                })
            return result

    def slave_count(self) -> int:
        return len(self._slaves)


# ======================================================================= #
# Slave Client (connects to master)                                        #
# ======================================================================= #

class SlaveClient:
    """
    Slave-side: connects to master server, receives config updates.
    Matches: 'Master connection: state=%d, inpbuf=%d, outbuf=%d'
    """

    def __init__(self, cfg, on_update: Callable):
        self.cfg        = cfg
        self.on_update  = on_update
        self._running   = False
        self._thread    = None
        self._sock      = None

        self.master_host = cfg.get("MASTER_HOST", "")
        self.master_port = cfg.get("MASTER_PORT", 11200)
        self.state       = SLAVE_STATE_DOWN

    def start(self):
        if not self.master_host:
            return
        self._running = True
        self._thread  = threading.Thread(target=self._connect_loop,
                                         name="SlaveClient", daemon=True)
        self._thread.start()

    def stop(self):
        self._running = False

    def _connect_loop(self):
        while self._running:
            try:
                self._connect()
            except Exception as e:
                log.error("Got connect error: %s", e)
            time.sleep(5)

    def _connect(self):
        self._sock  = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            self._sock.connect((self.master_host, self.master_port))
            self.state = SLAVE_STATE_ACTIVE
            log.info("Master connection: state=ACTIVE, inpbuf=0, outbuf=0")
            buf = b""
            while self._running:
                self._sock.settimeout(10.0)
                try:
                    data = self._sock.recv(4096)
                except socket.timeout:
                    # Send heartbeat
                    self.send("PING\n")
                    continue
                if not data:
                    break
                buf += data
                while b"\n" in buf:
                    line, buf = buf.split(b"\n", 1)
                    self._handle_line(line.decode("utf-8", errors="replace"))
        finally:
            self.state = SLAVE_STATE_DOWN
            self._sock.close()

    def _handle_line(self, line: str):
        try:
            msg = json.loads(line)
            t   = msg.get("type", "")
            if t == "CONFIG":
                self.on_update(msg.get("data", {}))
            elif t == "UPDATE":
                log.info("Slave got update seqn=%s", msg.get("seqn"))
                self.on_update(msg.get("data", {}))
        except json.JSONDecodeError:
            pass

    def send(self, msg: str):
        try:
            if self._sock:
                self._sock.sendall(msg.encode())
        except Exception:
            pass
